"""Tests for :mod:`app_scanner`.

The suite is deliberately dependency-free: it uses plain ``assert`` statements
and can run either under pytest or directly::

    py -3.14 tests/test_app_scanner.py

No network access is performed.  VirusTotal is exercised through a fake
response object and a patched ``requests.get``.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import traceback
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app_scanner  # noqa: E402  (path setup must happen first)

# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------

REQUIRED_PERMISSIONS = (
    "RECEIVE_SMS",
    "READ_SMS",
    "SEND_SMS",
    "READ_CALL_LOG",
    "CALL_PHONE",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_PHONE_STATE",
    "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO",
    "CAMERA",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "REQUEST_INSTALL_PACKAGES",
    "PACKAGE_USAGE_STATS",
    "DEVICE_ADMIN",
    "BIND_DEVICE_ADMIN",
    "READ_CALENDAR",
    "BODY_SENSORS",
    "POST_NOTIFICATIONS",
    "INTERNET",
    "ACCESS_NETWORK_STATE",
    "WAKE_LOCK",
    "FOREGROUND_SERVICE",
    "QUERY_ALL_PACKAGES",
    "GET_ACCOUNTS",
    "USE_BIOMETRIC",
    "CHANGE_WIFI_STATE",
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "SCHEDULE_EXACT_ALARM",
    "READ_MEDIA_VIDEO",
    "BLUETOOTH_CONNECT",
    "NEARBY_WIFI_DEVICES",
    "ACTIVITY_RECOGNITION",
    "RECEIVE_BOOT_COMPLETED",
    "WRITE_SETTINGS",
    "MODIFY_AUDIO_SETTINGS",
    "DELETE_PACKAGES",
    "INSTALL_PACKAGES",
    "READ_HISTORY_BOOKMARKS",
    "PROCESS_OUTGOING_CALLS",
)

REQUIRED_APIS = (
    "DexClassLoader",
    "PathClassLoader",
    "Runtime.exec",
    "ProcessBuilder",
    "SmsManager.sendTextMessage",
    "SmsManager.sendMultipartTextMessage",
    "TelephonyManager.getDeviceId",
    "LocationManager.requestLocationUpdates",
    "Camera.open",
    "MediaRecorder.start",
    "AudioRecord.startRecording",
    "AccessibilityService",
    "NotificationListenerService",
    "DevicePolicyManager",
    "AccountManager.getAccounts",
    "ContactsContract",
    "ContentResolver.query",
    "Class.forName",
    "Method.invoke",
    "System.loadLibrary",
    "HttpURLConnection",
    "OkHttpClient",
    "Settings.Secure.getString",
)

REQUIRED_COMBO_CODES = (
    "sms_stealer",
    "accessibility_abuse",
    "overlay_phishing",
    "location_stalker",
    "contact_exfiltration",
    "silent_install",
    "device_admin_persistence",
    "call_log_theft",
    "audio_spy",
    "full_file_access",
)

ARABIC_RE = re.compile(r"[\u0600-\u06FF]")
MOJIBAKE_MARKERS = ("\u00c3", "\u00d8", "\u00d9", "\u00e2\u20ac", "\ufffd")
ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def perm(name: str) -> str:
    """Return the fully qualified Android permission name."""

    return f"android.permission.{name}"


def contains_arabic(text: str) -> bool:
    return bool(ARABIC_RE.search(text))


def assert_clean_text(text: object, *, label: str) -> None:
    assert isinstance(text, str), f"{label} must be a string"
    assert text.strip(), f"{label} must not be empty"
    for marker in MOJIBAKE_MARKERS:
        assert marker not in text, f"{label} contains mojibake marker {marker!r}"


def assert_scan_shape(result: object) -> None:
    """Validate every documented key and the internal consistency rules."""

    assert isinstance(result, dict)
    required = {
        "safe",
        "level",
        "score",
        "verdict",
        "msg",
        "warnings",
        "findings",
        "permissions_risky",
        "combos",
        "sources",
        "package",
        "sha256",
        "counts",
        "checked_at",
    }
    assert required <= set(result), f"missing keys: {required - set(result)}"

    assert isinstance(result["safe"], bool)
    assert result["level"] in ("safe", "low", "medium", "high", "critical")
    assert isinstance(result["score"], int) and 0 <= result["score"] <= 100
    assert result["verdict"] in ("safe", "suspicious", "dangerous", "critical")
    assert_clean_text(result["msg"], label="msg")
    assert isinstance(result["warnings"], list)
    assert all(isinstance(item, str) for item in result["warnings"])
    assert isinstance(result["findings"], list)
    assert isinstance(result["permissions_risky"], list)
    assert isinstance(result["combos"], list)
    assert isinstance(result["package"], str)
    assert isinstance(result["sha256"], str)
    assert isinstance(result["counts"], dict)
    assert set(result["counts"]) >= {"permissions", "apis"}
    assert isinstance(result["counts"]["permissions"], int)
    assert isinstance(result["counts"]["apis"], int)
    assert 0 <= result["counts"]["permissions"] <= app_scanner.MAX_PERMISSIONS
    assert 0 <= result["counts"]["apis"] <= app_scanner.MAX_APIS
    assert isinstance(result["checked_at"], str)
    assert ISO_UTC_RE.match(result["checked_at"])
    datetime.fromisoformat(result["checked_at"].replace("Z", "+00:00"))

    for finding in result["findings"]:
        assert set(finding) == {"code", "weight", "ar", "en"}
        assert isinstance(finding["code"], str) and finding["code"]
        assert isinstance(finding["weight"], int)
        assert isinstance(finding["ar"], str) and finding["ar"]
        assert isinstance(finding["en"], str) and finding["en"]
        assert contains_arabic(finding["ar"])

    for item in result["permissions_risky"]:
        assert set(item) == {"name", "risk", "ar", "en", "group"}
        assert isinstance(item["name"], str)
        assert isinstance(item["risk"], int) and 0 <= item["risk"] <= 100
        assert contains_arabic(item["ar"])
        assert isinstance(item["en"], str) and item["en"]

    for combo in result["combos"]:
        assert set(combo) == {"code", "weight", "ar", "en"}
        assert isinstance(combo["weight"], int) and combo["weight"] > 0
        assert contains_arabic(combo["ar"])
        assert isinstance(combo["en"], str) and combo["en"]

    sources = result["sources"]
    assert set(sources) == {"whitelist", "virustotal"}
    assert sources["whitelist"] in ("hit", "miss")
    assert sources["virustotal"] in (
        "clean",
        "hit",
        "disabled",
        "error",
        "skipped",
    )

    # The documented safe rule, verified end to end.
    dangerous_combo = any(combo["weight"] >= 40 for combo in result["combos"])
    expected_safe = (
        result["level"] in ("safe", "low")
        and sources["virustotal"] != "hit"
        and not dangerous_combo
    )
    assert result["safe"] is expected_safe


def assert_finding(result: dict, code: str) -> dict:
    matches = [item for item in result["findings"] if item["code"] == code]
    assert matches, f"expected finding {code!r}, got {[f['code'] for f in result['findings']]}"
    return matches[0]


@contextmanager
def no_vt_key():
    """Temporarily remove the VirusTotal key from the environment."""

    previous = os.environ.pop("VIRUSTOTAL_API_KEY", None)
    try:
        yield
    finally:
        if previous is not None:
            os.environ["VIRUSTOTAL_API_KEY"] = previous


class FakeResponse:
    """Minimal stand-in for ``requests.Response``."""

    def __init__(self, payload=None, status_code: int = 200, json_error: bool = False):
        self.payload = payload
        self.status_code = status_code
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise ValueError("invalid JSON")
        return self.payload


class FakeGet:
    """Callable used to patch ``app_scanner.requests.get``."""

    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


@contextmanager
def patched_get(response):
    fake = FakeGet(response)
    original = app_scanner.requests.get
    app_scanner.requests.get = fake
    try:
        yield fake
    finally:
        app_scanner.requests.get = original


class FakeCertificateHolder:
    human_friendly = "CN=Android Debug, O=Android, C=US"
    native = human_friendly
    rfc4514_string = human_friendly


class FakeCertificate:
    issuer = FakeCertificateHolder()
    subject = FakeCertificateHolder()

    def __str__(self):
        return "CN=Android Debug, O=Android, C=US"


class FakeAPK:
    def __init__(self, raw):
        self.raw = raw

    def get_package(self):
        return "com.example.debuggable"

    def get_app_name(self):
        return "Debug App"

    def get_permissions(self):
        return [
            "android.permission.INTERNET",
            "android.permission.CAMERA",
            None,
            42,
            "android.permission.INTERNET",
        ]

    def get_certificates(self):
        return [FakeCertificate()]


class BrokenAPK:
    def __init__(self, raw):
        raise ValueError("corrupt apk")


@contextmanager
def fake_apk_class(apk_class):
    original = app_scanner._import_apk_class
    app_scanner._import_apk_class = lambda: apk_class
    try:
        yield
    finally:
        app_scanner._import_apk_class = original


# ---------------------------------------------------------------------------
# Data quality
# ---------------------------------------------------------------------------


def test_data_quality():
    assert len(app_scanner.PERMISSIONS) >= 45
    assert len(app_scanner.DANGEROUS_APIS) >= 15
    assert len(app_scanner.DANGEROUS_COMBOS) >= 10
    assert len(app_scanner.WHITELIST) >= 25

    for short_name in REQUIRED_PERMISSIONS:
        full_name = perm(short_name)
        assert full_name in app_scanner.PERMISSIONS, full_name
        meta = app_scanner.PERMISSIONS[full_name]
        assert set(meta) == {"risk", "ar", "en", "group"}
        assert isinstance(meta["risk"], int) and 0 <= meta["risk"] <= 100
        assert isinstance(meta["group"], str) and meta["group"]
        assert_clean_text(meta["ar"], label=f"PERMISSIONS[{full_name}].ar")
        assert_clean_text(meta["en"], label=f"PERMISSIONS[{full_name}].en")
        assert contains_arabic(meta["ar"])

    for api_name in REQUIRED_APIS:
        assert api_name in app_scanner.DANGEROUS_APIS, api_name
        meta = app_scanner.DANGEROUS_APIS[api_name]
        assert set(meta) == {"risk", "ar", "en"}
        assert isinstance(meta["risk"], int) and 0 <= meta["risk"] <= 100
        assert_clean_text(meta["ar"], label=f"DANGEROUS_APIS[{api_name}].ar")
        assert_clean_text(meta["en"], label=f"DANGEROUS_APIS[{api_name}].en")
        assert contains_arabic(meta["ar"])

    codes = set()
    for combo in app_scanner.DANGEROUS_COMBOS:
        assert {"code", "weight", "all", "ar", "en"} <= set(combo)
        assert isinstance(combo["code"], str) and combo["code"]
        assert combo["code"] not in codes
        codes.add(combo["code"])
        assert isinstance(combo["weight"], int) and 0 < combo["weight"] <= 100
        assert isinstance(combo["all"], list) and combo["all"]
        for name in combo["all"]:
            assert name in app_scanner.PERMISSIONS, name
        for name in combo.get("any", []):
            assert name in app_scanner.PERMISSIONS, name
        assert_clean_text(combo["ar"], label=f"combo[{combo['code']}].ar")
        assert_clean_text(combo["en"], label=f"combo[{combo['code']}].en")
        assert contains_arabic(combo["ar"])

    for required_code in REQUIRED_COMBO_CODES:
        assert required_code in codes, required_code

    for entry in app_scanner.WHITELIST:
        assert isinstance(entry, str) and entry
        assert entry == entry.lower()

    # Mandatory publisher entries called out by the product spec.
    for expected in (
        "com.google.",
        "com.android.",
        "com.whatsapp",
        "com.facebook.katana",
        "com.instagram.android",
        "org.telegram.messenger",
        "com.microsoft.",
        "com.spotify.music",
        "com.netflix.mediaclient",
        "com.snapchat.android",
        "com.tiktok.",
        "com.vodafone.",
        "eg.com.instapay",
        "com.apple.",
    ):
        assert expected in app_scanner.WHITELIST, expected


def test_module_has_no_heavy_imports_and_androguard_is_lazy():
    source = (ROOT / "app_scanner.py").read_text(encoding="utf-8")
    import_pattern = re.compile(
        r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_.]*)", re.MULTILINE
    )
    imported_roots = {
        match.group(1).split(".")[0] for match in import_pattern.finditer(source)
    }
    assert "flask" not in imported_roots
    assert "sqlite3" not in imported_roots
    assert "app" not in imported_roots
    assert "requests" in imported_roots

    androguard_imports = [
        match.start()
        for match in re.finditer(
            r"^\s*(?:from|import)\s+androguard\b", source, re.MULTILINE
        )
    ]
    assert androguard_imports, "androguard must be imported somewhere"
    assert min(androguard_imports) > source.index("def _import_apk_class")
    assert source.count("def _import_apk_class") == 1


# ---------------------------------------------------------------------------
# Scoring scenarios
# ---------------------------------------------------------------------------


def test_clean_app_with_internet_only_is_safe():
    with no_vt_key():
        result = app_scanner.scan_app(
            "com.example.clean", [perm("INTERNET")]
        )
    assert_scan_shape(result)
    assert result["counts"] == {"permissions": 1, "apis": 0}
    assert result["score"] < 20
    assert result["level"] == "safe"
    assert result["verdict"] == "safe"
    assert result["safe"] is True
    assert result["permissions_risky"] == []
    assert result["findings"] == []
    assert result["sources"] == {"whitelist": "miss", "virustotal": "disabled"}
    assert result["checked_at"].endswith("Z")


def test_empty_app_scores_zero():
    result = app_scanner.scan_app(None, None)
    assert_scan_shape(result)
    assert result["score"] == 0
    assert result["level"] == "safe"
    assert result["safe"] is True


def test_sms_stealer_combo_is_high_or_critical():
    permissions = [perm("READ_SMS"), perm("RECEIVE_SMS"), perm("INTERNET")]
    result = app_scanner.scan_app("com.example.sms", permissions)
    assert_scan_shape(result)
    codes = [combo["code"] for combo in result["combos"]]
    assert "sms_stealer" in codes
    assert result["level"] in ("high", "critical")
    assert result["score"] >= 60
    assert result["safe"] is False
    assert result["warnings"]
    assert_finding(result, "sms_stealer")

    direct = app_scanner.combo_hits(permissions)
    assert any(combo["code"] == "sms_stealer" for combo in direct)


def test_accessibility_and_overlay_is_critical():
    permissions = [
        perm("BIND_ACCESSIBILITY_SERVICE"),
        perm("SYSTEM_ALERT_WINDOW"),
        perm("INTERNET"),
    ]
    result = app_scanner.scan_app("com.example.spy", permissions)
    assert_scan_shape(result)
    codes = {combo["code"] for combo in result["combos"]}
    assert {"accessibility_abuse", "overlay_phishing"} <= codes
    assert result["level"] == "critical"
    assert result["score"] >= 80
    assert result["safe"] is False
    assert result["verdict"] == "critical"
    assert_finding(result, "accessibility_abuse")
    assert_finding(result, "overlay_phishing")


def test_all_critical_signals_cap_at_100():
    permissions = [perm(name) for name in REQUIRED_PERMISSIONS]
    apis = list(REQUIRED_APIS)
    result = app_scanner.scan_app(
        "com.example.evil",
        permissions,
        apis=apis,
        signature_type="debug",
        vt_report={
            "status": "hit",
            "malicious": 12,
            "total": 70,
            "names": ["evil.apk"],
        },
    )
    assert_scan_shape(result)
    assert result["score"] == 100
    assert result["level"] == "critical"
    assert result["safe"] is False


def test_whitelisted_google_app_without_combos_is_safe():
    result = app_scanner.scan_app(
        "com.google.android.youtube",
        [perm("CAMERA"), perm("RECORD_AUDIO"), perm("INTERNET")],
    )
    assert_scan_shape(result)
    assert result["sources"]["whitelist"] == "hit"
    assert result["score"] <= 5
    assert result["level"] in ("safe", "low")
    assert result["verdict"] == "safe"
    assert result["safe"] is True
    assert result["combos"] == []


def test_whitelist_does_not_override_dangerous_combo():
    result = app_scanner.scan_app(
        "com.google.android.youtube",
        [perm("READ_SMS"), perm("RECEIVE_SMS"), perm("INTERNET")],
    )
    assert_scan_shape(result)
    assert result["sources"]["whitelist"] == "hit"
    assert result["safe"] is False
    assert result["level"] in ("high", "critical")


def test_whitelist_does_not_override_virustotal_hit():
    result = app_scanner.scan_app(
        "com.google.android.youtube",
        [perm("INTERNET")],
        vt_report={
            "status": "hit",
            "malicious": 6,
            "total": 70,
            "names": ["youtube.apk"],
        },
    )
    assert_scan_shape(result)
    assert result["sources"]["virustotal"] == "hit"
    assert result["safe"] is False
    assert result["score"] >= 80
    assert_finding(result, "virustotal_hit")


def test_debug_signature_adds_a_finding_and_points():
    release = app_scanner.scan_app(
        "com.example.signing", [perm("INTERNET")], signature_type="release"
    )
    debug = app_scanner.scan_app(
        "com.example.signing", [perm("INTERNET")], signature_type="DEBUG"
    )
    assert_scan_shape(release)
    assert_scan_shape(debug)
    assert not any(
        finding["code"] == "debug_signature" for finding in release["findings"]
    )
    finding = assert_finding(debug, "debug_signature")
    assert finding["weight"] > 0
    assert debug["score"] > release["score"]


def test_unknown_permissions_are_capped():
    permissions = [f"android.permission.UNKNOWN_{index}" for index in range(10_000)]
    result = app_scanner.scan_app("com.example.unknown", permissions)
    assert_scan_shape(result)
    assert result["counts"]["permissions"] == app_scanner.MAX_PERMISSIONS
    assert result["permissions_risky"] == []
    assert result["score"] == 20
    assert result["level"] == "low"
    finding = assert_finding(result, "unknown_permissions")
    assert finding["weight"] == 20
    assert result["warnings"]


def test_unknown_permissions_are_deduplicated_and_bounded():
    result = app_scanner.scan_app(
        "com.example.unknown",
        ["android.permission.MYSTERY", "android.permission.MYSTERY"]
        + [perm("INTERNET")],
    )
    assert_scan_shape(result)
    assert result["counts"]["permissions"] == 2
    assert result["score"] == 5


def test_apis_are_detected_canonicalized_and_capped():
    result = app_scanner.scan_app(
        "com.example.api",
        [perm("INTERNET")],
        apis=["DexClassLoader", "java.lang.Runtime.exec", "com.example.Unknown"],
    )
    assert_scan_shape(result)
    assert result["counts"]["apis"] == 3
    assert_finding(result, "api:DexClassLoader")
    assert_finding(result, "api:Runtime.exec")

    huge = app_scanner.scan_app(
        "com.example.api",
        [perm("INTERNET")],
        apis=[f"com.example.Api{index}" for index in range(5_000)],
    )
    assert_scan_shape(huge)
    assert huge["counts"]["apis"] == app_scanner.MAX_APIS


def test_permissions_are_deduplicated():
    result = app_scanner.scan_app(
        "com.example.dupes",
        [perm("INTERNET"), perm("INTERNET"), perm("INTERNET")],
    )
    assert_scan_shape(result)
    assert result["counts"]["permissions"] == 1
    assert result["score"] == 3


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def test_risky_permissions_sorted_and_defensive():
    assert app_scanner.risky_permissions(None) == []
    assert app_scanner.risky_permissions(123) == []
    assert app_scanner.risky_permissions(b"\xff\xfe") == []
    assert app_scanner.risky_permissions({"x": 1}) == []

    items = app_scanner.risky_permissions(
        [perm("INTERNET"), perm("READ_SMS"), perm("CAMERA"), perm("READ_SMS")]
    )
    assert items
    risks = [item["risk"] for item in items]
    assert risks == sorted(risks, reverse=True)
    assert {item["name"] for item in items} == {perm("READ_SMS"), perm("CAMERA")}
    assert all(item["risk"] >= app_scanner.RISKY_PERMISSION_THRESHOLD for item in items)

    # Short names and mixed case are accepted.
    short = app_scanner.risky_permissions(["camera", "INTERNET"])
    assert [item["name"] for item in short] == [perm("CAMERA")]


def test_combo_hits_sorted_and_defensive():
    assert app_scanner.combo_hits(None) == []
    assert app_scanner.combo_hits(42) == []
    assert app_scanner.combo_hits({"a": 1}) == []

    hits = app_scanner.combo_hits(
        [perm("READ_SMS"), perm("RECEIVE_SMS"), perm("INTERNET"), perm("READ_CONTACTS")]
    )
    codes = [hit["code"] for hit in hits]
    assert "sms_stealer" in codes
    assert codes == sorted(codes, key=lambda code: -dict(
        (combo["code"], combo["weight"]) for combo in app_scanner.DANGEROUS_COMBOS
    )[code])
    assert all(set(hit) == {"code", "weight", "ar", "en"} for hit in hits)

    # "any" semantics: overlay phishing needs SMS or accessibility in addition
    # to the overlay and internet permissions.
    without_any = app_scanner.combo_hits(
        [perm("SYSTEM_ALERT_WINDOW"), perm("INTERNET")]
    )
    assert "overlay_phishing" not in [hit["code"] for hit in without_any]
    with_accessibility = app_scanner.combo_hits(
        [
            perm("SYSTEM_ALERT_WINDOW"),
            perm("INTERNET"),
            perm("BIND_ACCESSIBILITY_SERVICE"),
        ]
    )
    assert "overlay_phishing" in [hit["code"] for hit in with_accessibility]
    with_sms = app_scanner.combo_hits(
        [perm("SYSTEM_ALERT_WINDOW"), perm("INTERNET"), perm("RECEIVE_SMS")]
    )
    assert "overlay_phishing" in [hit["code"] for hit in with_sms]

    # The SMS stealer needs all three permissions.
    partial = app_scanner.combo_hits([perm("READ_SMS"), perm("INTERNET")])
    assert "sms_stealer" not in [hit["code"] for hit in partial]


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


def test_malformed_inputs_never_raise():
    bad_permissions = [
        None,
        0,
        -1,
        3.14,
        True,
        {"android.permission.INTERNET": True},
        b"\xff\xfe\x00",
        b"android.permission.INTERNET",
        [{"x": 1}, 5, None, True],
        [perm("INTERNET")],
        "",
        "   ",
        [perm("INTERNET")] * 10_000,
        {perm("INTERNET"): "yes", 5: "no"},
    ]
    bad_apis = [
        None,
        7,
        {"DexClassLoader": True},
        b"\x00",
        [None, 3, {"a": 1}],
        "DexClassLoader",
        ["DexClassLoader"] * 10_000,
    ]
    bad_packages = [None, 123, b"com.example", {"p": 1}, "x" * 5_000, ""]
    bad_langs = [None, 5, "fr", "en-US", b"en", {"lang": "ar"}]
    bad_signatures = [None, 5, "weird", "", b"debug"]
    bad_vt = [
        None,
        5,
        "hit",
        [],
        {"status": "weird"},
        {"status": "clean", "malicious": "not-a-number"},
        {"status": "hit", "malicious": None, "total": None},
    ]

    for permissions in bad_permissions:
        for apis in bad_apis[:3]:
            result = app_scanner.scan_app(
                "com.example.malformed",
                permissions,
                apis=apis,
                label={"weird": object()},
                sha256=object(),
                vt_report={"status": "clean", "malicious": 0, "total": 0},
            )
            assert_scan_shape(result)

    for package in bad_packages:
        for lang in bad_langs:
            for signature in bad_signatures:
                result = app_scanner.scan_app(
                    package,
                    [perm("INTERNET")],
                    signature_type=signature,
                    lang=lang,
                )
                assert_scan_shape(result)
                assert isinstance(result["package"], str)
                assert result["msg"]

    for vt_report in bad_vt:
        result = app_scanner.scan_app(
            "com.example.vt",
            [perm("INTERNET")],
            vt_report=vt_report,
        )
        assert_scan_shape(result)
        assert result["sources"]["virustotal"] in (
            "clean",
            "hit",
            "disabled",
            "error",
            "skipped",
        )

    # scan_app must never perform network I/O by itself.
    with patched_get(AssertionError("network must not be touched")) as fake:
        app_scanner.scan_app(
            "com.example.nonet",
            [perm("READ_SMS"), perm("RECEIVE_SMS"), perm("INTERNET")],
            apis=["DexClassLoader"],
            vt_report={"status": "clean", "malicious": 0, "total": 0},
        )
        assert fake.calls == []


def test_factor_functions_never_raise_on_hostile_shapes():
    hostile = [
        None,
        object(),
        {"a": {"b": [1, 2, 3]}},
        [object(), object()],
        b"\x00" * 10,
    ]
    for value in hostile:
        app_scanner.risky_permissions(value)
        app_scanner.combo_hits(value)
        result = app_scanner.scan_app(value, value, apis=value)
        assert_scan_shape(result)


# ---------------------------------------------------------------------------
# Localization
# ---------------------------------------------------------------------------


def test_arabic_and_english_localization():
    permissions = [
        perm("READ_SMS"),
        perm("RECEIVE_SMS"),
        perm("INTERNET"),
        perm("BIND_ACCESSIBILITY_SERVICE"),
    ]
    arabic = app_scanner.scan_app("com.example.lang", permissions, lang="ar")
    english = app_scanner.scan_app("com.example.lang", permissions, lang="en")
    assert_scan_shape(arabic)
    assert_scan_shape(english)

    assert contains_arabic(arabic["msg"])
    assert not contains_arabic(english["msg"])
    assert arabic["msg"] != english["msg"]
    assert arabic["warnings"] and english["warnings"]
    for text in arabic["warnings"]:
        assert contains_arabic(text)
    for text in english["warnings"]:
        assert not contains_arabic(text)
        assert_clean_text(text, label="english warning")

    # Unknown language falls back to Arabic.
    fallback = app_scanner.scan_app("com.example.lang", permissions, lang="fr")
    assert fallback["msg"] == arabic["msg"]

    # The unavailable APK message is localized too.
    with no_vt_key():
        apk_ar = app_scanner.scan_apk(b"corrupt", lang="ar")
        apk_en = app_scanner.scan_apk(b"corrupt", lang="en")
    assert contains_arabic(apk_ar["msg"])
    assert not contains_arabic(apk_en["msg"])
    assert "androguard" in apk_en["msg"].lower()
    assert apk_ar["warnings"] and apk_en["warnings"]


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------


def test_vt_file_report_requires_a_key():
    digest = "a" * 64
    with no_vt_key():
        assert app_scanner.vt_file_report(digest) is None
        assert app_scanner.vt_file_report(None) is None
        assert app_scanner.vt_file_report(digest, key="") is None
        assert app_scanner.vt_file_report("not-a-hash") is None

    # Invalid hashes never reach the network, even with a key.
    with patched_get(AssertionError("must not call network")) as fake:
        report = app_scanner.vt_file_report("not-a-hash", key="test-key")
    assert report is not None and report["status"] == "error"
    assert report["reason"] == "invalid_sha256"
    assert fake.calls == []


def test_vt_file_report_hit():
    digest = "b" * 64
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 60,
                    "malicious": 4,
                    "suspicious": 1,
                    "undetected": 2,
                    "timeout": 0,
                },
                "names": ["evil.apk", "evil.apk", "com.evil.app", 5],
            }
        }
    }
    with no_vt_key(), patched_get(FakeResponse(payload)) as fake:
        report = app_scanner.vt_file_report(digest, key="secret-key", timeout=3)
    assert report == {
        "status": "hit",
        "malicious": 4,
        "total": 67,
        "names": ["evil.apk", "com.evil.app"],
    }
    assert len(fake.calls) == 1
    url, kwargs = fake.calls[0]
    assert url == f"https://www.virustotal.com/api/v3/files/{digest}"
    assert kwargs["headers"]["x-apikey"] == "secret-key"
    assert kwargs["timeout"] == 3.0


def test_vt_file_report_clean_and_env_key():
    digest = "c" * 64
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"harmless": 70, "malicious": 0},
                "names": [],
            }
        }
    }
    previous = os.environ.get("VIRUSTOTAL_API_KEY")
    os.environ["VIRUSTOTAL_API_KEY"] = "env-key"
    try:
        with patched_get(FakeResponse(payload)) as fake:
            report = app_scanner.vt_file_report(digest)
    finally:
        if previous is None:
            os.environ.pop("VIRUSTOTAL_API_KEY", None)
        else:
            os.environ["VIRUSTOTAL_API_KEY"] = previous
    assert report is not None
    assert report["status"] == "clean"
    assert report["malicious"] == 0
    assert report["total"] == 70
    assert report["names"] == []
    assert fake.calls[0][1]["headers"]["x-apikey"] == "env-key"


def test_vt_file_report_error_paths():
    digest = "d" * 64
    cases = [
        (FakeResponse({"message": "not found"}, status_code=404), "not_found"),
        (FakeResponse({}, status_code=401), "unauthorized"),
        (FakeResponse({}, status_code=403), "unauthorized"),
        (FakeResponse({}, status_code=429), "rate_limited"),
        (FakeResponse({}, status_code=500), "http_500"),
        (FakeResponse(None, json_error=True), "invalid_response"),
        (FakeResponse("not a dict"), "invalid_response"),
        (FakeResponse({"data": {"attributes": {}}}), "invalid_response"),
        (app_scanner.requests.RequestException("boom"), "request_failed"),
    ]
    for response, expected_reason in cases:
        with no_vt_key(), patched_get(response):
            report = app_scanner.vt_file_report(digest, key="key")
        assert report is not None
        assert report["status"] == "error"
        assert report["malicious"] == 0
        assert report["total"] == 0
        assert report["names"] == []
        assert report["reason"] == expected_reason


def test_vt_statuses_reach_scan_app():
    disabled = app_scanner.scan_app(
        "com.example.vt", [perm("INTERNET")], vt_report={"status": "disabled"}
    )
    assert disabled["sources"]["virustotal"] == "disabled"
    assert disabled["safe"] is True

    clean = app_scanner.scan_app(
        "com.example.vt",
        [perm("INTERNET")],
        vt_report={"status": "clean", "malicious": 0, "total": 0, "names": []},
    )
    assert clean["sources"]["virustotal"] == "clean"
    assert clean["safe"] is True

    error = app_scanner.scan_app(
        "com.example.vt", [perm("INTERNET")], vt_report={"status": "error"}
    )
    assert error["sources"]["virustotal"] == "error"
    assert error["safe"] is True

    hit = app_scanner.scan_app(
        "com.example.vt",
        [perm("INTERNET")],
        vt_report={"status": "hit", "malicious": 3, "total": 60, "names": ["x"]},
    )
    assert hit["sources"]["virustotal"] == "hit"
    assert hit["safe"] is False
    assert hit["score"] >= 60
    assert_finding(hit, "virustotal_hit")

    malformed = app_scanner.scan_app(
        "com.example.vt", [perm("INTERNET")], vt_report=123
    )
    assert malformed["sources"]["virustotal"] == "error"


def test_vt_skipped_when_env_key_present_but_no_report():
    previous = os.environ.get("VIRUSTOTAL_API_KEY")
    os.environ["VIRUSTOTAL_API_KEY"] = "env-key"
    try:
        result = app_scanner.scan_app("com.example.vt", [perm("INTERNET")])
    finally:
        if previous is None:
            os.environ.pop("VIRUSTOTAL_API_KEY", None)
        else:
            os.environ["VIRUSTOTAL_API_KEY"] = previous
    assert result["sources"]["virustotal"] == "skipped"


# ---------------------------------------------------------------------------
# APK scanning
# ---------------------------------------------------------------------------


def test_scan_apk_without_androguard_is_unavailable():
    payload = os.urandom(512)
    expected = hashlib.sha256(payload).hexdigest()

    with no_vt_key(), patched_get(AssertionError("network must not be touched")) as fake:
        result = app_scanner.scan_apk(payload, filename="random.bin")

    assert fake.calls == []
    assert isinstance(result, dict)
    assert result["status"] == "unavailable"
    assert result["reason"] == "androguard_not_installed"
    assert result["sha256"] == expected
    assert result["score"] == 0
    assert result["safe"] is True
    assert result["level"] == "safe"
    assert result["verdict"] == "safe"
    assert result["warnings"]
    assert result["msg"]
    assert result["filename"] == "random.bin"
    assert result["sources"] == {"whitelist": "miss", "virustotal": "disabled"}
    assert result["counts"] == {"permissions": 0, "apis": 0}
    assert result["virustotal"] is None

    # Empty bytes and non-bytes input are handled too.
    empty = app_scanner.scan_apk(b"")
    assert empty["sha256"] == hashlib.sha256(b"").hexdigest()
    str_input = app_scanner.scan_apk("not bytes")
    assert str_input["sha256"] == hashlib.sha256(b"not bytes").hexdigest()
    none_input = app_scanner.scan_apk(None)
    assert none_input["sha256"] == hashlib.sha256(b"").hexdigest()

    # The Arabic default localizes the explanation.
    assert contains_arabic(result["msg"])


def test_scan_apk_with_fake_androguard_parses_manifest():
    with no_vt_key(), patched_get(AssertionError("network must not be touched")):
        with fake_apk_class(FakeAPK):
            result = app_scanner.scan_apk(b"fake apk bytes", filename="debug.apk")
    assert result["status"] == "ok"
    assert result["reason"] is None
    assert result["package"] == "com.example.debuggable"
    assert result["label"] == "Debug App"
    assert result["signature_type"] == "debug"
    assert result["counts"]["permissions"] == 2
    assert result["filename"] == "debug.apk"
    assert_finding(result, "debug_signature")
    assert result["warnings"]


def test_scan_apk_parse_failure_does_not_raise():
    with no_vt_key():
        with fake_apk_class(BrokenAPK):
            result = app_scanner.scan_apk(b"definitely not an apk")
    assert result["status"] == "error"
    assert result["reason"] == "parse_failed"
    assert result["safe"] is False
    assert 0 <= result["score"] <= 100
    assert result["warnings"]
    assert_clean_text(result["msg"], label="parse failure msg")


def test_scan_apk_uses_virustotal_when_key_is_provided():
    digest_input = b"apk bytes for vt"
    digest = hashlib.sha256(digest_input).hexdigest()
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"harmless": 1, "malicious": 5},
                "names": ["bad.apk"],
            }
        }
    }
    with no_vt_key(), patched_get(FakeResponse(payload)) as fake:
        result = app_scanner.scan_apk(digest_input, vt_key="explicit-key")
    assert len(fake.calls) == 1
    assert digest in fake.calls[0][0]
    # androguard is not installed here, so the unavailable path still reports
    # the VirusTotal lookup in its sources.
    assert result["status"] == "unavailable"
    assert result["sources"]["virustotal"] == "hit"
    assert result["virustotal"] is not None
    assert result["virustotal"]["malicious"] == 5


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------


def main() -> int:
    os.environ.pop("VIRUSTOTAL_API_KEY", None)
    tests = [
        (name, value)
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    failures: list[str] = []
    print(f"Running {len(tests)} tests for app_scanner")
    for name, test in tests:
        try:
            test()
        except Exception:
            failures.append(name)
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"PASS {name}")
    passed = len(tests) - len(failures)
    print(f"\n{passed}/{len(tests)} tests passed")
    if failures:
        print("Failed: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
