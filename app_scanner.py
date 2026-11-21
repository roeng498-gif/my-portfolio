"""SafeGuard app-risk scanner.

This module is intentionally framework-free: it depends only on the Python
standard library and :mod:`requests`.  It powers the "scan an app" feature of
the SafeGuard child-safety product and can be used from Flask, a CLI, a worker
or a test suite without importing the web application, a database or any
application model.

The public surface is:

``PERMISSIONS``, ``DANGEROUS_APIS``, ``DANGEROUS_COMBOS``
    Curated threat-intelligence data (Arabic + English).
``risky_permissions(permissions)``
    Known permissions ranked by risk.
``combo_hits(permissions)``
    Dangerous permission combinations present in the app.
``scan_app(...)``
    Score a package from its manifest permissions and optional API evidence.
``vt_file_report(sha256, key=None, timeout=8)``
    Query VirusTotal for a file hash.
``scan_apk(data, filename="app.apk", lang="ar", vt_key=None)``
    Hash an APK and, when ``androguard`` is installed, inspect its manifest.

Scoring model (deterministic and monotonic):

* Known permissions are sorted by risk and contribute
  ``risk * 0.40 * 0.45**i`` points, capped at 70.  A single ``INTERNET``
  permission therefore scores 3, while many dangerous permissions converge
  towards the cap.
* Dangerous API evidence contributes ``risk * 0.25 * 0.50**i``, capped at 25.
* Each matched dangerous combination contributes its weight, capped at 60 in
  total.  The raw combination weights are what the ``safe`` rule and the
  whitelist override use.
* Unknown permissions add 2 points each (at most 20), a debug signature adds
  15, and a VirusTotal hit adds between 40 and 80.
* The final score is capped at 100.

A package from the trusted-publisher list is forced to a score of at most 5
(and therefore a "safe" verdict) only when it has no dangerous combination and
no VirusTotal hit.  The list is name based and must not be the only control:
package names can be spoofed, so a production deployment should also verify
the signing certificate.

All external input is treated as hostile.  None of the public functions raise
for malformed types, ``None``, huge lists, invalid Unicode or corrupt APK
bytes; they degrade to empty data and still return a well-formed result.
"""

from __future__ import annotations

import hashlib
import itertools
import logging
import math
import os
import re
from datetime import datetime, timezone
from typing import Any

import requests

__all__ = [
    "PERMISSIONS",
    "DANGEROUS_APIS",
    "DANGEROUS_COMBOS",
    "WHITELIST",
    "MAX_PERMISSIONS",
    "MAX_APIS",
    "risky_permissions",
    "combo_hits",
    "scan_app",
    "vt_file_report",
    "scan_apk",
]

__version__ = "1.0.0"

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Limits and score weights
# ---------------------------------------------------------------------------

MAX_PERMISSIONS = 300
MAX_APIS = 300
MAX_RAW_ITEMS = 5_000
MAX_FINDINGS = 1_000
MAX_WARNINGS = 15

RISKY_PERMISSION_THRESHOLD = 40
UNKNOWN_PERMISSION_POINTS = 2
UNKNOWN_PERMISSION_CAP = 20
DEBUG_SIGNATURE_EXTRA = 15
DEBUG_SIGNATURE_WEIGHT = 20
COMBO_DANGEROUS_WEIGHT = 40

PERMISSION_SCORE_CAP = 70.0
API_SCORE_CAP = 25.0
COMBO_SCORE_CAP = 60.0

_VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
_VT_STAT_KEYS = (
    "harmless",
    "malicious",
    "suspicious",
    "undetected",
    "timeout",
    "failure",
    "type-unsupported",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PERMISSION_NAME_RE = re.compile(r"^[A-Za-z0-9_.]{1,200}$")
_API_NAME_RE = re.compile(r"^[A-Za-z0-9_.$/<>-]{1,300}$")

_LEVEL_MESSAGES: dict[str, tuple[str, str]] = {
    "safe": (
        "التطبيق يبدو آمنًا: لم تُكتشف صلاحيات خطرة أو أنماط خبيثة.",
        "This app looks safe: no dangerous permissions or malicious patterns detected.",
    ),
    "low": (
        "مخاطر منخفضة: بعض الصلاحيات تحتاج إلى مراجعة بسيطة.",
        "Low risk: a few permissions deserve a quick review.",
    ),
    "medium": (
        "مخاطر متوسطة: راجع الصلاحيات ومصدر التطبيق قبل الاستخدام.",
        "Medium risk: review the permissions and the app source before use.",
    ),
    "high": (
        "مخاطر عالية: يجمع التطبيق بين صلاحيات خطرة تشير إلى سلوك خبيث محتمل.",
        "High risk: the app combines dangerous permissions that suggest likely malicious behavior.",
    ),
    "critical": (
        "خطر بالغ: أنماط الصلاحيات مطابقة لبرمجيات تجسس أو سرقة بيانات.",
        "Critical risk: the permission patterns match spyware or data-theft behavior.",
    ),
}

_WHITELIST_MESSAGE = (
    "تطبيق من ناشر معروف (قائمة الثقة) ولم تُكتشف أنماط خطرة.",
    "App from a known publisher (trusted list) with no dangerous patterns detected.",
)

_DEBUG_MESSAGE = (
    "التطبيق موقّع بشهادة تصحيح (Debug)، ما يسهّل التلاعب به.",
    "The app is signed with a debug certificate, making tampering easier.",
)

# ---------------------------------------------------------------------------
# Permission intelligence
# ---------------------------------------------------------------------------
# name -> (risk 0..100, group, Arabic explanation, English explanation)

_PERMISSION_SPECS: dict[str, tuple[int, str, str, str]] = {
    "RECEIVE_SMS": (
        85,
        "sms",
        "استقبال الرسائل النصية الواردة، ما يسمح بمراقبة رموز التحقق والرسائل الخاصة.",
        "Receive incoming SMS messages, allowing monitoring of verification codes and private texts.",
    ),
    "READ_SMS": (
        88,
        "sms",
        "قراءة الرسائل النصية المخزنة، ما قد يؤدي إلى سرقة رموز التحقق (OTP) والبيانات الحساسة.",
        "Read stored SMS messages, which can lead to theft of one-time passcodes (OTP) and sensitive data.",
    ),
    "SEND_SMS": (
        90,
        "sms",
        "إرسال رسائل نصية دون علم المستخدم، ما قد يسبب خصم الرصيد أو الاشتراك في خدمات مدفوعة.",
        "Send text messages without the user's knowledge, possibly causing premium charges or paid subscriptions.",
    ),
    "READ_CALL_LOG": (
        82,
        "calls",
        "قراءة سجل المكالمات، ما يكشف جهات الاتصال وأوقات التواصل.",
        "Read the call log, exposing contacts and communication patterns.",
    ),
    "CALL_PHONE": (
        60,
        "calls",
        "إجراء مكالمات هاتفية مباشرة دون تأكيد من المستخدم.",
        "Place phone calls directly without user confirmation.",
    ),
    "READ_CONTACTS": (
        70,
        "contacts",
        "قراءة جهات الاتصال، ما يسمح بسرقة دفتر العناوين والتواصل مع الأقارب.",
        "Read contacts, allowing theft of the address book and contact with family members.",
    ),
    "WRITE_CONTACTS": (
        75,
        "contacts",
        "تعديل جهات الاتصال أو إضافتها، ما قد يُستخدم للتلاعب ببيانات الطفل.",
        "Modify or add contacts, which can be used to tamper with the child's data.",
    ),
    "READ_PHONE_STATE": (
        55,
        "phone",
        "قراءة حالة الهاتف ومعرّفات الشبكة، ما يساعد في تتبع الجهاز.",
        "Read phone state and network identifiers, helping track the device.",
    ),
    "ACCESS_FINE_LOCATION": (
        78,
        "location",
        "تحديد الموقع الدقيق عبر GPS، ما يهدد خصوصية الطفل.",
        "Access precise GPS location, threatening the child's privacy.",
    ),
    "ACCESS_BACKGROUND_LOCATION": (
        85,
        "location",
        "تتبع الموقع في الخلفية حتى عند عدم استخدام التطبيق.",
        "Track location in the background even when the app is not in use.",
    ),
    "ACCESS_COARSE_LOCATION": (
        55,
        "location",
        "تحديد الموقع التقريبي عبر الشبكة أو أبراج الاتصال.",
        "Access approximate location via the network or cell towers.",
    ),
    "RECORD_AUDIO": (
        80,
        "microphone",
        "تسجيل الصوت من الميكروفون دون إذن واضح في كل مرة.",
        "Record audio from the microphone without clear per-use consent.",
    ),
    "CAMERA": (
        72,
        "camera",
        "التقاط الصور ومقاطع الفيديو عبر الكاميرا.",
        "Capture photos and videos through the camera.",
    ),
    "READ_EXTERNAL_STORAGE": (
        45,
        "storage",
        "قراءة الملفات والصور من مساحة التخزين المشتركة.",
        "Read files and photos from shared storage.",
    ),
    "WRITE_EXTERNAL_STORAGE": (
        50,
        "storage",
        "تعديل الملفات أو حذفها في مساحة التخزين المشتركة.",
        "Modify or delete files in shared storage.",
    ),
    "MANAGE_EXTERNAL_STORAGE": (
        88,
        "storage",
        "الوصول الكامل إلى جميع ملفات الجهاز، وهو إذن نادر يُستخدم في برامج الفدية والتجسس.",
        "Full access to all device files, a rare permission abused by ransomware and spyware.",
    ),
    "READ_MEDIA_IMAGES": (
        40,
        "media",
        "قراءة جميع صور الجهاز في أندرويد 13 وما بعده.",
        "Read all images on the device on Android 13 and later.",
    ),
    "READ_MEDIA_VIDEO": (
        40,
        "media",
        "قراءة جميع مقاطع الفيديو على الجهاز.",
        "Read all videos on the device.",
    ),
    "READ_MEDIA_AUDIO": (
        35,
        "media",
        "قراءة جميع الملفات الصوتية على الجهاز.",
        "Read all audio files on the device.",
    ),
    "READ_MEDIA_VISUAL_USER_SELECTED": (
        15,
        "media",
        "الوصول إلى الصور والفيديو التي يحددها المستخدم فقط.",
        "Access only the photos and videos the user selects.",
    ),
    "SYSTEM_ALERT_WINDOW": (
        82,
        "overlay",
        "الرسم فوق التطبيقات الأخرى، ما يتيح هجمات النوافذ المزيفة لسرقة كلمات المرور.",
        "Draw over other apps, enabling overlay phishing attacks that steal passwords.",
    ),
    "BIND_ACCESSIBILITY_SERVICE": (
        95,
        "accessibility",
        "خدمة إمكانية الوصول تسمح بقراءة الشاشة والتحكم الكامل في التطبيقات، وهي أخطر صلاحية على أندرويد.",
        "Accessibility service access allows screen reading and full app control, the most dangerous Android capability.",
    ),
    "REQUEST_INSTALL_PACKAGES": (
        75,
        "install",
        "طلب تثبيت تطبيقات أخرى، ما قد يُستخدم لتثبيت برمجيات خبيثة بصمت.",
        "Request installation of other apps, which can be abused to silently install malware.",
    ),
    "PACKAGE_USAGE_STATS": (
        65,
        "usage",
        "الاطلاع على التطبيقات المستخدمة ومدة الاستخدام، ما ينتهك خصوصية الطفل.",
        "View app usage statistics and screen time, invading the child's privacy.",
    ),
    "BIND_DEVICE_ADMIN": (
        85,
        "admin",
        "صلاحية مسؤول الجهاز تمنع إلغاء التثبيت وتسمح بفرض سياسات قوية.",
        "Device administrator access prevents uninstallation and enforces strong policies.",
    ),
    "DEVICE_ADMIN": (
        85,
        "admin",
        "تفعيل إدارة الجهاز للتحكم في سياسات الجهاز ومنع الإزالة.",
        "Activate device administration to control device policies and resist removal.",
    ),
    "READ_CALENDAR": (
        40,
        "calendar",
        "قراءة مواعيد التقويم والأنشطة الشخصية.",
        "Read calendar events and personal schedules.",
    ),
    "BODY_SENSORS": (
        55,
        "sensors",
        "قراءة بيانات المستشعرات الحيوية مثل معدل ضربات القلب.",
        "Read body sensors such as heart rate.",
    ),
    "POST_NOTIFICATIONS": (
        20,
        "notifications",
        "إرسال إشعارات قد تُستخدم للإزعاج أو التصيّد.",
        "Post notifications that may be used for spam or phishing.",
    ),
    "BIND_NOTIFICATION_LISTENER_SERVICE": (
        75,
        "notifications",
        "قراءة جميع الإشعارات، بما فيها رموز التحقق والرسائل.",
        "Read all notifications, including verification codes and messages.",
    ),
    "INTERNET": (
        8,
        "network",
        "الاتصال بالإنترنت، وهو إذن شائع وضروري لمعظم التطبيقات.",
        "Access the internet, a common permission required by most apps.",
    ),
    "ACCESS_NETWORK_STATE": (
        5,
        "network",
        "معرفة حالة الاتصال بالشبكة.",
        "View network connectivity status.",
    ),
    "ACCESS_WIFI_STATE": (
        5,
        "network",
        "قراءة معلومات شبكة Wi-Fi.",
        "Read Wi-Fi network information.",
    ),
    "CHANGE_WIFI_STATE": (
        20,
        "network",
        "تشغيل شبكة Wi-Fi أو إيقافها.",
        "Turn Wi-Fi on or off.",
    ),
    "WAKE_LOCK": (
        5,
        "system",
        "إبقاء الجهاز مستيقظًا واستهلاك البطارية.",
        "Keep the device awake and consume battery.",
    ),
    "FOREGROUND_SERVICE": (
        10,
        "system",
        "تشغيل خدمة في المقدمة مع إشعار دائم.",
        "Run a foreground service with a persistent notification.",
    ),
    "QUERY_ALL_PACKAGES": (
        45,
        "package",
        "الاستعلام عن جميع التطبيقات المثبتة، ما يكشف عادات الاستخدام.",
        "Query all installed packages, revealing usage habits.",
    ),
    "GET_ACCOUNTS": (
        60,
        "accounts",
        "الوصول إلى قائمة الحسابات على الجهاز.",
        "Access the list of accounts on the device.",
    ),
    "USE_BIOMETRIC": (
        25,
        "biometric",
        "استخدام البصمة أو التعرف على الوجه للمصادقة.",
        "Use fingerprint or face authentication.",
    ),
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": (
        25,
        "battery",
        "طلب استثناء التطبيق من توفير البطارية للعمل دائمًا في الخلفية.",
        "Request exemption from battery optimization to run constantly in the background.",
    ),
    "SCHEDULE_EXACT_ALARM": (
        20,
        "system",
        "جدولة منبهات دقيقة قد تُستخدم لتشغيل مهام في أوقات محددة.",
        "Schedule exact alarms that can trigger tasks at precise times.",
    ),
    "BLUETOOTH_CONNECT": (
        30,
        "bluetooth",
        "الاتصال بالأجهزة القريبة عبر البلوتوث.",
        "Connect to nearby Bluetooth devices.",
    ),
    "BLUETOOTH_SCAN": (
        25,
        "bluetooth",
        "البحث عن أجهزة بلوتوث قريبة.",
        "Scan for nearby Bluetooth devices.",
    ),
    "BLUETOOTH_ADVERTISE": (
        20,
        "bluetooth",
        "الإعلان عن الجهاز لأجهزة البلوتوث القريبة.",
        "Advertise the device to nearby Bluetooth devices.",
    ),
    "NEARBY_WIFI_DEVICES": (
        35,
        "location",
        "الوصول إلى أجهزة Wi-Fi القريبة، ما يساعد في تحديد الموقع.",
        "Access nearby Wi-Fi devices, which can aid location tracking.",
    ),
    "ACTIVITY_RECOGNITION": (
        25,
        "sensors",
        "التعرف على النشاط البدني مثل المشي والجري.",
        "Recognize physical activity such as walking and running.",
    ),
    "RECEIVE_BOOT_COMPLETED": (
        30,
        "system",
        "التشغيل التلقائي عند إعادة تشغيل الجهاز، ما يساعد على الاستمرارية الخبيثة.",
        "Start automatically on boot, enabling persistent malicious behavior.",
    ),
    "WRITE_SETTINGS": (
        55,
        "settings",
        "تعديل إعدادات النظام، ما قد يضعف حماية الجهاز.",
        "Modify system settings, potentially weakening device security.",
    ),
    "MODIFY_AUDIO_SETTINGS": (
        30,
        "settings",
        "تغيير إعدادات الصوت في النظام.",
        "Change global audio settings.",
    ),
    "DELETE_PACKAGES": (
        65,
        "package",
        "طلب حذف تطبيقات أخرى.",
        "Request deletion of other apps.",
    ),
    "INSTALL_PACKAGES": (
        80,
        "install",
        "تثبيت تطبيقات أخرى مباشرة، وهو خطر أمني كبير.",
        "Install other apps directly, a major security risk.",
    ),
    "REQUEST_DELETE_PACKAGES": (
        45,
        "package",
        "طلب إذن حذف التطبيقات.",
        "Request permission to delete apps.",
    ),
    "READ_HISTORY_BOOKMARKS": (
        45,
        "browser",
        "قراءة سجل التصفح والعلامات المرجعية.",
        "Read browsing history and bookmarks.",
    ),
    "PROCESS_OUTGOING_CALLS": (
        70,
        "calls",
        "مراقبة المكالمات الصادرة واعتراضها.",
        "Monitor and intercept outgoing calls.",
    ),
    "ANSWER_PHONE_CALLS": (
        55,
        "calls",
        "الرد على المكالمات الواردة تلقائيًا.",
        "Answer incoming calls automatically.",
    ),
    "READ_PHONE_NUMBERS": (
        35,
        "phone",
        "قراءة أرقام الهاتف المرتبطة بالجهاز.",
        "Read phone numbers associated with the device.",
    ),
    "WRITE_CALL_LOG": (
        78,
        "calls",
        "تعديل سجل المكالمات أو حذفه.",
        "Modify or delete the call log.",
    ),
    "ADD_VOICEMAIL": (
        35,
        "calls",
        "إضافة رسائل بريد صوتي.",
        "Add voicemail messages.",
    ),
    "USE_SIP": (
        45,
        "calls",
        "إجراء مكالمات عبر بروتوكول SIP.",
        "Make calls over the SIP protocol.",
    ),
    "SEND_RESPOND_VIA_MESSAGE": (
        50,
        "sms",
        "إرسال ردود تلقائية على الرسائل.",
        "Send automatic replies to messages.",
    ),
    "KILL_BACKGROUND_PROCESSES": (
        20,
        "system",
        "إيقاف تطبيقات أخرى في الخلفية.",
        "Stop other background apps.",
    ),
    "DISABLE_KEYGUARD": (
        30,
        "system",
        "تعطيل قفل الشاشة مؤقتًا.",
        "Temporarily disable the lock screen.",
    ),
    "EXPAND_STATUS_BAR": (
        25,
        "system",
        "فتح شريط الحالة أو إغلاقه.",
        "Expand or collapse the status bar.",
    ),
    "SET_WALLPAPER": (
        10,
        "system",
        "تغيير خلفية الشاشة.",
        "Change the device wallpaper.",
    ),
    "VIBRATE": (
        5,
        "system",
        "التحكم في اهتزاز الجهاز.",
        "Control device vibration.",
    ),
    "RECEIVE_MMS": (
        40,
        "sms",
        "استقبال رسائل الوسائط المتعددة (MMS).",
        "Receive multimedia messages (MMS).",
    ),
    "ACCESS_MEDIA_LOCATION": (
        30,
        "media",
        "قراءة بيانات الموقع المخزنة في الصور.",
        "Read location metadata stored in photos.",
    ),
}

PERMISSIONS: dict[str, dict] = {
    f"android.permission.{name}": {
        "risk": risk,
        "ar": ar,
        "en": en,
        "group": group,
    }
    for name, (risk, group, ar, en) in _PERMISSION_SPECS.items()
}

# Short-name (case-insensitive) lookup so callers can pass "INTERNET" as well
# as "android.permission.INTERNET".
_SHORT_PERMISSION_LOOKUP: dict[str, str] = {
    key.rsplit(".", 1)[-1].upper(): key for key in PERMISSIONS
}

# ---------------------------------------------------------------------------
# Dangerous API intelligence
# ---------------------------------------------------------------------------

_API_SPECS: dict[str, tuple[int, str, str]] = {
    "DexClassLoader": (
        90,
        "تحميل تعليمات برمجية ديناميكيًا من ملفات خارجية، وهو أسلوب شائع لإخفاء الشيفرة الخبيثة.",
        "Load code dynamically from external files, a common way to hide malicious logic.",
    ),
    "PathClassLoader": (
        70,
        "تحميل فئات Java من مسارات خارجية.",
        "Load Java classes from external paths.",
    ),
    "Runtime.exec": (
        85,
        "تنفيذ أوامر نظام من داخل التطبيق.",
        "Execute system commands from inside the app.",
    ),
    "ProcessBuilder": (
        80,
        "تشغيل عمليات نظام خارجية.",
        "Launch external system processes.",
    ),
    "SmsManager.sendTextMessage": (
        90,
        "إرسال رسائل SMS برمجيًا إلى أرقام عشوائية.",
        "Programmatically send SMS messages to arbitrary numbers.",
    ),
    "SmsManager.sendMultipartTextMessage": (
        90,
        "إرسال رسائل SMS طويلة مقسمة دون علم المستخدم.",
        "Send long multipart SMS messages without the user's knowledge.",
    ),
    "TelephonyManager.getDeviceId": (
        70,
        "قراءة معرّف الجهاز الثابت (IMEI) لتتبع المستخدم.",
        "Read the persistent device ID (IMEI) to track the user.",
    ),
    "LocationManager.requestLocationUpdates": (
        60,
        "طلب تحديثات الموقع بشكل مستمر.",
        "Continuously request location updates.",
    ),
    "Camera.open": (
        65,
        "فتح الكاميرا والتقاط الصور بصمت.",
        "Open the camera and capture images silently.",
    ),
    "MediaRecorder.start": (
        65,
        "بدء تسجيل الصوت أو الفيديو.",
        "Start audio or video recording.",
    ),
    "AudioRecord.startRecording": (
        70,
        "تسجيل الصوت خامًا من الميكروفون.",
        "Record raw audio from the microphone.",
    ),
    "AccessibilityService": (
        90,
        "خدمة إمكانية الوصول تتيح التحكم الكامل بالشاشة.",
        "Accessibility service enabling full screen control.",
    ),
    "NotificationListenerService": (
        80,
        "اعتراض جميع الإشعارات وقراءتها.",
        "Intercept and read all notifications.",
    ),
    "DevicePolicyManager": (
        85,
        "فرض سياسات إدارة الجهاز ومنع الحذف.",
        "Enforce device administration policies and prevent removal.",
    ),
    "AccountManager.getAccounts": (
        65,
        "سرد حسابات المستخدم على الجهاز.",
        "Enumerate the user's accounts on the device.",
    ),
    "ContactsContract": (
        50,
        "الوصول إلى قاعدة بيانات جهات الاتصال.",
        "Access the contacts database.",
    ),
    "ContentResolver.query": (
        45,
        "استعلام موسّع عن بيانات حساسة في النظام.",
        "Run broad queries against sensitive system data.",
    ),
    "Class.forName": (
        40,
        "تحميل فئات ديناميكيًا بحسب مدخلات خارجية.",
        "Load classes dynamically based on external input.",
    ),
    "Method.invoke": (
        55,
        "استدعاء طرق مخفية عبر الانعكاس (Reflection).",
        "Invoke hidden methods through reflection.",
    ),
    "System.loadLibrary": (
        75,
        "تحميل مكتبات أصلية (Native) قد تحتوي شيفرة خبيثة.",
        "Load native libraries that may contain malicious code.",
    ),
    "HttpURLConnection": (
        20,
        "إرسال بيانات عبر HTTP، وغالبًا بدون تشفير.",
        "Send data over HTTP, often without encryption.",
    ),
    "OkHttpClient": (
        20,
        "إرسال البيانات إلى خوادم خارجية.",
        "Send data to external servers.",
    ),
    "Settings.Secure.getString": (
        45,
        "قراءة إعدادات النظام الحساسة ومعرّفات الجهاز.",
        "Read sensitive system settings and device identifiers.",
    ),
    "WebView.addJavascriptInterface": (
        75,
        "حقن واجهة JavaScript في WebView، ما يتيح تنفيذ شيفرة عن بُعد.",
        "Inject a JavaScript bridge into a WebView, enabling remote code execution.",
    ),
    "Cipher.getInstance": (
        35,
        "استخدام التشفير، وقد يُستخدم لتشفير ملفات الضحية.",
        "Use cryptography, which can be abused to encrypt victim files.",
    ),
    "Base64.decode": (
        20,
        "فك ترميز بيانات مخفية داخل التطبيق.",
        "Decode hidden payloads inside the app.",
    ),
}

DANGEROUS_APIS: dict[str, dict] = {
    name: {"risk": risk, "ar": ar, "en": en}
    for name, (risk, ar, en) in _API_SPECS.items()
}

_API_LOOKUP: dict[str, str] = {key.lower(): key for key in DANGEROUS_APIS}
_API_TOKENS: tuple[tuple[str, str], ...] = tuple(
    sorted(_API_LOOKUP.items(), key=lambda item: len(item[0]), reverse=True)
)

# ---------------------------------------------------------------------------
# Dangerous permission combinations (real malware signals)
# ---------------------------------------------------------------------------

DANGEROUS_COMBOS: list[dict] = [
    {
        "code": "sms_stealer",
        "weight": 55,
        "all": [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.INTERNET",
        ],
        "ar": "يجمع التطبيق بين قراءة الرسائل واستقبالها والاتصال بالإنترنت: نمط كلاسيكي لسرقة رسائل التحقق (OTP).",
        "en": "Combines reading and receiving SMS with internet access: a classic one-time-password theft pattern.",
    },
    {
        "code": "accessibility_abuse",
        "weight": 60,
        "all": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.INTERNET",
        ],
        "ar": "خدمة إمكانية الوصول مع اتصال بالإنترنت: تحكم كامل بالشاشة مع إرسال البيانات إلى خادم خارجي.",
        "en": "Accessibility service combined with internet access: full screen control plus data upload to an external server.",
    },
    {
        "code": "overlay_phishing",
        "weight": 50,
        "all": [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET",
        ],
        "any": [
            "android.permission.RECEIVE_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
        "ar": "نوافذ عائمة فوق التطبيقات مع الاتصال بالإنترنت ورسائل أو إمكانية وصول: نمط تصيّد لسرقة كلمات المرور.",
        "en": "Overlay windows combined with internet access and SMS or accessibility: a phishing pattern used to steal credentials.",
    },
    {
        "code": "location_stalker",
        "weight": 50,
        "all": [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.INTERNET",
        ],
        "ar": "موقع دقيق مع تتبع في الخلفية واتصال بالإنترنت: تعقب مستمر لموقع الطفل.",
        "en": "Precise location with background tracking and internet access: continuous stalking of the child's location.",
    },
    {
        "code": "contact_exfiltration",
        "weight": 40,
        "all": [
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
        ],
        "ar": "قراءة جهات الاتصال مع الاتصال بالإنترنت: تسريب دفتر العناوين بالكامل.",
        "en": "Reading contacts with internet access: full address-book exfiltration.",
    },
    {
        "code": "silent_install",
        "weight": 45,
        "all": [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INTERNET",
        ],
        "ar": "طلب تثبيت تطبيقات مع الاتصال بالإنترنت: تثبيت صامت لبرمجيات إضافية.",
        "en": "Requesting app installs with internet access: silent installation of additional software.",
    },
    {
        "code": "device_admin_persistence",
        "weight": 45,
        "all": [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
        "ar": "مسؤول الجهاز مع التشغيل التلقائي عند الإقلاع: بقاء خبيث يصعب إزالته.",
        "en": "Device administrator combined with boot startup: persistence that is hard to remove.",
    },
    {
        "code": "call_log_theft",
        "weight": 45,
        "all": [
            "android.permission.READ_CALL_LOG",
            "android.permission.INTERNET",
        ],
        "ar": "قراءة سجل المكالمات مع الاتصال بالإنترنت: سرقة سجل التواصل.",
        "en": "Reading the call log with internet access: theft of communication history.",
    },
    {
        "code": "audio_spy",
        "weight": 50,
        "all": [
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        ],
        "ar": "تسجيل الصوت مع الموقع في الخلفية: تنصت مخفي مرتبط بالمكان.",
        "en": "Audio recording with background location: hidden location-linked eavesdropping.",
    },
    {
        "code": "full_file_access",
        "weight": 45,
        "all": [
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.INTERNET",
        ],
        "ar": "وصول كامل للملفات مع الاتصال بالإنترنت: قراءة ورفع ملفات الجهاز.",
        "en": "Full file access with internet access: reading and uploading device files.",
    },
]

# ---------------------------------------------------------------------------
# Trusted publisher list
# ---------------------------------------------------------------------------
# Entries ending with "." are prefixes; all others are exact package names.
# This list is intentionally conservative and is only one signal: a determined
# attacker can use a look-alike package name.

WHITELIST: tuple[str, ...] = (
    "com.google.",
    "com.android.",
    "com.android.chrome",
    "com.whatsapp",
    "com.whatsapp.",
    "com.facebook.katana",
    "com.facebook.orca",
    "com.facebook.",
    "com.instagram.android",
    "org.telegram.messenger",
    "com.microsoft.",
    "com.spotify.music",
    "com.netflix.mediaclient",
    "com.snapchat.android",
    "com.tiktok.",
    "com.zhiliaoapp.musically",
    "com.vodafone.",
    "eg.com.instapay",
    "com.apple.",
    "com.amazon.",
    "com.samsung.",
    "com.oneplus.",
    "com.miui.",
    "com.xiaomi.",
    "com.linkedin.android",
    "com.twitter.android",
    "com.discord",
    "com.discord.",
    "com.pinterest.",
    "com.reddit.frontpage",
    "com.uber.",
    "com.booking",
    "com.duolingo",
    "org.wikipedia",
    "com.fawry.",
    "com.paymob.",
    "com.valu.",
    "com.careem.",
    "com.deliveryhero.",
    "com.talabat.",
    "com.bankmisr.",
    "com.nbe.",
    "com.banquemisr.",
)


# ---------------------------------------------------------------------------
# Small defensive helpers
# ---------------------------------------------------------------------------


def _localized(lang: str, ar: str, en: str) -> str:
    """Return the English or Arabic string for a normalized language code."""

    return en if lang == "en" else ar


def _normalize_lang(lang: object) -> str:
    """Map arbitrary input to ``"ar"`` or ``"en"`` (Arabic is the default)."""

    if isinstance(lang, str):
        try:
            if lang.strip().lower().startswith("en"):
                return "en"
        except Exception:  # pragma: no cover - str methods are safe
            pass
    return "ar"


def _clip(value: object, limit: int = 200) -> str:
    """Return a trimmed string, or ``""`` for non-strings."""

    if isinstance(value, str):
        try:
            return value.strip()[:limit]
        except Exception:  # pragma: no cover - defensive
            return ""
    return ""


def _to_int(value: object, default: int = 0) -> int:
    """Best-effort integer conversion that never raises."""

    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        try:
            return int(value)
        except (OverflowError, ValueError):
            return default
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except (TypeError, ValueError, OverflowError):
            return default
    return default


def _sha256_of(data: object) -> str:
    """Hash bytes, or a stable textual representation, without raising."""

    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            raw = bytes(data)
        except Exception:  # pragma: no cover - defensive
            raw = b""
    elif isinstance(data, str):
        raw = data.encode("utf-8", "ignore")
    elif data is None:
        raw = b""
    else:
        try:
            raw = repr(data).encode("utf-8", "ignore")
        except Exception:  # pragma: no cover - defensive
            raw = b""
    return hashlib.sha256(raw).hexdigest()


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string ending in ``Z``."""

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _raw_items(value: object) -> list[Any]:
    """Coerce supported containers into a bounded list of raw candidates.

    Only explicitly supported types are accepted.  Generators and arbitrary
    iterables are rejected on purpose: they could be infinite, and the scanner
    must never hang on hostile input.
    """

    if value is None:
        return []
    if isinstance(value, str):
        text = value[:100_000]
        return [part for part in re.split(r"[\s,;]+", text) if part]
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            text = bytes(value).decode("utf-8", "ignore")
        except Exception:  # pragma: no cover - defensive
            return []
        return _raw_items(text)
    if isinstance(value, dict):
        try:
            return list(value.keys())[:MAX_RAW_ITEMS]
        except Exception:  # pragma: no cover - defensive
            return []
    if isinstance(value, (list, tuple)):
        try:
            return list(value[:MAX_RAW_ITEMS])
        except Exception:  # pragma: no cover - defensive
            return []
    if isinstance(value, (set, frozenset)):
        try:
            return list(itertools.islice(value, MAX_RAW_ITEMS))
        except Exception:  # pragma: no cover - defensive
            return []
    return []


def _canonical_permission(name: object) -> str | None:
    """Normalize a permission name to its full ``android.permission.*`` form.

    Unknown but syntactically valid names are returned unchanged (they are the
    caller's responsibility to score).  Invalid names return ``None``.
    """

    if not isinstance(name, str):
        return None
    text = name.strip()
    if not text or len(text) > 200:
        return None
    if not _PERMISSION_NAME_RE.match(text):
        return None
    if text in PERMISSIONS:
        return text
    if "." not in text:
        candidate = f"android.permission.{text}"
        if candidate in PERMISSIONS:
            return candidate
        return _SHORT_PERMISSION_LOOKUP.get(text.upper(), text)
    return text


def _prepare_permissions(permissions: object) -> list[str]:
    """Return a de-duplicated, capped list of canonical permission names."""

    prepared: list[str] = []
    seen: set[str] = set()
    for item in _raw_items(permissions):
        if len(prepared) >= MAX_PERMISSIONS:
            break
        canonical = _canonical_permission(item)
        if canonical is None or canonical in seen:
            continue
        seen.add(canonical)
        prepared.append(canonical)
    return prepared


def _canonical_api(name: object) -> str | None:
    """Normalize an API reference such as ``java.lang.Runtime.exec``."""

    if not isinstance(name, str):
        return None
    text = name.strip()
    if not text or len(text) > 300:
        return None
    if not _API_NAME_RE.match(text):
        return None
    lowered = text.lower()
    if lowered in _API_LOOKUP:
        return _API_LOOKUP[lowered]
    for token, canonical in _API_TOKENS:
        if token in lowered:
            return canonical
    return text


def _prepare_apis(apis: object) -> list[str]:
    """Return a de-duplicated, capped list of canonical API names."""

    prepared: list[str] = []
    seen: set[str] = set()
    for item in _raw_items(apis):
        if len(prepared) >= MAX_APIS:
            break
        canonical = _canonical_api(item)
        if canonical is None or canonical in seen:
            continue
        seen.add(canonical)
        prepared.append(canonical)
    return prepared


def _whitelist_match(package: object) -> str | None:
    """Return the matching trusted-publisher entry, or ``None``."""

    normalized = _clip(package, 255).lower()
    if not normalized:
        return None
    for entry in WHITELIST:
        candidate = entry.lower()
        if candidate.endswith("."):
            if normalized.startswith(candidate) and len(normalized) > len(candidate):
                return entry
        elif normalized == candidate:
            return entry
    return None


def _level_for(score: int) -> str:
    """Map a 0..100 score to the product's five-level scale."""

    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "safe"


def _verdict_for(level: str) -> str:
    """Map a level to the verdict shown to users."""

    if level in ("safe", "low"):
        return "safe"
    if level == "medium":
        return "suspicious"
    if level == "high":
        return "dangerous"
    return "critical"


# ---------------------------------------------------------------------------
# VirusTotal helpers
# ---------------------------------------------------------------------------


def _vt_value(report: object, key: str) -> Any:
    if not isinstance(report, dict):
        return None
    try:
        return report.get(key)
    except Exception:  # pragma: no cover - hostile dict subclass
        return None


def _vt_malicious(report: object) -> int:
    return max(0, _to_int(_vt_value(report, "malicious"), 0))


def _vt_hit(report: object) -> bool:
    """True when a report marks the file as malicious."""

    if not isinstance(report, dict):
        return False
    status = _vt_value(report, "status")
    if status == "hit":
        return True
    return _vt_malicious(report) > 0


def _vt_status(report: object) -> str:
    """Normalize a VirusTotal report to one of the public source statuses."""

    if report is None:
        return "disabled"
    if not isinstance(report, dict):
        return "error"
    status = _vt_value(report, "status")
    if status in ("clean", "hit", "disabled", "error", "skipped"):
        normalized = str(status)
    elif _vt_malicious(report) > 0:
        normalized = "hit"
    else:
        normalized = "error"
    if normalized == "clean" and _vt_malicious(report) > 0:
        return "hit"
    return normalized


def _vt_error(reason: str) -> dict:
    """Build the error shape returned by :func:`vt_file_report`."""

    return {
        "status": "error",
        "malicious": 0,
        "total": 0,
        "names": [],
        "reason": reason,
    }


def _vt_names(attributes: dict) -> list[str]:
    raw = attributes.get("names")
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return []
    names: list[str] = []
    seen: set[str] = set()
    try:
        iterator: Any = itertools.islice(raw, 50)
    except Exception:  # pragma: no cover - defensive
        return []
    for item in iterator:
        if not isinstance(item, str):
            continue
        name = item.strip()[:120]
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
        if len(names) >= 10:
            break
    return names


def vt_file_report(sha256: object, key: object = None, timeout: object = 8) -> dict | None:
    """Look up a SHA-256 hash on VirusTotal.

    Returns ``None`` when no API key is available (explicitly passed or via the
    ``VIRUSTOTAL_API_KEY`` environment variable).  Every other failure is
    represented as a dict with ``status == "error"`` rather than an exception.

    The returned shape is::

        {"status": "hit"|"clean"|"disabled"|"error",
         "malicious": int, "total": int, "names": [str]}

    Error responses additionally carry a short ``"reason"``.
    """

    api_key = key if isinstance(key, str) and key.strip() else os.environ.get(
        "VIRUSTOTAL_API_KEY"
    )
    if not isinstance(api_key, str) or not api_key.strip():
        return None

    digest = _clip(sha256, 128).lower()
    if isinstance(sha256, (bytes, bytearray, memoryview)):
        try:
            digest = bytes(sha256).decode("ascii", "ignore").strip().lower()[:128]
        except Exception:  # pragma: no cover - defensive
            digest = ""
    if not _SHA256_RE.match(digest):
        return _vt_error("invalid_sha256")

    try:
        timeout_value = float(timeout)
        if not math.isfinite(timeout_value) or timeout_value <= 0:
            timeout_value = 8.0
    except (TypeError, ValueError, OverflowError):
        timeout_value = 8.0
    timeout_value = min(max(timeout_value, 1.0), 30.0)

    try:
        response = requests.get(
            _VT_URL.format(sha256=digest),
            headers={"x-apikey": api_key.strip(), "accept": "application/json"},
            timeout=timeout_value,
        )
    except requests.RequestException as exc:
        logger.debug("VirusTotal request failed: %s", type(exc).__name__)
        return _vt_error("request_failed")
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("VirusTotal request failed unexpectedly: %s", type(exc).__name__)
        return _vt_error("request_failed")

    status_code = _to_int(getattr(response, "status_code", 200), 200)
    if status_code == 404:
        return _vt_error("not_found")
    if status_code in (401, 403):
        return _vt_error("unauthorized")
    if status_code == 429:
        return _vt_error("rate_limited")
    if status_code < 200 or status_code >= 300:
        return _vt_error(f"http_{status_code}")

    try:
        payload = response.json()
    except Exception:
        return _vt_error("invalid_response")
    if not isinstance(payload, dict):
        return _vt_error("invalid_response")

    data = payload.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        return _vt_error("invalid_response")

    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        # A file object without analysis stats is not a trustworthy report:
        # treating it as "clean" would be worse than reporting an error.
        return _vt_error("invalid_response")

    malicious = max(0, _to_int(stats.get("malicious"), 0))
    suspicious = max(0, _to_int(stats.get("suspicious"), 0))
    total = 0
    for stat_key in _VT_STAT_KEYS:
        total += max(0, _to_int(stats.get(stat_key), 0))
    if total <= 0:
        total = malicious + suspicious

    return {
        "status": "hit" if malicious > 0 else "clean",
        "malicious": malicious,
        "total": total,
        "names": _vt_names(attributes),
    }


# ---------------------------------------------------------------------------
# Public scanning functions
# ---------------------------------------------------------------------------


def risky_permissions(permissions: object) -> list[dict]:
    """Return known risky permissions, sorted by risk descending.

    Accepts a list/tuple/set of permission names, a single string, a dict whose
    keys are names, or bytes.  Anything else (including ``None``) yields an
    empty list.  Only permissions at or above
    :data:`RISKY_PERMISSION_THRESHOLD` are returned; low-risk plumbing
    permissions such as ``INTERNET`` stay out of the "risky" list but still
    contribute a small number of points to the score.
    """

    items: list[dict] = []
    for name in _prepare_permissions(permissions):
        meta = PERMISSIONS.get(name)
        if meta is None:
            continue
        risk = _to_int(meta.get("risk"), 0)
        if risk < RISKY_PERMISSION_THRESHOLD:
            continue
        items.append(
            {
                "name": name,
                "risk": risk,
                "ar": str(meta.get("ar", "")),
                "en": str(meta.get("en", "")),
                "group": str(meta.get("group", "")),
            }
        )
    items.sort(key=lambda item: (-item["risk"], item["name"]))
    return items


def combo_hits(permissions: object) -> list[dict]:
    """Return dangerous permission combinations matched by ``permissions``.

    ``all`` entries are mandatory.  A combination may also declare ``any``:
    at least one of those permissions must be present.  Results are sorted by
    weight descending (worst first) and are safe to serialize directly.
    """

    present = set(_prepare_permissions(permissions))
    hits: list[dict] = []
    for combo in DANGEROUS_COMBOS:
        required = combo.get("all") or []
        matched = True
        for item in required:
            canonical = _canonical_permission(item)
            if canonical is None or canonical not in present:
                matched = False
                break
        if not matched:
            continue

        alternatives = combo.get("any") or []
        if alternatives:
            any_matched = False
            for item in alternatives:
                canonical = _canonical_permission(item)
                if canonical is not None and canonical in present:
                    any_matched = True
                    break
            if not any_matched:
                continue

        hits.append(
            {
                "code": str(combo.get("code", "")),
                "weight": _to_int(combo.get("weight"), 0),
                "ar": str(combo.get("ar", "")),
                "en": str(combo.get("en", "")),
            }
        )
    hits.sort(key=lambda item: (-item["weight"], item["code"]))
    return hits


def scan_app(
    package_name: object,
    permissions: object,
    apis: object = None,
    label: object = "",
    sha256: object = "",
    signature_type: object = None,
    lang: object = "ar",
    vt_report: object = None,
) -> dict:
    """Score an Android app from its package metadata and permissions.

    Parameters are accepted as ``object`` on purpose so untrusted JSON from a
    web request can be passed without pre-validation.  The return value always
    contains every documented key with the correct type.

    The ``label`` argument is accepted for API compatibility (and for callers
    that render it themselves); it does not influence the score.

    See the module docstring for the scoring model.
    """

    language = _normalize_lang(lang)
    package = _clip(package_name, 255)
    digest = _clip(sha256, 128)
    # Keep the argument part of the contract even though the caller normally
    # renders it; sanitize it so a hostile value cannot leak downstream.
    _ = _clip(label, 255)

    prepared_permissions = _prepare_permissions(permissions)
    prepared_apis = _prepare_apis(apis)

    risky = risky_permissions(prepared_permissions)
    combos = combo_hits(prepared_permissions)

    # --- permission component -------------------------------------------------
    known_risks = sorted(
        (
            _to_int(PERMISSIONS[name].get("risk"), 0)
            for name in prepared_permissions
            if name in PERMISSIONS
        ),
        reverse=True,
    )
    permission_points = 0.0
    for index, risk in enumerate(known_risks):
        permission_points += risk * 0.40 * (0.45**index)
    permission_points = min(PERMISSION_SCORE_CAP, permission_points)

    # --- API component --------------------------------------------------------
    api_risks = sorted(
        (
            _to_int(DANGEROUS_APIS[name].get("risk"), 0)
            for name in prepared_apis
            if name in DANGEROUS_APIS
        ),
        reverse=True,
    )
    api_points = 0.0
    for index, risk in enumerate(api_risks):
        api_points += risk * 0.25 * (0.50**index)
    api_points = min(API_SCORE_CAP, api_points)

    # --- combination component ------------------------------------------------
    combo_points = min(
        COMBO_SCORE_CAP,
        float(sum(_to_int(combo.get("weight"), 0) for combo in combos)),
    )

    # --- non-permission evidence ---------------------------------------------
    unknown_permissions = [
        name for name in prepared_permissions if name not in PERMISSIONS
    ]
    unknown_points = min(
        UNKNOWN_PERMISSION_CAP,
        UNKNOWN_PERMISSION_POINTS * len(unknown_permissions),
    )

    signature = _clip(signature_type, 64).lower()
    debug_signed = signature in {"debug", "debug_key", "test", "testkey"} or (
        "debug" in signature
    )

    vt_hit = _vt_hit(vt_report)
    vt_malicious_count = _vt_malicious(vt_report)
    vt_weight = (
        min(80, 40 + 4 * vt_malicious_count)
        if vt_hit
        else 0
    )

    extra_points = float(unknown_points)
    if debug_signed:
        extra_points += DEBUG_SIGNATURE_EXTRA
    if vt_hit:
        extra_points += float(vt_weight)

    score = int(
        round(permission_points + api_points + combo_points + extra_points)
    )
    score = max(0, min(100, score))

    # A confirmed VirusTotal detection must never look "safe"/"low".
    if vt_hit:
        score = max(score, 80 if vt_malicious_count >= 5 else 60)
        score = min(100, score)

    dangerous_combo = any(
        _to_int(combo.get("weight"), 0) >= COMBO_DANGEROUS_WEIGHT
        for combo in combos
    )
    whitelist_entry = _whitelist_match(package)
    whitelist_forced = (
        whitelist_entry is not None and not dangerous_combo and not vt_hit
    )
    if whitelist_forced:
        score = min(score, 5)

    level = _level_for(score)
    verdict = _verdict_for(level)
    safe = (
        level in ("safe", "low")
        and not vt_hit
        and not dangerous_combo
    )

    # --- findings -------------------------------------------------------------
    findings: list[dict] = []
    for item in risky:
        findings.append(
            {
                "code": f"perm:{item['name']}",
                "weight": item["risk"],
                "ar": item["ar"],
                "en": item["en"],
            }
        )
    for combo in combos:
        findings.append(
            {
                "code": combo["code"],
                "weight": combo["weight"],
                "ar": combo["ar"],
                "en": combo["en"],
            }
        )
    for api_name in prepared_apis:
        meta = DANGEROUS_APIS.get(api_name)
        if meta is None:
            continue
        findings.append(
            {
                "code": f"api:{api_name}",
                "weight": _to_int(meta.get("risk"), 0),
                "ar": str(meta.get("ar", "")),
                "en": str(meta.get("en", "")),
            }
        )
    if unknown_permissions:
        findings.append(
            {
                "code": "unknown_permissions",
                "weight": unknown_points,
                "ar": (
                    f"رُصدت {len(unknown_permissions)} صلاحية غير معروفة، وقد تشير "
                    "إلى محاولة تجاوز المراجعة."
                ),
                "en": (
                    f"{len(unknown_permissions)} unrecognized permission(s) detected; "
                    "this may indicate an attempt to bypass review."
                ),
            }
        )
    if debug_signed:
        findings.append(
            {
                "code": "debug_signature",
                "weight": DEBUG_SIGNATURE_WEIGHT,
                "ar": _DEBUG_MESSAGE[0],
                "en": _DEBUG_MESSAGE[1],
            }
        )
    if vt_hit:
        findings.append(
            {
                "code": "virustotal_hit",
                "weight": vt_weight,
                "ar": (
                    f"أبلغ VirusTotal عن {vt_malicious_count} محرك أمني باعتبار "
                    "ملف التطبيق خبيثًا."
                ),
                "en": (
                    f"VirusTotal flagged the app file as malicious by "
                    f"{vt_malicious_count} engine(s)."
                ),
            }
        )

    findings.sort(key=lambda item: (-item["weight"], item["code"]))
    findings = findings[:MAX_FINDINGS]

    # --- warnings (worst first) ----------------------------------------------
    weighted_warnings: list[tuple[int, str]] = []
    for combo in combos:
        text = combo["ar"] if language == "ar" else combo["en"]
        weighted_warnings.append((combo["weight"], text))
    for item in risky[:8]:
        if language == "ar":
            text = f"صلاحية عالية الخطورة: {item['ar']}"
        else:
            text = f"High-risk permission: {item['en']}"
        weighted_warnings.append((item["risk"], text))
    for api_name in prepared_apis:
        meta = DANGEROUS_APIS.get(api_name)
        if meta is None:
            continue
        text = (
            f"استدعاء API خطير: {api_name} — {meta['ar']}"
            if language == "ar"
            else f"Dangerous API call: {api_name} — {meta['en']}"
        )
        weighted_warnings.append((_to_int(meta.get("risk"), 0), text))
    if unknown_permissions:
        if language == "ar":
            text = (
                f"{len(unknown_permissions)} صلاحية غير معروفة قد تخفي سلوكًا "
                "خبيثًا؛ تم احتسابها بحد أقصى 20 نقطة."
            )
        else:
            text = (
                f"{len(unknown_permissions)} unrecognized permission(s) may hide "
                "malicious behavior; they are capped at 20 points."
            )
        weighted_warnings.append((unknown_points, text))
    if debug_signed:
        weighted_warnings.append(
            (DEBUG_SIGNATURE_WEIGHT, _DEBUG_MESSAGE[0] if language == "ar" else _DEBUG_MESSAGE[1])
        )
    if vt_hit:
        if language == "ar":
            text = (
                f"VirusTotal: كشف {vt_malicious_count} محرك أمني الملف كخبيث."
            )
        else:
            text = (
                f"VirusTotal: {vt_malicious_count} security engine(s) flagged "
                "the file as malicious."
            )
        weighted_warnings.append((vt_weight, text))

    weighted_warnings.sort(key=lambda item: (-item[0], item[1]))
    warnings: list[str] = []
    seen_warnings: set[str] = set()
    for _, text in weighted_warnings:
        if not text or text in seen_warnings:
            continue
        seen_warnings.add(text)
        warnings.append(text)
        if len(warnings) >= MAX_WARNINGS:
            break

    # --- VirusTotal source status --------------------------------------------
    if vt_report is None:
        virustotal_status = (
            "skipped" if os.environ.get("VIRUSTOTAL_API_KEY") else "disabled"
        )
    else:
        virustotal_status = _vt_status(vt_report)

    if whitelist_forced:
        message = _localized(language, _WHITELIST_MESSAGE[0], _WHITELIST_MESSAGE[1])
    else:
        message = _localized(
            language, _LEVEL_MESSAGES[level][0], _LEVEL_MESSAGES[level][1]
        )

    return {
        "safe": bool(safe),
        "level": level,
        "score": int(score),
        "verdict": verdict,
        "msg": message,
        "warnings": warnings,
        "findings": findings,
        "permissions_risky": risky,
        "combos": combos,
        "sources": {
            "whitelist": "hit" if whitelist_entry is not None else "miss",
            "virustotal": virustotal_status,
        },
        "package": package,
        "sha256": digest,
        "counts": {
            "permissions": len(prepared_permissions),
            "apis": len(prepared_apis),
        },
        "checked_at": _utc_now(),
    }


# ---------------------------------------------------------------------------
# APK scanning (androguard is optional and lazily imported)
# ---------------------------------------------------------------------------


def _import_apk_class() -> Any:
    """Import and return ``androguard``'s APK class, or ``None``.

    The import happens inside the APK functions so that deployments without
    ``androguard`` can still use the rest of this module.
    """

    try:
        from androguard.core.apk import APK  # type: ignore[import-not-found]

        return APK
    except Exception:
        pass
    try:
        from androguard.core.bytecodes.apk import APK  # type: ignore[import-not-found]

        return APK
    except Exception:
        return None


def _limited_values(value: object, limit: int = 20) -> list[Any]:
    """Return at most ``limit`` items from a container, never raising."""

    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        try:
            return list(itertools.islice(value, limit))
        except Exception:  # pragma: no cover - defensive
            return []
    return [value]


def _certificate_text(apk: object) -> str:
    """Extract human-readable certificate text from an androguard APK."""

    chunks: list[str] = []
    getters = (
        "get_certificates",
        "get_signature_names",
        "get_signature",
    )
    for getter_name in getters:
        getter = getattr(apk, getter_name, None)
        if not callable(getter):
            continue
        try:
            value = getter()
        except Exception:
            continue
        for item in _limited_values(value):
            if isinstance(item, str):
                chunks.append(item)
                continue
            for attr_name in ("human_friendly", "native", "rfc4514_string"):
                try:
                    attr_value = getattr(item, attr_name, None)
                except Exception:
                    continue
                if isinstance(attr_value, str):
                    chunks.append(attr_value)
            for holder_name in ("issuer", "subject"):
                try:
                    holder = getattr(item, holder_name, None)
                except Exception:
                    holder = None
                if holder is None:
                    continue
                for attr_name in ("human_friendly", "native", "rfc4514_string"):
                    try:
                        attr_value = getattr(holder, attr_name, None)
                    except Exception:
                        continue
                    if isinstance(attr_value, str):
                        chunks.append(attr_value)
            try:
                chunks.append(str(item))
            except Exception:  # pragma: no cover - defensive
                pass
    return " | ".join(chunk for chunk in chunks if chunk)


def _apk_is_debug_signed(apk: object) -> bool:
    """Best-effort debug-certificate detection that never raises."""

    try:
        text = _certificate_text(apk)
    except Exception:  # pragma: no cover - defensive
        return False
    lowered = text.lower()
    return "android debug" in lowered or "cn=android debug" in lowered


def _apk_call(apk: object, method: str, default: Any) -> Any:
    """Call an androguard accessor defensively."""

    accessor = getattr(apk, method, None)
    if not callable(accessor):
        return default
    try:
        value = accessor()
    except Exception:
        return default
    return default if value is None else value


def _unavailable_apk_result(
    digest: str,
    filename: str,
    language: str,
    vt_report: dict | None,
    virustotal_status: str,
) -> dict:
    """Result returned when ``androguard`` is not installed."""

    if language == "ar":
        message = (
            "الفحص العميق لملف APK غير مُفعّل على هذا الخادم (مكتبة androguard "
            "غير مثبتة)؛ تم حساب بصمة SHA-256 فقط."
        )
        warning = (
            "لم يتم تحليل محتوى التطبيق أو صلاحياته؛ هذه النتيجة لا تعني أن "
            "التطبيق آمن."
        )
    else:
        message = (
            "APK deep scanning is disabled on this server because the androguard "
            "library is not installed; only the SHA-256 hash was computed."
        )
        warning = (
            "The app's contents and permissions were not analyzed; this result "
            "does not mean the app is safe."
        )
    warnings = [warning]
    if vt_report is not None and _vt_hit(vt_report):
        malicious = _vt_malicious(vt_report)
        warnings.insert(
            0,
            (
                f"VirusTotal: كشف {malicious} محرك أمني الملف كخبيث."
                if language == "ar"
                else f"VirusTotal: {malicious} security engine(s) flagged the file as malicious."
            ),
        )
    return {
        "status": "unavailable",
        "reason": "androguard_not_installed",
        "sha256": digest,
        "filename": filename,
        "package": "",
        "label": "",
        "permissions": [],
        "apis": [],
        "score": 0,
        "safe": True,
        "level": "safe",
        "verdict": "safe",
        "msg": message,
        "warnings": warnings,
        "findings": [],
        "permissions_risky": [],
        "combos": [],
        "sources": {"whitelist": "miss", "virustotal": virustotal_status},
        "counts": {"permissions": 0, "apis": 0},
        "checked_at": _utc_now(),
        "virustotal": vt_report,
    }


def _failed_apk_result(
    digest: str,
    filename: str,
    language: str,
    vt_report: dict | None,
    virustotal_status: str,
) -> dict:
    """Result returned when androguard is present but cannot parse the file."""

    if language == "ar":
        message = "تعذّر تحليل ملف APK؛ قد يكون الملف تالفًا أو غير مدعوم."
        warning = "فشل الفحص العميق، ولا يمكن تأكيد سلامة التطبيق."
    else:
        message = "The APK could not be parsed; the file may be corrupt or unsupported."
        warning = "Deep scanning failed, so the app's safety cannot be confirmed."
    return {
        "status": "error",
        "reason": "parse_failed",
        "sha256": digest,
        "filename": filename,
        "package": "",
        "label": "",
        "permissions": [],
        "apis": [],
        "score": 40,
        "safe": False,
        "level": "medium",
        "verdict": "suspicious",
        "msg": message,
        "warnings": [warning],
        "findings": [],
        "permissions_risky": [],
        "combos": [],
        "sources": {"whitelist": "miss", "virustotal": virustotal_status},
        "counts": {"permissions": 0, "apis": 0},
        "checked_at": _utc_now(),
        "virustotal": vt_report,
    }


def scan_apk(
    data: bytes,
    filename: object = "app.apk",
    lang: object = "ar",
    vt_key: object = None,
) -> dict:
    """Hash and (when possible) deeply scan an APK.

    The SHA-256 digest is always computed, even for corrupt or empty input.
    ``androguard`` is imported lazily; when it is missing the function returns
    a successful, well-formed *unavailable* result instead of raising.

    VirusTotal is queried by hash when an API key is supplied explicitly or via
    the ``VIRUSTOTAL_API_KEY`` environment variable.
    """

    language = _normalize_lang(lang)
    safe_filename = _clip(filename, 255) or "app.apk"
    digest = _sha256_of(data)

    api_key = vt_key if isinstance(vt_key, str) and vt_key.strip() else None
    if api_key is None:
        env_key = os.environ.get("VIRUSTOTAL_API_KEY")
        api_key = env_key if isinstance(env_key, str) and env_key.strip() else None

    vt_report: dict | None = None
    if api_key is not None:
        vt_report = vt_file_report(digest, key=api_key)

    if vt_report is None:
        virustotal_status = "disabled"
    else:
        virustotal_status = _vt_status(vt_report)

    apk_class = _import_apk_class()
    if apk_class is None:
        return _unavailable_apk_result(
            digest, safe_filename, language, vt_report, virustotal_status
        )

    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            raw = bytes(data)
        except Exception:  # pragma: no cover - defensive
            raw = b""
    elif isinstance(data, str):
        raw = data.encode("utf-8", "ignore")
    elif data is None:
        raw = b""
    else:
        try:
            raw = repr(data).encode("utf-8", "ignore")
        except Exception:  # pragma: no cover - defensive
            raw = b""

    try:
        apk = apk_class(raw)
    except Exception as exc:
        logger.debug("APK parse failed: %s", type(exc).__name__)
        return _failed_apk_result(
            digest, safe_filename, language, vt_report, virustotal_status
        )

    package = _clip(_apk_call(apk, "get_package", ""), 255)
    label = _clip(_apk_call(apk, "get_app_name", ""), 255)
    raw_permissions = _apk_call(apk, "get_permissions", [])
    if not isinstance(raw_permissions, (list, tuple, set, frozenset)):
        raw_permissions = []
    try:
        permissions = [item for item in itertools.islice(raw_permissions, MAX_PERMISSIONS)]
    except Exception:  # pragma: no cover - defensive
        permissions = []

    debug_signed = _apk_is_debug_signed(apk)
    signature_type = "debug" if debug_signed else "release"

    result = scan_app(
        package,
        permissions,
        apis=None,
        label=label,
        sha256=digest,
        signature_type=signature_type,
        lang=language,
        vt_report=vt_report,
    )

    if language == "ar":
        unavailable_note = (
            "تم تحليل بيان التطبيق فقط؛ لم يتم تحليل الشيفرة التنفيذية أو "
            "مكتبات dex."
        )
    else:
        unavailable_note = (
            "Only the manifest was analyzed; executable code and dex libraries "
            "were not inspected."
        )
    result["warnings"] = list(result.get("warnings", [])) + [unavailable_note]
    result["warnings"] = result["warnings"][:MAX_WARNINGS]

    result["status"] = "ok"
    result["reason"] = None
    result["filename"] = safe_filename
    result["label"] = label
    result["signature_type"] = signature_type
    result["virustotal"] = vt_report
    return result
