"""محرك فحص الروابط — طبقات متعددة.

1) فحوصات محلية (heuristics) من غير إنترنت: IP، HTTPS، @، punycode، TLD، انتحال علامات، إلخ.
2) فحص الوصول الفعلي مع حماية SSRF (كل تحويلة بتتحقق).
3) Google Safe Browsing + URLhaus + VirusTotal (اختياري بالمفاتيح).

الدالة الأساسية: scan_url() وبترجّع dict فيه safe/level/score/warnings/sources.
مفيش Flask ولا قاعدة بيانات هنا — الموديل ده مستقل بالكامل.
"""
import base64
import ipaddress
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urljoin, urlsplit

import requests

USER_AGENT = 'SafeGuardScanner/2.0'
HTTP_TIMEOUT = 8

# --------------------------------------------------------------------------
# بيانات الفحص المحلي
# --------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.mov', '.top', '.xyz', '.club',
    '.work', '.click', '.link', '.icu', '.cam', '.rest', '.loan', '.buzz', '.fit',
}

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy',
    'shorturl.at', 'rebrand.ly', 'ow.ly', 'buff.ly', 's.id', 't.ly',
}

BRANDS = {
    'paypal': ('paypal.com',),
    'apple': ('apple.com', 'icloud.com'),
    'google': ('google.com', 'gmail.com', 'youtube.com', 'googleusercontent.com'),
    'facebook': ('facebook.com', 'fb.com'),
    'whatsapp': ('whatsapp.com', 'whatsapp.net'),
    'instagram': ('instagram.com',),
    'microsoft': ('microsoft.com', 'live.com', 'office.com', 'outlook.com'),
    'netflix': ('netflix.com',),
    'amazon': ('amazon.com', 'amazon.eg', 'amazon.sa', 'amazon.ae'),
    'telegram': ('telegram.org', 't.me'),
    'tiktok': ('tiktok.com',),
    'snapchat': ('snapchat.com',),
    'steam': ('steampowered.com', 'steamcommunity.com'),
    'vodafone': ('vodafone.com', 'vodafone.com.eg'),
    'instapay': ('instapay.com', 'instapay.com.eg'),
    'bank': ('nbe.com.eg', 'banquemisr.com', 'cibeg.com'),
    'بنك': ('nbe.com.eg', 'banquemisr.com', 'cibeg.com'),
}

PHISH_KEYWORDS = (
    'login', 'verify', 'secure', 'account', 'update', 'wallet', 'bonus', 'free',
    'gift', 'prize', 'password', 'otp', 'confirm', 'support', 'recovery',
    'كلمة المرور', 'تحديث', 'جائزة', 'مجانا', 'مجاناً', 'اربح', 'تحقق',
)

DANGEROUS_EXTENSIONS = ('.apk', '.exe', '.scr', '.msi', '.bat', '.cmd', '.jar', '.vbs', '.ps1')

REDIRECT_PARAMS = {'redirect', 'url', 'next', 'continue', 'goto', 'return', 'target', 'r', 'u'}

TWO_LEVEL_TLDS = {'.co.uk', '.com.eg', '.com.sa', '.com.ae', '.co.ke', '.com.ng'}

TEXTS = {
    'ip_host': ('الرابط يستخدم عنوان IP بدل اسم موقع',
                'The link uses an IP address instead of a domain name'),
    'no_https': ('الرابط لا يستخدم تشفير HTTPS',
                 'The link does not use HTTPS encryption'),
    'at_sign': ('الرابط يحتوي على @ وهي حيلة شائعة في روابط التصيد',
                'The link contains "@", a common phishing trick'),
    'punycode': ('الرابط يستخدم حروفاً مشفرة (punycode) وقد ينتحل اسم موقع',
                 'The link uses punycode characters and may impersonate a domain'),
    'suspicious_tld': ('نطاق الرابط ({tld}) معروف بكثرة الاستخدام في التصيد',
                       'The link TLD ({tld}) is frequently used for phishing'),
    'many_dots': ('الرابط فيه عدد غير طبيعي من النقاط/النطاقات الفرعية',
                  'The link has an unusual number of dots/subdomains'),
    'phish_keywords': ('الرابط فيه كلمات مشبوهة ({word})',
                       'The link contains suspicious keywords ({word})'),
    'brand': ('الرابط ينتحل اسم {brand} وهو مش الموقع الرسمي',
              'The link impersonates {brand} but is not its official domain'),
    'port': ('الرابط بيستخدم بورت غير معتاد ({port})',
             'The link uses a non-standard port ({port})'),
    'long_url': ('الرابط طويل بشكل غير معتاد',
                 'The link is unusually long'),
    'obfuscated': ('الرابط فيه ترميز/تشفير مشبوه لإخفاء الوجهة',
                   'The link contains obfuscated encoding to hide its destination'),
    'dangerous_file': ('الرابط بينزّل ملف قابل للتنفيذ ({ext})',
                       'The link downloads an executable file ({ext})'),
    'shortener': ('الرابط مختصر (مخفي الوجهة الحقيقية)',
                  'The link is shortened (its real destination is hidden)'),
    'redirect_param': ('الرابط بيحوّلك لموقع تاني من خلال باراميتر ({param})',
                       'The link redirects elsewhere through a parameter ({param})'),
    'credentials': ('الرابط فيه بيانات دخول مكتوبة جواه',
                    'The link embeds credentials in the URL'),
    'redirect_cross': ('الرابط بيحوّلك لموقع مختلف ({host})',
                       'The link redirects you to a different site ({host})'),
    'unreachable': ('الرابط غير متاح أو غير موجود وقد يكون موقعًا وهميًا',
                    'The link is unreachable or does not exist; it may be fake'),
    'http_error': ('الرابط أعاد استجابة غير طبيعية (كود {code})',
                   'The link returned an abnormal response (status {code})'),
    'blocked': ('تم رفض الفحص: الرابط يشير إلى عنوان داخلي أو خاص',
                'Scan refused: the link points to an internal/private address'),
    'safe': ('الرابط يبدو آمنًا (لا توجد مؤشرات خطر).',
             'This link looks safe (no risk indicators).'),
    'risky': ('تنبيه: {reasons}', 'Warning: {reasons}'),
    'gsb': ('Google Safe Browsing صنّف الرابط كخطر',
            'Google Safe Browsing flagged this link as dangerous'),
    'urlhaus': ('URLhaus صنّف الرابط كموقع توزيع برمجيات خبيثة',
                'URLhaus flagged this link as malware distribution'),
    'vt': ('VirusTotal: {n} محرك صنّف الرابط كضار',
           'VirusTotal: {n} engines flagged this link as malicious'),
}


class BlockedURL(Exception):
    """الرابط بيشير لعنوان داخلي/خاص (SSRF)"""


class UnreachableURL(Exception):
    """تعذر الوصول للرابط"""


def _txt(key, lang='ar', **fmt):
    ar, en = TEXTS[key]
    text = ar if lang == 'ar' else en
    try:
        return text.format(**fmt)
    except (KeyError, IndexError):
        return text


def _finding(code, weight, severity='medium', **fmt):
    ar, en = TEXTS[code]
    return {'code': code, 'weight': weight, 'severity': severity,
            'ar': ar.format(**fmt) if fmt else ar,
            'en': en.format(**fmt) if fmt else en}


# --------------------------------------------------------------------------
# شبكة آمنة (SSRF)
# --------------------------------------------------------------------------
def is_public_host(hostname):
    """True = عنوان عام، False = عنوان داخلي/خاص (ممنوع)، None = مش موجود"""
    host = (hostname or '').strip().strip('[]')
    if not host:
        return None
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    if not infos:
        return None
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split('%')[0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


def safe_fetch(url, timeout=HTTP_TIMEOUT, max_redirects=5, headers=None):
    """يفتح الرابط ويتبع التحويلات يدوياً مع فحص كل عنوان (حماية SSRF).

    ملاحظة: فيه TOCTOU محتمل (DNS rebinding) بين الفحص والطلب — مقبول للمرحلة 1.
    """
    hops = [url]
    current = url
    for _ in range(max_redirects + 1):
        parts = urlsplit(current)
        if parts.scheme not in ('http', 'https'):
            raise UnreachableURL()
        public = is_public_host(parts.hostname)
        if public is None:
            raise UnreachableURL()
        if public is False:
            raise BlockedURL()
        resp = requests.get(current, timeout=timeout, allow_redirects=False,
                            headers=headers or {'User-Agent': USER_AGENT}, stream=True)
        if resp.is_redirect:
            location = resp.headers.get('Location', '')
            resp.close()
            if not location:
                raise UnreachableURL()
            current = urljoin(current, location)
            hops.append(current)
            continue
        resp.close()
        return resp, hops
    raise UnreachableURL()


# --------------------------------------------------------------------------
# الفحوصات المحلية
# --------------------------------------------------------------------------
def _registrable(host):
    host = (host or '').lower().rstrip('.')
    for tld in TWO_LEVEL_TLDS:
        if host.endswith(tld):
            base = host[:-len(tld)]
            if '.' in base:
                return base.rsplit('.', 1)[-1] + tld
            return host
    labels = host.split('.')
    return '.'.join(labels[-2:]) if len(labels) >= 2 else host


def heuristic_checks(url):
    """فحوصات محلية بحتة — بترجّع قائمة findings مرتبة حسب الخطورة"""
    findings = []
    raw = (url or '').strip()
    if not raw:
        return findings
    candidate = raw if '://' in raw else 'https://' + raw
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return findings
    host = (parts.hostname or '').lower()
    path = (parts.path or '').lower()
    netloc = parts.netloc or ''

    # 1) عنوان IP
    try:
        ipaddress.ip_address(host.strip('[]'))
        findings.append(_finding('ip_host', 20, 'high'))
    except ValueError:
        pass

    # 2) HTTPS
    if parts.scheme != 'https':
        findings.append(_finding('no_https', 10, 'medium'))

    # 3) @
    if '@' in raw:
        findings.append(_finding('at_sign', 15, 'high'))

    # 4) punycode
    if host.startswith('xn--') or '.xn--' in host:
        findings.append(_finding('punycode', 25, 'high'))

    # 5) TLD مشبوه
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            findings.append(_finding('suspicious_tld', 20, 'high', tld=tld))
            break

    # 6) نقاط/نطاقات فرعية كتير
    dots = host.count('.')
    if dots >= 6:
        findings.append(_finding('many_dots', 18, 'high'))
    elif dots >= 4:
        findings.append(_finding('many_dots', 10, 'medium'))

    # 7) كلمات تصيد
    haystack = host + path + '?' + (parts.query or '').lower()
    for word in PHISH_KEYWORDS:
        if word in haystack:
            findings.append(_finding('phish_keywords', 15, 'medium', word=word))
            break

    # 8) انتحال علامة تجارية
    for brand, legit in BRANDS.items():
        if brand in host and _registrable(host) not in legit:
            findings.append(_finding('brand', 25, 'high', brand=brand))
            break

    # 9) بورت غير معتاد
    if parts.port and parts.port not in (80, 443):
        findings.append(_finding('port', 15, 'medium', port=parts.port))

    # 10) طول الرابط
    if len(raw) > 400:
        findings.append(_finding('long_url', 20, 'high'))
    elif len(raw) > 200:
        findings.append(_finding('long_url', 10, 'medium'))

    # 11) ترميز/تشفير مشبوه
    if '%00' in raw.lower() or '%2e' in raw.lower() or raw.count('%') >= 8:
        findings.append(_finding('obfuscated', 20, 'high'))
    elif re.search(r'(?:0x[0-9a-f]{6,}|\\x[0-9a-f]{2})', raw.lower()):
        findings.append(_finding('obfuscated', 15, 'medium'))

    # 12) ملف تنفيذي
    for ext in DANGEROUS_EXTENSIONS:
        if path.endswith(ext) or ext + '?' in path:
            findings.append(_finding('dangerous_file', 25, 'high', ext=ext))
            break

    # 13) مختصر روابط
    if _registrable(host) in SHORTENERS:
        findings.append(_finding('shortener', 10, 'low'))

    # 14) باراميتر تحويل
    try:
        query = parse_qs(parts.query)
    except ValueError:
        query = {}
    for name, values in query.items():
        if name.lower() in REDIRECT_PARAMS and any('http' in str(v).lower() or '//' in str(v)
                                                   for v in values):
            findings.append(_finding('redirect_param', 15, 'medium', param=name))
            break

    # 15) بيانات دخول داخل الرابط
    if parts.username or parts.password:
        findings.append(_finding('credentials', 20, 'high'))

    findings.sort(key=lambda f: f['weight'], reverse=True)
    return findings


# --------------------------------------------------------------------------
# طبقات خارجية (اختيارية)
# --------------------------------------------------------------------------
def _cfg(config, key, env_name, default=None):
    if config is None:
        return default
    if isinstance(config, dict):
        return config.get(key, default)
    return getattr(config, key, default)


def _key(config, cfg_name, env_name):
    value = _cfg(config, cfg_name, env_name, '') or ''
    return str(value).strip()


def gsb_check(url, key, timeout=HTTP_TIMEOUT):
    if not key:
        return 'disabled', 0
    body = {
        'client': {'clientId': 'safeguard', 'clientVersion': '2.0.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}],
        },
    }
    try:
        resp = requests.post(
            'https://safebrowsing.googleapis.com/v4/threatMatches:find',
            params={'key': key}, json=body, timeout=timeout)
        if resp.status_code != 200:
            return 'error', 0
        return ('hit' if (resp.json() or {}).get('matches') else 'clean'), 0
    except (requests.exceptions.RequestException, ValueError):
        return 'error', 0


def urlhaus_check(url, timeout=HTTP_TIMEOUT):
    try:
        resp = requests.post('https://urlhaus-api.abuse.ch/v1/url/',
                             data={'url': url}, timeout=timeout,
                             headers={'User-Agent': USER_AGENT})
        if resp.status_code != 200:
            return 'error', 0
        payload = resp.json()
        if payload.get('query_status') == 'ok' and payload.get('url_status') == 'online':
            return 'hit', 0
        return 'clean', 0
    except (requests.exceptions.RequestException, ValueError):
        return 'error', 0


def _vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii').rstrip('=')


def virustotal_check(url, key, timeout=HTTP_TIMEOUT):
    if not key:
        return 'disabled', 0
    try:
        resp = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{_vt_url_id(url)}',
            headers={'x-apikey': key, 'User-Agent': USER_AGENT}, timeout=timeout)
        if resp.status_code in (401, 403):
            return 'error', 0
        if resp.status_code == 404:
            return 'clean', 0
        if resp.status_code != 200:
            return 'error', 0
        stats = (((resp.json() or {}).get('data') or {}).get('attributes') or {}) \
            .get('last_analysis_stats') or {}
        malicious = int(stats.get('malicious') or 0)
        suspicious = int(stats.get('suspicious') or 0)
        total = malicious + suspicious
        return ('hit' if malicious >= 1 else 'clean'), malicious
    except (requests.exceptions.RequestException, ValueError, TypeError):
        return 'error', 0


# --------------------------------------------------------------------------
# كاش بسيط
# --------------------------------------------------------------------------
_CACHE = {}
_CACHE_TTL = 300
_CACHE_MAX = 500


def _cache_get(key):
    item = _CACHE.get(key)
    if not item:
        return None
    created, value = item
    if time.time() - created > _CACHE_TTL:
        _CACHE.pop(key, None)
        return None
    return value


def _cache_set(key, value):
    if len(_CACHE) >= _CACHE_MAX:
        oldest = sorted(_CACHE.items(), key=lambda kv: kv[1][0])[:len(_CACHE) // 4]
        for name, _ in oldest:
            _CACHE.pop(name, None)
    _CACHE[key] = (time.time(), value)


def clear_cache():
    _CACHE.clear()


# --------------------------------------------------------------------------
# الدالة الأساسية
# --------------------------------------------------------------------------
def _level_for(score):
    if score >= 70:
        return 'critical'
    if score >= 45:
        return 'high'
    if score >= 20:
        return 'medium'
    return 'safe'


def _empty_result(raw, lang, score=0):
    return {
        'url': raw, 'final_url': raw, 'safe': False, 'level': _level_for(score),
        'score': score, 'msg': _txt('safe', lang), 'warnings': [], 'findings': [],
        'sources': {'google': {'status': 'skipped'}, 'urlhaus': {'status': 'skipped'},
                    'virustotal': {'status': 'skipped'}},
        'http': {'reachable': False, 'status_code': None, 'redirects': []},
        'blocked': False, 'cached': False, 'duration_ms': 0,
        'checked_at': datetime.now(timezone.utc).isoformat(),
    }


def scan_url(url, timeout=HTTP_TIMEOUT, max_redirects=5, scan_type='normal',
             lang='ar', external=True, config=None):
    """فحص رابط وإرجاع نتيجة كاملة. لا يرفع استثناء أبداً."""
    started = time.monotonic()
    raw = (url or '').strip()
    lang = 'en' if str(lang).lower().startswith('en') else 'ar'
    cache_key = (raw.lower(), scan_type, lang, bool(external))
    cached = _cache_get(cache_key)
    if cached is not None:
        result = dict(cached)
        result['cached'] = True
        result['duration_ms'] = int((time.monotonic() - started) * 1000)
        return result

    if not raw:
        return _empty_result(raw, lang)

    target = raw if raw.startswith(('http://', 'https://')) else 'https://' + raw
    if len(target) > 2000:
        result = _empty_result(raw, lang, 30)
        result['warnings'] = [_txt('obfuscated', lang)]
        result['findings'] = [_finding('obfuscated', 30, 'high')]
        result['msg'] = _txt('risky', lang, reasons=result['warnings'][0])
        return result

    findings = heuristic_checks(target)
    sources = {'google': {'status': 'skipped'}, 'urlhaus': {'status': 'skipped'},
               'virustotal': {'status': 'skipped'}}
    http_info = {'reachable': None, 'status_code': None, 'redirects': [target]}
    blocked = False
    reached = False
    score = sum(f['weight'] for f in findings)

    if external:
        try:
            resp, hops = safe_fetch(target, timeout=timeout, max_redirects=max_redirects,
                                    headers={'User-Agent': str(_cfg(config, 'user_agent', '', USER_AGENT))})
            reached = True
            http_info = {'reachable': True, 'status_code': resp.status_code, 'redirects': hops}
            if len(hops) > 1 and (urlsplit(hops[0]).hostname or '') != (urlsplit(hops[-1]).hostname or ''):
                findings.append(_finding('redirect_cross', 15, 'medium',
                                         host=urlsplit(hops[-1]).hostname))
            if resp.status_code >= 400:
                findings.append(_finding('http_error', 25, 'high', code=resp.status_code))
        except BlockedURL:
            blocked = True
            findings.append(_finding('blocked', 65, 'critical'))
        except (UnreachableURL, requests.exceptions.RequestException):
            findings.append(_finding('unreachable', 25, 'medium'))
        except Exception:                      # أي خطأ غير متوقع ما يوقعش الطلب
            findings.append(_finding('unreachable', 25, 'medium'))

        if not blocked:
            if scan_type == 'quick':
                vhost = urlsplit(target).netloc
                sources['google'] = {'status': 'skipped'}
                sources['urlhaus'] = {'status': 'skipped'}
                sources['virustotal'] = {'status': 'skipped'}
            else:
                key = _key(config, 'gsb_key', 'GOOGLE_SAFE_BROWSING_KEY')
                status, _ = gsb_check(target, key, timeout=min(timeout, HTTP_TIMEOUT))
                sources['google'] = {'status': status}
                if status == 'hit':
                    score += 60
                    findings.append(_finding('gsb', 60, 'critical'))
                else:
                    if _cfg(config, 'urlhaus', 'SF_URLHAUS_ENABLED', True):
                        status, _ = urlhaus_check(target, timeout=min(timeout, HTTP_TIMEOUT))
                    else:
                        status = 'disabled'
                    sources['urlhaus'] = {'status': status}
                    if status == 'hit':
                        score += 55
                        findings.append(_finding('urlhaus', 55, 'critical'))
                    else:
                        key = _key(config, 'vt_key', 'VIRUSTOTAL_API_KEY')
                        status, malicious = virustotal_check(target, key,
                                                             timeout=min(timeout, HTTP_TIMEOUT))
                        sources['virustotal'] = {'status': status,
                                                 'malicious': malicious}
                        if status == 'hit':
                            score += 40 if malicious >= 5 else 25
                            findings.append(_finding('vt', 40 if malicious >= 5 else 25,
                                                     'high', n=malicious))

    score = max(0, min(100, score))
    level = _level_for(score)
    blocked_hit = any(f['code'] == 'blocked' for f in findings)
    external_hit = any(s.get('status') == 'hit' for s in sources.values())
    http_ok = (http_info['status_code'] is not None and http_info['status_code'] < 400) \
        if external else True
    safe = (level == 'safe' and not blocked_hit and not external_hit and http_ok)

    warnings = [f['ar' if lang == 'ar' else 'en'] for f in findings[:6]]
    if blocked_hit:
        msg = _txt('blocked', lang)
    elif not external:
        msg = _txt('safe', lang) if not warnings else _txt('risky', lang, reasons=' • '.join(warnings[:3]))
    elif not reached and external:
        msg = _txt('unreachable', lang)
    elif http_info['status_code'] is not None and http_info['status_code'] >= 400:
        msg = _txt('http_error', lang, code=http_info['status_code'])
    elif safe:
        msg = _txt('safe', lang)
    else:
        msg = _txt('risky', lang, reasons=' • '.join(warnings[:3]) or _txt('safe', lang))

    result = {
        'url': raw,
        'final_url': http_info['redirects'][-1] if http_info['redirects'] else target,
        'safe': bool(safe), 'level': level, 'score': score, 'msg': msg,
        'warnings': warnings,
        'findings': findings,
        'sources': sources,
        'http': http_info,
        'blocked': blocked_hit,
        'cached': False,
        'duration_ms': int((time.monotonic() - started) * 1000),
        'checked_at': datetime.now(timezone.utc).isoformat(),
    }
    if reached or blocked_hit:
        _cache_set(cache_key, {k: v for k, v in result.items() if k != 'cached'})
    return result
