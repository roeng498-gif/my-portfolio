"""اختبارات محرك فحص الروابط — كلها بدون إنترنت.

التشغيل:  py -3.14 tests/test_url_scanner.py
"""
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import url_scanner as us  # noqa: E402

PASSED = []


def check(label, condition, extra=''):
    if condition:
        PASSED.append(label)
        print(f'  ok  {label}')
    else:
        print(f'FAIL  {label} {extra}')
        raise SystemExit(1)


def codes(findings):
    return {f['code'] for f in findings}


print('\n[1] فحوصات محلية')
check('ip host', 'ip_host' in codes(us.heuristic_checks('http://192.168.1.1/login')))
check('no https', 'no_https' in codes(us.heuristic_checks('http://example.com/')))
check('at sign', 'at_sign' in codes(us.heuristic_checks('https://user@evil.example/')))
check('punycode', 'punycode' in codes(us.heuristic_checks('https://xn--80ak6aa92e.com/')))
check('suspicious tld', 'suspicious_tld' in codes(us.heuristic_checks('https://free-gift.tk/')))
check('brand impersonation',
      'brand' in codes(us.heuristic_checks('https://paypal-secure.tk/login')))
check('legit brand is fine', 'brand' not in codes(us.heuristic_checks('https://www.paypal.com/signin')))
check('shortener', 'shortener' in codes(us.heuristic_checks('https://bit.ly/abc123')))
check('dangerous file', 'dangerous_file' in codes(us.heuristic_checks('https://x.example/a.apk')))
check('long url', 'long_url' in codes(us.heuristic_checks('https://example.com/' + 'a' * 260)))
check('phishing keyword', 'phish_keywords' in codes(us.heuristic_checks('https://example.com/verify-account')))
check('obfuscation', 'obfuscated' in codes(us.heuristic_checks('https://example.com/%2e%2e%00x')))
check('redirect param',
      'redirect_param' in codes(us.heuristic_checks('https://example.com/?url=https%3A%2F%2Fevil.tk')))
check('non-standard port', 'port' in codes(us.heuristic_checks('https://example.com:8443/')))
check('credentials', 'credentials' in codes(us.heuristic_checks('https://a:b@example.com/')))
check('clean url has no findings', not us.heuristic_checks('https://example.com/about'))
check('garbage never raises', isinstance(us.heuristic_checks(None), list) and
      isinstance(us.heuristic_checks('not a url at all'), list) and
      isinstance(us.heuristic_checks('http://'), list))

print('\n[2] حماية SSRF')
check('127.0.0.1 blocked', us.is_public_host('127.0.0.1') is False)
check('10.0.0.1 blocked', us.is_public_host('10.0.0.1') is False)
check('localhost blocked', us.is_public_host('localhost') is False)
check('169.254 metadata blocked', us.is_public_host('169.254.169.254') is False)
check('ipv6 loopback blocked', us.is_public_host('[::1]') is False)
check('unknown host is None', us.is_public_host('this-host-does-not-exist.invalid') is None)
try:
    us.safe_fetch('http://127.0.0.1:8080/admin')
    check('safe_fetch refuses loopback', False)
except us.BlockedURL:
    check('safe_fetch refuses loopback', True)

print('\n[3] scan_url بدون إنترنت')
for target in ('http://127.0.0.1/', 'http://169.254.169.254/latest'):
    result = us.scan_url(target, external=True)
    check(f'blocked result {target}', result['blocked'] is True and result['safe'] is False)
check('blocked msg is localised', 'داخلي' in us.scan_url('http://127.0.0.1/', external=True)['msg'])
result = us.scan_url('https://example.com/', external=False, lang='en')
check('offline scan safe', result['safe'] is True and result['level'] == 'safe', result)
check('offline sources skipped', all(s['status'] in ('skipped', 'disabled')
                                     for s in result['sources'].values()))
result = us.scan_url('https://paypal-verify.tk/login', external=False, lang='ar')
check('offline risky scan', result['safe'] is False and result['score'] >= 20, result['score'])
check('risky has warnings', result['warnings'] and isinstance(result['warnings'][0], str))
check('risky msg mentions reasons', 'تنبيه' in result['msg'])
check('levels ordered', us._level_for(0) == 'safe' and us._level_for(20) == 'medium' and
      us._level_for(45) == 'high' and us._level_for(70) == 'critical')
check('empty url no crash', us.scan_url('', external=False)['score'] == 0)
check('none url no crash', us.scan_url(None, external=False)['safe'] is False)
check('huge url no crash', us.scan_url('https://x.example/' + 'a' * 5000)['score'] > 0)

print('\n[4] الكاش')
us.clear_cache()
a = us.scan_url('http://10.1.2.3/', external=True)
b = us.scan_url('http://10.1.2.3/', external=True)
check('cache hit', b['cached'] is True)
check('blocked cached too', a['blocked'] and b['blocked'])

print('\n[5] الرسائل بالعربي والإنجليزي')
ar = us.scan_url('https://free-gift.tk/login', external=False, lang='ar')
en = us.scan_url('https://free-gift.tk/login', external=False, lang='en')
check('arabic text', any('نطاق' in w or 'كلمات' in w or 'الرابط' in w for w in ar['warnings']))
check('english text', any('domain' in w.lower() or 'link' in w.lower() for w in en['warnings']))
check('different languages', ar['warnings'] != en['warnings'])

print(f'\nALL PASSED: {len(PASSED)} checks')
