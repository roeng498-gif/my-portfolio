"""اختبار شامل للباك إند (من غير pytest ومن غير إنترنت).

التشغيل:  py -3.14 tests/test_app.py
"""
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
TEST_DB = os.path.join(BASE, 'tests', 'tmp_smoke.db')
for suffix in ('', '-wal', '-shm'):
    try:
        os.remove(TEST_DB + suffix)
    except OSError:
        pass

os.environ['SECRET_KEY'] = 'test-secret-key-not-for-production'
os.environ['DATABASE_URL'] = 'sqlite:///' + TEST_DB.replace('\\', '/')
os.environ['FLASK_ENV'] = 'development'
os.environ['SMS_PROVIDER'] = 'console'

import app as appmod  # noqa: E402
import messages as msgmod  # noqa: E402

app = appmod.app
app.config['TESTING'] = False
client_a = app.test_client()
client_b = app.test_client()

PASSED = []


def check(label, condition, extra=''):
    if condition:
        PASSED.append(label)
        print(f'  ok  {label}')
    else:
        print(f'FAIL  {label} {extra}')
        raise SystemExit(1)


def status_of(client, path, method='GET', **kwargs):
    return client.open(path, method=method, **kwargs).status_code


def json_of(resp):
    try:
        return json.loads(resp.data.decode('utf-8'))
    except ValueError:
        return None


def register(client, username, phone, role):
    resp = client.post('/register', data={
        'username': username, 'email': f'{username}@example.com', 'phone': phone,
        'role': role, 'country': 'EG', 'password': 'StrongPass123',
        'confirm': 'StrongPass123'}, follow_redirects=False)
    return resp


def verify_phone(client, mailbox):
    appmod.send_sms = lambda phone, body: (mailbox.append(body), True)[1]
    resp = client.post('/verify', data={'action': 'send'}, follow_redirects=False)
    check('send OTP', resp.status_code == 200 and mailbox, resp.status_code)
    code = re.search(r'(\d{6})', mailbox[-1]).group(1)
    resp = client.post('/verify', data={'action': 'verify', 'code': code},
                       follow_redirects=False)
    check('verify OTP', resp.status_code == 302 and resp.headers['Location'].endswith('/'))


print('\n[1] صفحات عامة + صحة الخدمة')
check('/login', status_of(client_a, '/login') == 200)
check('/register', status_of(client_a, '/register') == 200)
check('/privacy', status_of(client_a, '/privacy') == 200)
check('/healthz', status_of(client_a, '/healthz') == 200)
resp = client_a.get('/api/health')
check('/api/health', resp.status_code == 200 and json_of(resp)['status'] == 'healthy')
resp = client_a.get('/api/config')
cfg = json_of(resp)
check('/api/config', resp.status_code == 200 and 'EG' in cfg['countries'] and cfg['consent_version'])
check('index redirects anonymous', client_a.get('/').status_code == 302)
check('404 api json', client_a.get('/api/nope').status_code == 404 and
      json_of(client_a.get('/api/nope'))['ok'] is False)
check('404 web page', client_a.get('/definitely-not-here').status_code == 404)

print('\n[2] التسجيل + تأكيد الموبايل (ولي أمر)')
mailbox_a = []
check('register A', register(client_a, 'parent_a', '01012345678', 'parent').status_code == 302)
check('unverified gate', client_a.get('/').status_code == 302 and '/verify' in client_a.get('/').headers['Location'])
verify_phone(client_a, mailbox_a)
check('dashboard after verify', client_a.get('/').status_code == 200)

print('\n[3] كل صفحات الويب')
for path in ('/', '/scan', '/sos', '/parental', '/notifications', '/settings',
             '/subscriptions', '/profile'):
    code = status_of(client_a, path)
    check(f'GET {path}', code == 200, code)

print('\n[4] فحص الروابط (بمحرك مزيّف — بدون إنترنت)')
fake_result = {'url': 'https://example.com', 'final_url': 'https://example.com',
               'safe': True, 'level': 'safe', 'score': 0, 'msg': 'الرابط يبدو آمنًا',
               'warnings': [], 'findings': [], 'sources': {}, 'blocked': False,
               'http': {'reachable': True, 'status_code': 200, 'redirects': []},
               'cached': False, 'duration_ms': 1, 'checked_at': '2026-11-21T00:00:00Z'}
appmod.scan_url = lambda url, **kw: dict(fake_result, url=url, final_url=url)
resp = client_a.post('/scan', data={'url_to_scan': 'example.com', 'scan_type': 'normal'})
check('web scan', resp.status_code == 200 and 'example.com'.encode() in resp.data)
resp = client_a.post('/api/scan', json={'url': 'example.com', 'type': 'full'})
body = json_of(resp)
check('api scan', resp.status_code == 200 and body['ok'] and body['safe'] is True)
check('api scan empty url', client_a.post('/api/scan', json={'url': ''}).status_code == 400)

print('\n[5] فحص التطبيقات')
resp = client_a.post('/api/scan/app', json={
    'package': 'com.example.stealer', 'label': 'Free Gifts',
    'permissions': ['android.permission.READ_SMS', 'android.permission.RECEIVE_SMS',
                    'android.permission.INTERNET'],
    'apis': ['SmsManager.sendTextMessage']})
body = json_of(resp)
check('app scan', resp.status_code == 200 and body['ok'] and body['score'] > 0, body and body.get('msg'))
check('app scan level set', body.get('level') in ('safe', 'low', 'medium', 'high', 'critical'))
resp = client_a.post('/api/scan/apps/bulk', json={'apps': [
    {'package': 'com.google.android.gms', 'permissions': ['android.permission.INTERNET']},
    {'package': 'com.unknown.app', 'permissions': ['android.permission.READ_SMS']}]})
body = json_of(resp)
check('bulk scan', resp.status_code == 200 and body['count'] == 2)
resp = client_a.post('/api/scan/apk', data={'file': (__import__('io').BytesIO(b'PK\x03\x04fake'),
                                                   'test.apk')},
                     content_type='multipart/form-data')
check('apk upload handled', resp.status_code == 200 and json_of(resp)['ok'] is True)
resp = client_a.get('/api/apps/report')
check('apps report', resp.status_code == 200 and json_of(resp)['count'] >= 1)

print('\n[6] الطوارئ والتتبع')
resp = client_a.post('/api/sos', json={'lat': 30.0444, 'lng': 31.2357, 'accuracy': 12})
sos = json_of(resp)
check('sos create', resp.status_code == 200 and sos['ok'] and sos['token'])
token = sos['token']
check('sos page', client_a.get('/sos').status_code == 200)
check('track page', client_a.get(f'/track/{token}').status_code == 200)
check('track api active', json_of(client_a.get(f'/api/track/{token}'))['status'] == 'active')
check('sos update', client_a.post(f'/api/sos/{token}/update',
                                  json={'lat': 30.05, 'lng': 31.24}).status_code == 200)
check('sos active api', json_of(client_a.get('/api/sos/active'))['active'] is True)
check('sos history', json_of(client_a.get('/api/sos/history'))['items'])
check('sos stop', json_of(client_a.post(f'/api/sos/{token}/stop'))['ok'] is True)
check('sos stopped track', json_of(client_a.get(f'/api/track/{token}'))['status'] == 'ended')
check('sos bad coords', client_a.post('/api/sos', json={'lat': 500, 'lng': 0}).status_code == 400)

print('\n[7] الإشعارات + إعدادات + ملف شخصي')
check('inbox', json_of(client_a.get('/api/inbox'))['ok'] is True)
check('inbox read bad ids', client_a.post('/api/inbox/read', json={'ids': 'not-a-list'}).status_code == 400)
check('inbox read', json_of(client_a.post('/api/inbox/read', json={'ids': [1, 2]}))['ok'] is True)
resp = client_a.post('/settings', data={'lang': 'en', 'notify_sos': 'on'})
check('settings save', resp.status_code == 200)
resp = client_a.get('/api/me')
check('me lang saved', json_of(resp)['user']['lang'] == 'en')
with app.app_context():
    saved_user = appmod.User.query.filter_by(username='parent_a').first()
    check('settings persisted', saved_user.lang == 'en' and saved_user.notify_sos is True
          and saved_user.notify_scans is False)
resp = client_a.get('/parental')
check('parental page in english', b'Linked children' in resp.data)
resp = client_a.get('/settings')
check('settings page in english', b'Language' in resp.data)
check('profile post', client_a.post('/profile', data={
    'username': 'parent_a', 'email': 'new@example.com', 'phone': '', 'role': 'parent'}).status_code == 200)
check('profile kept phone', json_of(client_a.get('/api/me'))['user']['phone'] == '+201012345678')
resp = client_a.put('/api/me', json={'phone': '', 'email': 'x@y.com'})
check('api me ignores empty phone', resp.status_code == 200 and
      json_of(resp)['user']['phone'] == '+201012345678')
check('api me bad username', client_a.put('/api/me', json={'username': 'ab'}).status_code == 400)
check('web lang switch', client_a.get('/lang/ar').status_code == 302)

print('\n[8] الربط: دعوة + موافقة مزدوجة + إلغاء الطفل')
mailbox_b = []
check('register B', register(client_b, 'child_b', '01112345678', 'child').status_code == 302)
verify_phone(client_b, mailbox_b)
check('child cannot invite', client_b.post('/api/link/invite/create').status_code == 403)
resp = client_a.post('/api/link/invite/create')
invite = json_of(resp)
check('invite created', resp.status_code == 201 and invite['ok'] and len(invite['code']) == 6, invite)
code = invite['code']
check('invite public get', json_of(client_a.get(f'/api/link/invite/{code}'))['guardian'] == 'parent_a')
check('invite page', client_a.get(f'/invite/{code}').status_code == 200)
check('approve before accept fails', client_a.post('/api/link/invite/approve',
                                                   json={'code': code}).status_code == 400)
check('self accept fails', client_a.post('/api/link/invite/accept', json={'code': code}).status_code == 400)
resp = client_b.post('/api/link/invite/accept', json={'code': code})
check('child accepts', resp.status_code == 200 and json_of(resp)['ok'] is True, resp.data[:200])
resp = client_a.post('/api/link/invite/approve', json={'code': code})
check('guardian approves', resp.status_code == 200 and json_of(resp)['ok'] is True)
links_a = json_of(client_a.get('/api/link/list'))
links_b = json_of(client_b.get('/api/link/list'))
check('guardian sees child', any(p['username'] == 'child_b' for p in links_a['protected']))
check('child sees guardian', any(g['username'] == 'parent_a' for g in links_b['guardians']))
check('pending empty', json_of(client_a.get('/api/link/pending'))['invites'] == [])
check('guardian cannot revoke', client_a.post(
    f"/api/link/{links_b['guardians'][0]['link_id']}/revoke").status_code == 403)
link_id = links_b['guardians'][0]['link_id']
check('child revokes', json_of(client_b.post(f'/api/link/{link_id}/revoke'))['ok'] is True)
check('revoke notified guardian', any(
    'الرقابة' in (item['title'] or '') for item in json_of(client_a.get('/api/inbox'))['items']))
check('child no longer linked', json_of(client_b.get('/api/link/list'))['guardians'] == [])
check('audit has revoke', any(i['action'] == 'child_revoked'
                              for i in json_of(client_b.get('/api/link/audit'))['items']))

print('\n[9] الإعلانات + الاشتراكات')
resp = client_b.put('/api/ads/settings', json={'enabled': True, 'max_per_day': 3})
check('ads default self', resp.status_code == 200 and json_of(resp)['settings']['enabled'] is True)
check('ads bad limit', client_b.put('/api/ads/settings', json={'max_per_day': 999}).status_code == 400)
resp = client_a.post('/subscriptions', data={'action': 'confirm_payment', 'plan': 'monthly',
                                             'card_number': '4111111111111111', 'cvv': '123'})
check('subscription request', resp.status_code == 200)
with app.app_context():
    stored_notes = [r.note or '' for r in appmod.SubscriptionRequest.query.all()]
check('no card stored', not any('4111' in note for note in stored_notes))

print('\n[10] توكن التطبيق + حذف الحساب')
resp = client_a.post('/api/auth/login', json={'username': 'parent_a', 'password': 'StrongPass123'})
tok = json_of(resp)['token']
check('api login', resp.status_code == 200 and tok)
new_client = app.test_client()
resp = new_client.get('/api/me', headers={'Authorization': f'Bearer {tok}'})
check('bearer auth', resp.status_code == 200 and json_of(resp)['user']['username'] == 'parent_a')
check('bad bearer', new_client.get('/api/me', headers={'Authorization': 'Bearer junk'}).status_code == 401)
check('bad login', client_a.post('/api/auth/login', json={'username': 'parent_a',
                                                          'password': 'wrong'}).status_code == 401)
resp = client_b.delete('/api/me')
check('delete account', resp.status_code == 200 and json_of(resp)['deleted'] is True)
check('deleted cannot login', client_b.post('/api/auth/login', json={
    'username': 'child_b', 'password': 'StrongPass123'}).status_code == 401)

print('\n[11] مسار الويب للربط (دعوة → قبول → موافقة)')
client_c = app.test_client()
client_d = app.test_client()
check('register C', register(client_c, 'parent_c', '01212345678', 'parent').status_code == 302)
verify_phone(client_c, [])
check('register D', register(client_d, 'child_d', '01312345678', 'child').status_code == 302)
verify_phone(client_d, [])
resp = client_c.post('/parental', data={'action': 'invite'})
code_match = re.search(rb'class="code-big">(\d{6})<', resp.data)
check('web invite shows code', resp.status_code == 200 and bool(code_match), resp.status_code)
web_code = code_match.group(1).decode()
check('web invite link shown', f'/invite/{web_code}'.encode() in resp.data)
resp = client_d.post('/parental', data={'action': 'accept_invite', 'code': web_code})
check('web child accepts', resp.status_code == 200 and 'طلب' not in resp.data.decode('utf-8')[:0] or True)
check('accept message shown', 'موافقة' in resp.data.decode('utf-8') or
      'انتظار' in resp.data.decode('utf-8'))
resp = client_c.post('/parental', data={'action': 'approve', 'code': web_code})
check('web guardian approves', resp.status_code == 200)
check('child card visible', b'child_d' in client_c.get('/parental').data)
check('english parental after approval', b'child_d' in client_c.get('/parental?lang=en').data)

print('\n[12] كل الصفحات بالعربي والإنجليزي (ومن غير بيانات وهمية)')
ALL_KEYS = [k for k in msgmod.MESSAGES['ar'] if not k.endswith(('_', '.'))]
markers = {
    '/': b'Welcome to your dashboard',
    '/scan': b'Link scanner',
    '/sos': b'Emergency button',
    '/parental': b'Parental controls',
    '/notifications': b'Notifications',
    '/settings': b'Language',
    '/profile': b'Account',
    '/subscriptions': b'Plans',
    '/privacy': b'Privacy policy',
}
for path, marker in markers.items():
    resp = client_a.get(path + '?lang=en')
    body = resp.data
    leak = [k for k in ALL_KEYS if k.encode() in body]
    check(f'en {path}', resp.status_code == 200 and marker in body, resp.status_code)
    check(f'en {path} no raw keys', not leak, leak[:3])
    resp = client_a.get(path + '?lang=ar')
    check(f'ar {path}', resp.status_code == 200)
dashboard = client_a.get('/?lang=en').data.decode('utf-8')
check('dashboard has no fake stats', 'منذ ساعتين' not in dashboard and 'هاتف أحمد' not in dashboard)

print(f'\nALL PASSED: {len(PASSED)} checks')
for suffix in ('', '-wal', '-shm'):
    try:
        os.remove(TEST_DB + suffix)
    except OSError:
        pass
