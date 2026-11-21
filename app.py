"""SafeGuard — باك إند Flask كامل.

المسؤوليات:
  * حسابات + تأكيد موبايل (OTP)
  * فحص روابط متعدد الطبقات + فحص تطبيقات (بيانات / APK)
  * زر الطوارئ وتتبع الموقع
  * ربط ولي الأمر بالطفل (دعوات + موافقة مزدوجة + حق الطفل في الإلغاء)
  * تحكم الإعلانات، إشعارات داخل التطبيق، FCM اختياري
  * API للتطبيق (Bearer token) + واجهة ويب (جلسة)
"""
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import timedelta
from functools import wraps

import requests
from flask import (Flask, g, jsonify, redirect, render_template, request,
                   session, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import event, inspect, text
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import link_service as links
from app_scanner import scan_apk, scan_app as analyze_app
from config import get_config
from messages import normalize_lang, resolve_lang, t
from models import (AdSettings, AppReport, AppScan, AuditLog, DeviceToken,
                    GuardianConsent, Link, LinkInvite, Notification, PairCode,
                    PairFail, PhoneCode, RateHit, SOSEvent, ScanLog, SmsLog,
                    SubscriptionRequest, User, db, now_utc)
from url_scanner import BlockedURL, UnreachableURL, safe_fetch, scan_url

app = Flask(__name__)
app.config.from_object(get_config())
db.init_app(app)

# الدول المدعومة: الكود -> (الاسم العربي، مفتاح الاتصال، رقم الشرطة، الاسم الإنجليزي)
COUNTRIES = {
    'EG': ('مصر', '20', '122', 'Egypt'),
    'KW': ('الكويت', '965', '112', 'Kuwait'),
    'JO': ('الأردن', '962', '911', 'Jordan'),
    'AE': ('الإمارات', '971', '999', 'UAE'),
    'QA': ('قطر', '974', '999', 'Qatar'),
    'SA': ('السعودية', '966', '999', 'Saudi Arabia'),
}

TOKEN_MAX_AGE = 60 * 60 * 24 * 30          # صلاحية توكن التطبيق: 30 يوم
UNVERIFIED_OK = {'verify', 'logout', 'profile', 'api_me', 'api_phone_send',
                 'api_phone_verify', 'api_health', 'api_config', 'set_lang'}

PLAN_INFO = {
    'free': {'ar': 'المجانية', 'en': 'Free', 'monthly': 0, 'yearly': 0,
             'features_ar': ['فحص روابط أساسي', 'نجدة SOS', 'ربط شخصين'],
             'features_en': ['Basic link scanning', 'SOS alerts', 'Link 2 people']},
    'monthly': {'ar': 'الشهرية', 'en': 'Monthly', 'monthly': 49, 'yearly': 0,
                'features_ar': ['فحص روابط كامل', 'فحص تطبيقات', 'حتى 5 أطفال', 'إشعارات فورية'],
                'features_en': ['Full link scanning', 'App scanning', 'Up to 5 children', 'Push alerts']},
    'yearly': {'ar': 'السنوية', 'en': 'Yearly', 'monthly': 0, 'yearly': 399,
               'features_ar': ['كل مميزات الشهرية', 'توفير 4 شهور', 'أولوية الدعم'],
               'features_en': ['Everything in Monthly', '4 months free', 'Priority support']},
    'family': {'ar': 'العائلة', 'en': 'Family', 'monthly': 79, 'yearly': 699,
               'features_ar': ['كل المميزات', 'حتى 10 أطفال', 'تحكم كامل في الإعلانات', 'تقارير أسبوعية'],
               'features_en': ['All features', 'Up to 10 children', 'Full ad controls', 'Weekly reports']},
}


# ==========================================================================
# أدوات عامة
# ==========================================================================
def now_utc_iso():
    return now_utc().isoformat() + 'Z'


def time_ago(dt, lang=None):
    """يحوّل الوقت لنص بسيط بلغة المستخدم"""
    if not dt:
        return ''
    secs = int((now_utc() - dt).total_seconds())
    if secs < 0:
        secs = 0
    code = lang or _lang()
    if secs < 60:
        return t('time.now', code)
    if secs < 3600:
        return t('time.ago_min', code, n=secs // 60)
    if secs < 86400:
        return t('time.ago_hour', code, n=secs // 3600)
    return t('time.ago_day', code, n=secs // 86400)


def _lang():
    """لغة الطلب الحالي (للواجهة)"""
    return getattr(g, 'lang', None) or app.config['DEFAULT_LANG']


def api_lang():
    """لغة الطلب الحالي (للـ API): الجلسة/التوكن > Accept-Language"""
    user = current_user()
    return resolve_lang(request.headers.get('Accept-Language'), session.get('lang'),
                        user.lang if user else None, app.config['DEFAULT_LANG'])


def tr(key, **kwargs):
    return t(key, api_lang(), **kwargs)


def client_ip():
    return request.remote_addr or ''


def current_user():
    """المستخدم الحالي: جلسة المتصفح أو Authorization: Bearer <token>"""
    if 'user' not in g:
        uid = session.get('uid')
        g.user = db.session.get(User, uid) if uid else _token_user()
    return g.user


def is_api():
    return request.path.startswith('/api/')


def _json_error(key, status=400, code=None, **fmt):
    payload = {'ok': False, 'error': tr(key, **fmt)}
    if code:
        payload['code'] = code
    return jsonify(payload), status


def safe_next(target):
    """يمنع التحويل لمواقع خارجية بعد الدخول"""
    if target and target.startswith('/') and not target.startswith('//') and '\\' not in target:
        return target
    return url_for('index')


# ==========================================================================
# حدود الاستخدام (Rate limit) — عدّاد في القاعدة
# ==========================================================================
def _trim_hits(bucket, cutoff):
    RateHit.query.filter(RateHit.bucket == bucket, RateHit.created_at < cutoff).delete(
        synchronize_session=False)


def over_limit(bucket, limit, window):
    cutoff = now_utc() - window
    _trim_hits(bucket, cutoff)
    return RateHit.query.filter(RateHit.bucket == bucket, RateHit.created_at >= cutoff).count() >= limit


def note_hit(bucket):
    db.session.add(RateHit(bucket=bucket, created_at=now_utc()))
    db.session.commit()


def hit_limit(bucket, limit, window):
    """True لو العداد عدّى الحد، وإلا بيسجّل المحاولة الحالية"""
    if over_limit(bucket, limit, window):
        db.session.commit()
        return True
    note_hit(bucket)
    return False


# ==========================================================================
# المصادقة
# ==========================================================================
def _serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='api-token')


def make_token(user):
    return _serializer().dumps({'uid': user.id})


def _token_user():
    header = request.headers.get('Authorization', '')
    if not header.startswith('Bearer '):
        return None
    try:
        uid = _serializer().loads(header[7:], max_age=TOKEN_MAX_AGE)['uid']
    except (BadSignature, SignatureExpired, KeyError, TypeError):
        return None
    return db.session.get(User, uid)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            if is_api():
                return _json_error('auth.login_required', 401)
            return redirect(url_for('login', next=request.path))
        if not u.phone_verified and request.endpoint not in UNVERIFIED_OK:
            if is_api():
                return _json_error('auth.phone_unverified', 403, code='phone_unverified')
            return redirect(url_for('verify'))
        return f(*args, **kwargs)
    return wrapper


def guardian_required(f):
    """بعض العمليات (الدعوات/الإعلانات) لولي الأمر بس"""
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        u = current_user()
        if u.role != 'parent':
            if is_api():
                return _json_error('errors.forbidden', 403)
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper


# ==========================================================================
# الترجمة + الحالة العامة للقوالب
# ==========================================================================
@app.before_request
def _prepare_request():
    requested = request.args.get('lang')
    if requested:
        code = normalize_lang(requested)
        if code:
            session['lang'] = code
    g.lang = resolve_lang(request.headers.get('Accept-Language'), session.get('lang'),
                          None, app.config['DEFAULT_LANG'])
    g.dir = 'rtl' if g.lang == 'ar' else 'ltr'
    # حماية بسيطة من CSRF لنماذج الويب: لو المتصفح بعت Origin مختلف نرفض
    if request.method in ('POST', 'PUT', 'DELETE'):
        origin = request.headers.get('Origin')
        if origin and is_api() is False:
            allowed = {request.host_url.rstrip('/')}
            if origin.rstrip('/') not in allowed:
                return render_template('error.html', code=403, message=tr('errors.forbidden')), 403


@app.context_processor
def _inject():
    return {
        't': lambda key, **kw: t(key, _lang(), **kw),
        'lang': _lang(),
        'dir': g.get('dir', 'rtl'),
        'countries': COUNTRIES,
        'app_name': app.config['APP_NAME'],
        'support_email': app.config['SUPPORT_EMAIL'],
        'current_year': now_utc().year,
    }


@app.after_request
def _headers(resp):
    if is_api():
        allowed = app.config['ALLOWED_ORIGINS']
        origin = request.headers.get('Origin', '')
        resp.headers['Access-Control-Allow-Origin'] = allowed if allowed != '*' else (
            origin or '*')
        resp.headers['Vary'] = 'Origin'
        resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Accept-Language'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        resp.headers['Access-Control-Max-Age'] = '600'
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    return resp


# ==========================================================================
# قاعدة البيانات: إنشاء + ترقية آمنة (من غير مسح بيانات)
# ==========================================================================
def _bool_ddl(default):
    return 'BOOLEAN DEFAULT ' + ('TRUE' if default else 'FALSE')


def _datetime_ddl():
    return 'TIMESTAMP' if db.engine.dialect.name != 'sqlite' else 'DATETIME'


def init_db():
    """ينشئ الجداول الناقصة ويضيف الأعمدة الجديدة للجداول القديمة"""
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        @event.listens_for(db.engine, 'connect')
        def _sqlite_pragmas(dbapi_connection, _record):
            cur = dbapi_connection.cursor()
            cur.execute('PRAGMA journal_mode=WAL')
            cur.execute('PRAGMA synchronous=NORMAL')
            cur.execute('PRAGMA busy_timeout=5000')
            cur.execute('PRAGMA foreign_keys=ON')
            cur.execute('PRAGMA temp_store=MEMORY')
            cur.execute('PRAGMA cache_size=-20000')
            cur.close()

    db.create_all()

    migrations = {
        'user': [
            ('password_hash', "VARCHAR(255) DEFAULT ''"),
            ('country', "VARCHAR(2) DEFAULT ''"),
            ('phone_verified', _bool_ddl(False)),
            ('lang', "VARCHAR(2) DEFAULT 'ar'"),
            ('notify_sos', _bool_ddl(True)),
            ('notify_scans', _bool_ddl(True)),
            ('max_children', 'INTEGER DEFAULT 10'),
            ('allow_child_revoke', _bool_ddl(True)),
            ('created_at', _datetime_ddl()),
        ],
        'link': [
            ('status', "VARCHAR(12) DEFAULT 'active'"),
            ('ended_by', 'INTEGER'),
            ('end_reason', "VARCHAR(30) DEFAULT ''"),
            ('ended_at', _datetime_ddl()),
        ],
        'sos_event': [('ended_at', _datetime_ddl())],
        'scan_log': [
            ('score', 'INTEGER DEFAULT 0'),
            ('level', "VARCHAR(10) DEFAULT ''"),
            ('final_url', "VARCHAR(500) DEFAULT ''"),
            ('sources', "TEXT DEFAULT '{}'"),
        ],
    }
    for table, columns in migrations.items():
        try:
            existing = {c['name'] for c in inspect(db.engine).get_columns(table)}
        except Exception:            # الجدول مش موجود لسه
            continue
        for name, ddl in columns:
            if name not in existing:
                db.session.execute(text(f'ALTER TABLE "{table}" ADD COLUMN {name} {ddl}'))
                db.session.commit()

    for stmt in (
        'CREATE INDEX IF NOT EXISTS ix_sos_user ON sos_event (user_id)',
        'CREATE INDEX IF NOT EXISTS ix_sos_status ON sos_event (status)',
        'CREATE INDEX IF NOT EXISTS ix_notif_user_time ON notification (user_id, created_at)',
        'CREATE INDEX IF NOT EXISTS ix_link_guardian ON link (guardian_id)',
        'CREATE INDEX IF NOT EXISTS ix_link_protected ON link (protected_id)',
        'CREATE INDEX IF NOT EXISTS ix_link_status ON link (status)',
        'CREATE INDEX IF NOT EXISTS ix_scan_user_time ON scan_log (user_id, created_at)',
        'CREATE INDEX IF NOT EXISTS ix_app_user_time ON app_report (user_id, created_at)',
        'CREATE INDEX IF NOT EXISTS ix_rate_bucket_time ON rate_hit (bucket, created_at)',
        'CREATE INDEX IF NOT EXISTS ix_invite_code ON link_invite (code)',
        'CREATE INDEX IF NOT EXISTS ix_invite_guardian ON link_invite (guardian_id)',
        'CREATE INDEX IF NOT EXISTS ix_audit_actor_time ON audit_log (actor_id, created_at)',
        'CREATE INDEX IF NOT EXISTS ix_appscan_user_time ON app_scan (user_id, created_at)',
        'CREATE INDEX IF NOT EXISTS ix_consent_child ON guardian_consent (child_id)',
    ):
        try:
            db.session.execute(text(stmt))
            db.session.commit()
        except Exception:
            db.session.rollback()

    # قيم افتراضية للصفوف القديمة
    for stmt in (
        'UPDATE link SET status = \'active\' WHERE status IS NULL',
        'UPDATE "user" SET lang = \'ar\' WHERE lang IS NULL',
        'UPDATE "user" SET max_children = 10 WHERE max_children IS NULL',
    ):
        try:
            db.session.execute(text(stmt))
            db.session.commit()
        except Exception:
            db.session.rollback()


with app.app_context():
    init_db()


# ==========================================================================
# أدوات المستخدم / التحقق
# ==========================================================================
def normalize_phone(country, raw):
    """يرجّع الرقم بصيغة دولية (+201012345678) أو None"""
    if country not in COUNTRIES:
        return None
    raw = (raw or '').strip()
    digits = re.sub(r'\D', '', raw)
    if raw.startswith('+'):
        pass
    elif digits.startswith('00'):
        digits = digits[2:]
    elif digits.startswith(COUNTRIES[country][1]) and len(digits) > 9:
        pass                       # المستخدم كتب كود الدولة من غير +
    else:
        digits = COUNTRIES[country][1] + digits.lstrip('0')
    return '+' + digits if 8 <= len(digits) <= 15 else None


def mask_phone(p):
    return (p[:3] + '•' * max(len(p) - 7, 0) + p[-4:]) if p else ''


def user_json(u):
    return {'id': u.id, 'username': u.username, 'email': u.email, 'phone': u.phone,
            'role': u.role, 'country': u.country or '',
            'phone_verified': bool(u.phone_verified), 'lang': u.lang or 'ar',
            'max_children': u.max_children or 10,
            'allow_child_revoke': bool(u.allow_child_revoke)}


def signup_error(username, email, password, confirm, role, country, phone):
    if not (3 <= len(username) <= 40):
        return 'auth.invalid_username'
    if len(username) > 40 or re.search(r'[\s/\\]', username):
        return 'auth.invalid_username'
    if User.query.filter_by(username=username).first():
        return 'auth.username_taken'
    if email and '@' not in email:
        return 'auth.invalid_email'
    if country not in COUNTRIES:
        return 'auth.invalid_country'
    if not normalize_phone(country, phone):
        return 'auth.invalid_phone'
    if len(password) < 8:
        return 'auth.weak_password'
    if password != confirm:
        return 'auth.password_mismatch'
    if role not in ('parent', 'child'):
        return 'auth.invalid_role'
    return ''


# ==========================================================================
# إشعارات FCM (اختياري)
# ==========================================================================
def push_to_user(user_id, title, body, data=None):
    """إشعار فوري على موبايلات المستخدم عبر Firebase — بيشتغل لو الإعدادات موجودة"""
    project = app.config.get('FCM_PROJECT_ID')
    cred_path = app.config.get('FCM_CREDENTIALS')
    if not (project and cred_path):
        return
    devices = DeviceToken.query.filter_by(user_id=user_id).all()
    if not devices:
        return
    try:
        from google.auth.transport.requests import Request
        from google.oauth2 import service_account
        creds = service_account.Credentials.from_service_account_file(
            cred_path, scopes=['https://www.googleapis.com/auth/firebase.messaging'])
        creds.refresh(Request())
    except Exception as exc:          # مكتبة ناقصة أو ملف غلط
        app.logger.warning('FCM auth failed: %s', exc)
        return
    for dev in devices:
        payload = {'message': {
            'token': dev.token,
            'notification': {'title': title, 'body': body},
            'data': {k: str(v) for k, v in (data or {}).items()},
            'android': {'priority': 'HIGH', 'notification': {'channel_id': 'sos_alerts'}},
        }}
        try:
            r = requests.post(
                f'https://fcm.googleapis.com/v1/projects/{project}/messages:send',
                headers={'Authorization': f'Bearer {creds.token}'}, json=payload, timeout=10)
            if r.status_code == 404 or 'UNREGISTERED' in r.text:
                db.session.delete(dev)
        except requests.exceptions.RequestException:
            pass
    db.session.commit()


def notify(user_id, title, body, kind='info', event_token=''):
    """إشعار داخلي + (اختياري) إشعار فوري"""
    db.session.add(Notification(user_id=user_id, kind=kind, title=title[:120],
                                body=body[:300], event_token=event_token))
    db.session.commit()
    push_to_user(user_id, title, body)


# ==========================================================================
# لوحة التحكم
# ==========================================================================
def _latest_scan(user):
    return (ScanLog.query.filter_by(user_id=user.id)
            .order_by(ScanLog.created_at.desc()).first())


def protection_label(user):
    code = _lang()
    if SOSEvent.query.filter_by(user_id=user.id, status='active').first():
        return t('protection.active', code)
    protected_ids = [lk.protected_id for lk in links.links_as_guardian(user.id)]
    if protected_ids and SOSEvent.query.filter(
            SOSEvent.user_id.in_(protected_ids), SOSEvent.status == 'active').first():
        return t('protection.active_linked', code)
    last = _latest_scan(user)
    if not last:
        return t('protection.never', code)
    return t('protection.last_risky', code) if not last.safe else t('protection.last_clean', code)


def recent_activity(user):
    rows = []
    notes = (Notification.query.filter_by(user_id=user.id)
             .order_by(Notification.created_at.desc()).limit(5).all())
    for n in notes:
        rows.append((n.created_at, n.title, n.body, time_ago(n.created_at)))
    scans = (ScanLog.query.filter_by(user_id=user.id)
             .order_by(ScanLog.created_at.desc()).limit(5).all())
    for s in scans:
        rows.append((s.created_at, t('scan.activity', _lang()), s.msg, time_ago(s.created_at)))
    rows.sort(key=lambda r: r[0] or now_utc(), reverse=True)
    return [{'title': title, 'desc': desc, 'time': tm} for _, title, desc, tm in rows[:5]]


@app.route('/', methods=['GET'])
@login_required
def index():
    user = current_user()
    last = _latest_scan(user)
    alerts_count = Notification.query.filter_by(user_id=user.id, read=False).count()
    own_sos = SOSEvent.query.filter_by(user_id=user.id, status='active').first()
    linked_ids = [lk.protected_id for lk in links.links_as_guardian(user.id)]
    linked_sos = (SOSEvent.query.filter(SOSEvent.user_id.in_(linked_ids),
                                        SOSEvent.status == 'active').first()
                  if linked_ids else None)
    if own_sos or linked_sos:
        protection_level = 'danger'
    elif last and not last.safe:
        protection_level = 'warn'
    else:
        protection_level = 'safe'
    return render_template(
        'index.html', user=user, protection=protection_label(user),
        devices=links.link_count(user.id), alerts=alerts_count,
        last_scan=time_ago(last.created_at) if last else t('time.never', _lang()),
        activities=recent_activity(user), protection_level=protection_level,
        pending_invites=len(links.pending_for_guardian(user.id)) if user.role == 'parent' else 0)


# ==========================================================================
# تسجيل الدخول / التسجيل / الخروج
# ==========================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user():
        return redirect(url_for('index'))
    error, username = '', ''
    nxt = request.args.get('next', '')
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        nxt = request.form.get('next', '')
        bucket = 'login:' + client_ip()
        if over_limit(bucket, 30, timedelta(minutes=15)):
            db.session.commit()
            error = tr('auth.login_rate_limited')
        else:
            u = User.query.filter_by(username=username).first()
            if u and u.password_hash and check_password_hash(u.password_hash, password):
                session.clear()
                session['uid'] = u.id
                session['lang'] = u.lang or app.config['DEFAULT_LANG']
                links.log(u.id, 'login_web', 'user', u.id, ip=client_ip())
                return redirect(safe_next(nxt))
            note_hit(bucket)
            error = tr('auth.bad_credentials')
    return render_template('login.html', error=error, username=username, next=nxt)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user():
        return redirect(url_for('index'))
    error = ''
    form = {'username': '', 'email': '', 'phone': '', 'role': 'parent', 'country': 'EG'}
    if request.method == 'POST':
        for key in ('username', 'email', 'phone'):
            form[key] = request.form.get(key, '').strip()
        form['role'] = request.form.get('role', 'parent')
        form['country'] = request.form.get('country', '')
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        error_key = signup_error(form['username'], form['email'], password, confirm,
                                 form['role'], form['country'], form['phone'])
        if not error_key:
            u = User(username=form['username'], email=form['email'],
                     phone=normalize_phone(form['country'], form['phone']),
                     country=form['country'], role=form['role'], lang=_lang(),
                     password_hash=generate_password_hash(password))
            db.session.add(u)
            db.session.commit()
            session.clear()
            session['uid'] = u.id
            session['lang'] = u.lang
            links.log(u.id, 'register_web', 'user', u.id, ip=client_ip())
            return redirect(url_for('index'))
        error = tr(error_key)
    return render_template('register.html', error=error, form=form, countries=COUNTRIES)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/lang/<code>')
def set_lang(code):
    normalized = normalize_lang(code)
    if normalized:
        session['lang'] = normalized
        user = current_user()
        if user:
            user.lang = normalized
            db.session.commit()
    nxt = request.args.get('next') or request.referrer or url_for('index')
    return redirect(safe_next(nxt) if nxt.startswith('/') else url_for('index'))


# ==========================================================================
# الفحص
# ==========================================================================
def scan_limits(scan_type):
    return app.config['SCAN_MODES'].get(scan_type, app.config['SCAN_MODES']['normal'])


def run_scan(url, scan_type, lang=None):
    """يفحص الرابط ويرجّع (الرابط، نوع الفحص، النتيجة أو None)"""
    code = lang or api_lang()
    url = (url or '').strip()
    if scan_type not in app.config['SCAN_MODES']:
        scan_type = 'normal'
    if not url:
        return url, scan_type, None
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    timeout, max_redirects = scan_limits(scan_type)
    result = scan_url(url, timeout=timeout, max_redirects=max_redirects,
                      scan_type=scan_type, lang=code,
                      config={'gsb_key': app.config['GOOGLE_SAFE_BROWSING_KEY'],
                              'vt_key': app.config['VIRUSTOTAL_API_KEY'],
                              'urlhaus': app.config['URLHAUS_ENABLED'],
                              'user_agent': app.config['SCANNER_USER_AGENT']})
    return url, scan_type, result


def log_scan(user, url, scan_type, result):
    row = ScanLog(user_id=user.id, url=url[:500], scan_type=scan_type,
                  safe=bool(result.get('safe')), msg=str(result.get('msg', ''))[:300],
                  score=int(result.get('score') or 0), level=str(result.get('level', ''))[:10],
                  final_url=str(result.get('final_url', url))[:500],
                  sources=json.dumps(result.get('sources', {}), ensure_ascii=False)[:2000])
    db.session.add(row)
    db.session.commit()
    return row


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    user = current_user()
    scan_result, scanned_url, scan_type, scan_error = None, '', 'normal', ''
    if request.method == 'POST':
        if hit_limit('scan:' + str(user.id), app.config['SCAN_PER_HOUR'], timedelta(hours=1)):
            scan_error = tr('scan.rate_limit')
        else:
            scanned_url, scan_type, scan_result = run_scan(
                request.form.get('url_to_scan', ''), request.form.get('scan_type', 'normal'),
                lang=_lang())
            if scan_result:
                log_scan(user, scanned_url, scan_type, scan_result)
    report = (AppReport.query.filter_by(user_id=user.id)
              .order_by(AppReport.created_at.desc()).first())
    app_names = []
    if report and report.names:
        try:
            app_names = json.loads(report.names)
        except (TypeError, ValueError):
            app_names = []
    last_apps = (AppScan.query.filter_by(user_id=user.id)
                 .order_by(AppScan.created_at.desc()).limit(5).all())
    return render_template('scan.html', user=user, scan_result=scan_result,
                           scanned_url=scanned_url, scan_type=scan_type,
                           scan_error=scan_error, app_report=report, app_names=app_names,
                           app_report_time=time_ago(report.created_at) if report else '',
                           app_scans=last_apps)


# ==========================================================================
# الطوارئ (SOS)
# ==========================================================================
@app.route('/sos', methods=['GET', 'POST'])
@login_required
def sos():
    return render_template('sos.html', user=current_user(), auto_trigger=request.method == 'POST')


def _valid_coords(data):
    try:
        lat = float(data.get('lat'))
        lng = float(data.get('lng'))
        acc = float(data.get('accuracy') or 0)
    except (TypeError, ValueError, AttributeError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lng <= 180) or acc < 0:
        return None
    return lat, lng, acc


@app.route('/api/sos', methods=['POST'])
@login_required
def api_sos_create():
    user = current_user()
    if hit_limit('sos:' + str(user.id), 5, timedelta(hours=1)):
        return _json_error('sos.rate_limit', 429)
    coords = _valid_coords(request.get_json(silent=True) or {})
    if not coords:
        return _json_error('sos.invalid_coords', 400)
    lat, lng, acc = coords
    ev = SOSEvent(user_id=user.id, token=secrets.token_urlsafe(16), lat=lat, lng=lng, accuracy=acc)
    db.session.add(ev)
    db.session.commit()

    title = tr('sos.title', username=user.username)
    body = tr('sos.body')
    targets = [lk.guardian_id for lk in links.links_as_protected(user.id)]
    for guardian_id in targets:
        db.session.add(Notification(user_id=guardian_id, kind='sos', title=title[:120],
                                    body=body[:300], event_token=ev.token))
    db.session.commit()
    for guardian_id in targets:
        push_to_user(guardian_id, title, body, {'type': 'sos', 'token': ev.token})
    links.log(user.id, 'sos_create', 'sos_event', ev.id, {'guardians': len(targets)}, client_ip())
    return jsonify(ok=True, token=ev.token, id=ev.id,
                   track_url=url_for('track', token=ev.token, _external=True),
                   notified=len(targets), message=tr('sos.notified', n=len(targets)))


@app.route('/api/sos/active')
@login_required
def api_sos_active():
    user = current_user()
    ev = (SOSEvent.query.filter_by(user_id=user.id, status='active')
          .order_by(SOSEvent.created_at.desc()).first())
    return jsonify(ok=True, active=bool(ev),
                   event=None if not ev else {
                       'id': ev.id, 'token': ev.token, 'lat': ev.lat, 'lng': ev.lng,
                       'accuracy': ev.accuracy,
                       'track_url': url_for('track', token=ev.token, _external=True),
                       'updated': time_ago(ev.updated_at)})


@app.route('/api/sos/history')
@login_required
def api_sos_history():
    user = current_user()
    rows = (SOSEvent.query.filter_by(user_id=user.id)
            .order_by(SOSEvent.created_at.desc()).limit(20).all())
    return jsonify(ok=True, items=[{
        'id': ev.id, 'status': ev.status, 'lat': ev.lat, 'lng': ev.lng,
        'created': time_ago(ev.created_at), 'token': ev.token} for ev in rows])


@app.route('/api/sos/<token>/update', methods=['POST'])
def api_sos_update(token):
    ev = SOSEvent.query.filter_by(token=token).first_or_404()
    if ev.status != 'active':
        return _json_error('sos.ended', 400)
    coords = _valid_coords(request.get_json(silent=True) or {})
    if not coords:
        return _json_error('sos.invalid_coords', 400)
    if ev.updated_at and (now_utc() - ev.updated_at).total_seconds() < 8:
        return jsonify(ok=True, skipped=True)
    ev.lat, ev.lng, ev.accuracy = coords
    ev.updated_at = now_utc()
    db.session.commit()
    return jsonify(ok=True)


@app.route('/api/sos/<token>/stop', methods=['POST'])
def api_sos_stop(token):
    ev = SOSEvent.query.filter_by(token=token).first_or_404()
    if ev.status == 'active':
        ev.status = 'ended'
        ev.ended_at = now_utc()
        db.session.commit()
        links.log(ev.user_id, 'sos_stop', 'sos_event', ev.id, ip=client_ip())
    return jsonify(ok=True)


@app.route('/api/track/<token>')
def api_track(token):
    ev = SOSEvent.query.filter_by(token=token).first_or_404()
    if ev.status != 'active':
        return jsonify(status='ended')
    return jsonify(status='active', lat=ev.lat, lng=ev.lng, accuracy=ev.accuracy,
                   updated=time_ago(ev.updated_at))


@app.route('/track/<token>')
def track(token):
    ev = SOSEvent.query.filter_by(token=token).first_or_404()
    owner = db.session.get(User, ev.user_id)
    return render_template('track.html', ev=ev, owner=owner, updated=time_ago(ev.updated_at))


# ==========================================================================
# الاشتراكات (من غير أي تعامل مع بيانات الكروت)
# ==========================================================================
@app.route('/subscriptions', methods=['GET', 'POST'])
@login_required
def subscriptions():
    user = current_user()
    sub_message, error_msg = '', ''
    selected_plan = 'free'
    if request.method == 'POST':
        action = request.form.get('action')
        plan = request.form.get('plan') or request.form.get('plan_name') or ''
        if plan not in PLAN_INFO or plan == 'free':
            error_msg = tr('subs.invalid_plan')
        elif action == 'select_plan':
            selected_plan = plan
        elif action == 'confirm_payment':
            # ممنوع نستقبل بيانات بطاقة هنا: الدفع لازم يكون على بوابة مستضافة
            db.session.add(SubscriptionRequest(user_id=user.id, plan=plan,
                                               period='yearly' if plan == 'yearly' else 'monthly',
                                               note='طلب من صفحة الويب'))
            db.session.commit()
            links.log(user.id, 'subscription_request', 'plan', None, {'plan': plan}, client_ip())
            sub_message = tr('subs.request_received')
            selected_plan = plan
        else:
            error_msg = tr('errors.bad_request')
        if action == 'confirm_payment':
            for field in ('card_number', 'cvv', 'expiry', 'card_holder'):
                if request.form.get(field):
                    app.logger.warning('card data submitted on /subscriptions and dropped (user %s)', user.id)
                    break
    plans = []
    for key, info in PLAN_INFO.items():
        plans.append({'key': key, 'name': info.get(_lang()) or info['ar'],
                      'monthly': info['monthly'], 'yearly': info['yearly'],
                      'features': info.get('features_' + _lang()) or info['features_ar']})
    latest = (SubscriptionRequest.query.filter_by(user_id=user.id)
              .order_by(SubscriptionRequest.created_at.desc()).first())
    return render_template('subscriptions.html', user=user, plans=plans,
                           selected_plan=selected_plan, sub_message=sub_message,
                           error=error_msg, subscription=latest,
                           free_plan=PLAN_INFO['free'])


# ==========================================================================
# الملف الشخصي
# ==========================================================================
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user()
    message = error = ''
    if request.method == 'POST':
        new_name = request.form.get('username', user.username).strip() or user.username
        if not (3 <= len(new_name) <= 40):
            error = tr('auth.invalid_username')
        elif User.query.filter(User.username == new_name, User.id != user.id).first():
            error = tr('auth.username_taken')
        else:
            user.username = new_name
            email = request.form.get('email', user.email)
            if not email or '@' in email:
                user.email = email
            else:
                error = tr('auth.invalid_email')
            country = request.form.get('country', user.country or '').strip().upper()
            if country in COUNTRIES:
                user.country = country
            # الرقم الفاضي أو الغلط ما بيمسحش الرقم ولا التوثيق
            raw_phone = request.form.get('phone', '').strip()
            if raw_phone and user.country:
                new_phone = normalize_phone(user.country, raw_phone)
                if new_phone and new_phone != (user.phone or ''):
                    user.phone = new_phone
                    user.phone_verified = False
            new_role = request.form.get('role', user.role)
            if new_role in ('parent', 'child'):
                user.role = new_role
            db.session.commit()
            message = tr('common.saved')
            links.log(user.id, 'profile_update', 'user', user.id, ip=client_ip())
    return render_template('profile.html', user=user, countries=COUNTRIES,
                           message=message, error=error)


# ==========================================================================
# الرقابة الوالدية (صفحة الويب)
# ==========================================================================
PAIR_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'


def _code_hash(code):
    return hmac.new(app.config['SECRET_KEY'].encode(), code.upper().encode(), hashlib.sha256).hexdigest()


def _new_pair_code(user):
    """كود الربط القديم (8 حروف) — صالح 10 دقايق"""
    PairCode.query.filter_by(guardian_id=user.id, used=False).delete()
    code = ''.join(secrets.choice(PAIR_ALPHABET) for _ in range(8))
    db.session.add(PairCode(guardian_id=user.id, code_hash=_code_hash(code),
                            expires_at=now_utc() + timedelta(minutes=10)))
    db.session.commit()
    return code


def _join_pair(user, raw_code):
    """يدخل كود الربط القديم. يرجّع (نجح؟، نص)"""
    since = now_utc() - timedelta(hours=1)
    if PairFail.query.filter(PairFail.user_id == user.id, PairFail.created_at > since).count() >= 10:
        return False, tr('link.too_many_attempts')
    code = re.sub(r'[^A-Za-z0-9]', '', str(raw_code or '')).upper()
    pc = PairCode.query.filter_by(code_hash=_code_hash(code), used=False).first() if code else None
    if not pc or pc.expires_at < now_utc():
        db.session.add(PairFail(user_id=user.id))
        db.session.commit()
        return False, tr('link.invalid_code')
    if pc.guardian_id == user.id:
        return False, tr('link.self_link')
    guardian = db.session.get(User, pc.guardian_id)
    if not guardian:
        return False, tr('link.invalid_code')
    if not links.active_link(guardian.id, user.id):
        ok, key = links.create_legacy_link(guardian.id, user.id, client_ip())
        if not ok:
            return False, tr(key)
        notify(guardian.id, 'تم ربط حساب جديد',
               f'{user.username} ربط حسابه بحسابك، وهيوصلك تنبيه لو أرسل نجدة.')
    pc.used = True
    db.session.commit()
    return True, guardian.username


@app.route('/parental', methods=['GET', 'POST'])
@login_required
def parental():
    user = current_user()
    message = error = code = ''
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'code':
            code = _new_pair_code(user)
            message = tr('link.pair_code_msg')
        elif action == 'join':
            ok_join, val = _join_pair(user, request.form.get('code', ''))
            message, error = (tr('link.created'), '') if ok_join else ('', val)
        elif action == 'remove':
            link = db.session.get(Link, request.form.get('link_id', type=int))
            ok_remove, key = links.remove_link(user, link, client_ip())
            message, error = (tr(key), '') if ok_remove else ('', tr(key))
        elif action == 'revoke':
            link = db.session.get(Link, request.form.get('link_id', type=int))
            ok_revoke, key = links.revoke_link(user, link, client_ip())
            message, error = (tr(key), '') if ok_revoke else ('', tr(key))
        elif action == 'invite':
            ok_inv, invite, _payload = links.create_invite(
                user, app.config['INVITE_PER_DAY'], app.config['INVITE_TTL_HOURS'], client_ip())
            if ok_inv:
                code = invite.code
                message = tr('link.invite_created')
            else:
                error = tr(invite) if isinstance(invite, str) else tr('common.error')
        elif action == 'accept_invite':
            invite = links.get_invite(request.form.get('code', ''))
            ok_accept, key = links.accept_invite(
                user, invite, consent_text=tr('link.consent_body'),
                consent_version=app.config['CONSENT_VERSION'], ip=client_ip())
            message, error = (tr(key), '') if ok_accept else ('', tr(key))
        elif action == 'approve':
            invite = links.get_invite(request.form.get('code', ''), for_guardian=user.id)
            ok_app, key = links.approve_invite(user, invite, client_ip())
            message, error = (tr(key), '') if ok_app else ('', tr(key))
        elif action == 'reject':
            invite = links.get_invite(request.form.get('code', ''), for_guardian=user.id)
            ok_rej, key = links.reject_invite(user, invite, client_ip())
            message, error = (tr(key), '') if ok_rej else ('', tr(key))
        else:
            error = tr('errors.bad_request')

    protected, guardians = _linked_people(user)
    pending = links.pending_for_guardian(user.id) if user.role == 'parent' else []
    return render_template('parental.html', user=user, protected=protected, guardians=guardians,
                           message=message, error=error, pair_code=code,
                           pending=pending, consent_text=tr('link.consent_body'),
                           invite_web_link=url_for('invite_page', code=code, _external=True) if code else '')


def _linked_people(user):
    protected = []
    for lk in links.links_as_guardian(user.id):
        other = db.session.get(User, lk.protected_id)
        if not other:
            continue
        ev = (SOSEvent.query.filter_by(user_id=other.id, status='active')
              .order_by(SOSEvent.updated_at.desc()).first())
        report = (AppReport.query.filter_by(user_id=other.id)
                  .order_by(AppReport.created_at.desc()).first())
        scan = (AppScan.query.filter_by(user_id=other.id)
                .order_by(AppScan.created_at.desc()).first())
        names = []
        if report and report.names:
            try:
                names = json.loads(report.names)
            except (TypeError, ValueError):
                names = []
        if not names and scan and scan.package:
            names = [scan.package]
        ad_row = AdSettings.query.filter_by(child_id=other.id).first()
        protected.append({
            'link_id': lk.id, 'username': other.username, 'event': ev, 'names': names,
            'report_time': time_ago(report.created_at) if report else '',
            'report_count': report.app_count if report else 0,
            'track_url': url_for('track', token=ev.token) if ev else '',
            'moved': time_ago(ev.updated_at) if ev else '',
            'ads': links.ads_to_dict(ads_for(other.id)) if ad_row else None,
            'last_scan': time_ago(scan.created_at) if scan else '',
            'last_scan_level': scan.level if scan else '',
        })
    guardians = []
    for lk in links.links_as_protected(user.id):
        other = db.session.get(User, lk.guardian_id)
        if other:
            guardians.append({'link_id': lk.id, 'username': other.username,
                              'since': time_ago(lk.created_at)})
    return protected, guardians


def ads_for(child_id):
    return links.ads_for(child_id)


# ==========================================================================
# الإشعارات / الإعدادات / الخصوصية
# ==========================================================================
def build_alerts(user):
    alerts = []
    recent_sos = (SOSEvent.query.filter_by(user_id=user.id)
                  .order_by(SOSEvent.created_at.desc()).limit(5).all())
    for ev in recent_sos:
        active = ev.status == 'active'
        alerts.append({
            'type': 'danger',
            'title': tr('sos.title', username=user.username),
            'desc': (tr('sos.body') + (' (التتبع مستمر)' if active else '')) if _lang() == 'ar'
                    else tr('sos.body'),
            'time': time_ago(ev.created_at),
        })
    inbox = (Notification.query.filter_by(user_id=user.id)
             .order_by(Notification.created_at.desc()).limit(10).all())
    for n in inbox:
        alerts.append({'type': 'danger' if n.kind == 'sos' else 'info', 'title': n.title,
                       'desc': n.body, 'time': time_ago(n.created_at)})
    return alerts


@app.route('/notifications', methods=['GET', 'POST'])
@login_required
def notifications():
    user = current_user()
    if request.method == 'POST':
        Notification.query.filter_by(user_id=user.id, read=False).update({'read': True})
        db.session.commit()
    return render_template('notifications.html', user=user, alerts=build_alerts(user))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = current_user()
    settings_saved = False
    error = ''
    if request.method == 'POST':
        lang = normalize_lang(request.form.get('lang', user.lang))
        if lang:
            user.lang = lang
            session['lang'] = lang
        user.notify_sos = request.form.get('notify_sos') == 'on'
        user.notify_scans = request.form.get('notify_scans') == 'on'
        db.session.commit()
        settings_saved = True
        links.log(user.id, 'settings_update', 'user', user.id,
                  {'lang': user.lang}, client_ip())
    return render_template('settings.html', user=user, settings_saved=settings_saved,
                           error=error, langs=[('ar', 'العربية'), ('en', 'English')])


@app.route('/privacy')
def privacy():
    return render_template('privacy.html', user=current_user())


# ==========================================================================
# تأكيد الموبايل (OTP)
# ==========================================================================
_AR_DIGITS = str.maketrans('٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹', '01234567890123456789')


def _hash_code(user_id, phone, code):
    return hmac.new(app.config['SECRET_KEY'].encode(),
                    f'{user_id}:{phone}:{code}'.encode(), hashlib.sha256).hexdigest()


def send_sms(phone, body):
    """بيحدد المزوّد من SMS_PROVIDER: console (افتراضي) أو twilio"""
    provider = app.config['SMS_PROVIDER']
    if provider == 'twilio':
        try:
            sid = os.environ['TWILIO_ACCOUNT_SID']
            r = requests.post(
                f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json',
                data={'To': phone, 'From': os.environ['TWILIO_FROM'], 'Body': body},
                auth=(sid, os.environ['TWILIO_AUTH_TOKEN']), timeout=10)
            return r.status_code in (200, 201)
        except (KeyError, requests.exceptions.RequestException) as exc:
            app.logger.warning('Twilio send failed: %s', exc)
            return False
    app.logger.info('[SMS تجريبي] إلى %s: %s', phone, body)
    return True

def issue_code(user):
    """يولّد كود ويبعته. يرجّع (نجح؟، الكود أو الخطأ، ثواني الانتظار)"""
    now = now_utc()
    if not user.phone:
        return False, tr('phone.no_phone'), 0
    row = PhoneCode.query.filter_by(user_id=user.id).first()
    if row and row.sent_at:
        wait = app.config['OTP_COOLDOWN'] - (now - row.sent_at).total_seconds()
        if wait > 0:
            return False, tr('phone.cooldown'), int(wait) + 1
    if SmsLog.query.filter(SmsLog.phone == user.phone,
                           SmsLog.created_at > now - timedelta(days=1)).count() >= app.config['OTP_PER_PHONE_DAY']:
        return False, tr('phone.daily_limit'), 3600
    ip = client_ip()
    if SmsLog.query.filter(SmsLog.ip == ip,
                           SmsLog.created_at > now - timedelta(hours=1)).count() >= app.config['OTP_PER_IP_HOUR']:
        return False, tr('phone.ip_limit'), 600

    code = f'{secrets.randbelow(10 ** 6):06d}'
    if not send_sms(user.phone, tr('phone.sms_body', code=code)):
        return False, tr('phone.send_failed'), 30
    if row is None:
        row = PhoneCode(user_id=user.id)
        db.session.add(row)
    row.phone = user.phone
    row.code_hash = _hash_code(user.id, user.phone, code)
    row.expires_at = now + timedelta(seconds=app.config['OTP_TTL'])
    row.attempts = 0
    row.sent_at = now
    db.session.add(SmsLog(phone=user.phone, ip=ip))
    db.session.commit()
    
    # [تعديل]: بنرجع الكود بدل الرسالة الفاضية
    return True, code, app.config['OTP_COOLDOWN']


def check_code(user, code):
    row = PhoneCode.query.filter_by(user_id=user.id).first()
    if not row or row.phone != user.phone:
        return False, tr('phone.request_new')
    if now_utc() > row.expires_at or row.attempts >= app.config['OTP_MAX_ATTEMPTS']:
        db.session.delete(row)
        db.session.commit()
        return False, tr('phone.expired')
    clean = re.sub(r'\D', '', (code or '').translate(_AR_DIGITS))
    if not hmac.compare_digest(row.code_hash, _hash_code(user.id, user.phone, clean)):
        row.attempts += 1
        db.session.commit()
        return False, tr('phone.wrong_code')
    db.session.delete(row)
    user.phone_verified = True
    db.session.commit()
    links.log(user.id, 'phone_verified', 'user', user.id, ip=client_ip())
    return True, ''
         
@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    user = current_user()
    if user.phone_verified:
        return redirect(url_for('index'))
    msg = error = ''
    if request.method == 'POST':
        if request.form.get('action') == 'send':
            # [تعديل] استقبال الكود بدل الرسالة
            ok, result_data, _ = issue_code(user)
            if ok:
                msg, error = (tr('phone.code_sent', phone=mask_phone(user.phone)), '')
                # للتجربة: لو السيرفر بيطبع في الكونسول، بنعرض الكود في رسالة عشان نستخدمه
                if app.config.get('SMS_PROVIDER') == 'console':
                    msg += f" (كود التجربة: {result_data})"
            else:
                msg, error = ('', result_data)
        else:
            ok, err = check_code(user, request.form.get('code', ''))
            if ok:
                return redirect(url_for('index'))
            error = err
    return render_template('verify.html', masked=mask_phone(user.phone), msg=msg, error=error)


# ==========================================================================
# API: المصادقة
# ==========================================================================
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    if hit_limit('register:' + client_ip(), 10, timedelta(hours=1)):
        return _json_error('auth.login_rate_limited', 429)
    d = request.get_json(silent=True) or {}
    username = str(d.get('username', '')).strip()
    email = str(d.get('email', '')).strip()
    phone = str(d.get('phone', '')).strip()
    country = str(d.get('country', '')).strip().upper()
    role = d.get('role', 'parent')
    password = str(d.get('password', ''))
    error_key = signup_error(username, email, password, password, role, country, phone)
    if error_key:
        return _json_error(error_key, 400, code=error_key)
    u = User(username=username, email=email, phone=normalize_phone(country, phone),
             country=country, role=role, lang=api_lang(),
             password_hash=generate_password_hash(password))
    db.session.add(u)
    db.session.commit()
    links.log(u.id, 'register_api', 'user', u.id, ip=client_ip())
    return jsonify(ok=True, token=make_token(u), user=user_json(u)), 201


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    bucket = 'login:' + client_ip()
    if over_limit(bucket, 30, timedelta(minutes=15)):
        db.session.commit()
        return _json_error('auth.login_rate_limited', 429)
    d = request.get_json(silent=True) or {}
    u = User.query.filter_by(username=str(d.get('username', '')).strip()).first()
    if u and u.password_hash and check_password_hash(u.password_hash, str(d.get('password', ''))):
        links.log(u.id, 'login_api', 'user', u.id, ip=client_ip())
        return jsonify(ok=True, token=make_token(u), user=user_json(u))
    note_hit(bucket)
    return _json_error('auth.bad_credentials', 401)


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify(ok=True)


@app.route('/api/phone/send', methods=['POST'])
@login_required
def api_phone_send():
    user = current_user()
    d = request.get_json(silent=True) or {}
    if d.get('phone'):
        country = str(d.get('country', user.country or '')).strip().upper()
        norm = normalize_phone(country, str(d['phone']))
        if not norm:
            return _json_error('phone.invalid', 400, code='invalid_phone')
        if norm != user.phone or country != user.country:
            user.phone, user.country, user.phone_verified = norm, country, False
            db.session.commit()
    if user.phone_verified:
        return jsonify(ok=True, verified=True, user=user_json(user))
    ok, err, retry = issue_code(user)
    if not ok:
        return jsonify(ok=False, error=err, retry_after=retry), 429
    return jsonify(ok=True, masked=mask_phone(user.phone), retry_after=retry)


@app.route('/api/phone/verify', methods=['POST'])
@login_required
def api_phone_verify():
    user = current_user()
    ok, err = check_code(user, str((request.get_json(silent=True) or {}).get('code', '')))
    if not ok:
        return jsonify(ok=False, error=err), 400
    return jsonify(ok=True, user=user_json(user))


@app.route('/api/me', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_me():
    u = current_user()
    if request.method == 'PUT':
        d = request.get_json(silent=True) or {}
        new_name = str(d.get('username', u.username)).strip() or u.username
        if not (3 <= len(new_name) <= 40):
            return _json_error('auth.invalid_username', 400)
        if User.query.filter(User.username == new_name, User.id != u.id).first():
            return _json_error('auth.username_taken', 400)
        country = str(d.get('country', u.country or '')).strip().upper()
        if country and country not in COUNTRIES:
            return _json_error('auth.invalid_country', 400)
        # الرقم الفاضي مش بيمسح الرقم ولا التوثيق
        phone = u.phone or ''
        if d.get('phone'):
            if not country:
                return _json_error('auth.invalid_country', 400)
            phone = normalize_phone(country, str(d['phone']))
            if not phone:
                return _json_error('auth.invalid_phone', 400)
        u.username = new_name
        if d.get('email') is not None:
            email = str(d.get('email')).strip()
            if email and '@' not in email:
                return _json_error('auth.invalid_email', 400)
            u.email = email
        if phone != (u.phone or ''):
            u.phone_verified = False
        u.phone = phone
        if country:
            u.country = country
        if d.get('lang'):
            lang = normalize_lang(d.get('lang'))
            if lang:
                u.lang = lang
        if d.get('role') in ('parent', 'child'):
            u.role = d['role']
        db.session.commit()
        links.log(u.id, 'profile_update_api', 'user', u.id, ip=client_ip())
        return jsonify(ok=True, user=user_json(u))
    if request.method == 'DELETE':
        _delete_account(u)
        return jsonify(ok=True, deleted=True)
    return jsonify(ok=True, user=user_json(u))


def _delete_account(user):
    """حق المستخدم في حذف حسابه وكل بياناته"""
    Notification.query.filter_by(user_id=user.id).delete()
    DeviceToken.query.filter_by(user_id=user.id).delete()
    PhoneCode.query.filter_by(user_id=user.id).delete()
    SmsLog.query.filter(SmsLog.phone == user.phone).delete()
    SOSEvent.query.filter_by(user_id=user.id).delete()
    ScanLog.query.filter_by(user_id=user.id).delete()
    AppScan.query.filter_by(user_id=user.id).delete()
    AppReport.query.filter_by(user_id=user.id).delete()
    PairCode.query.filter_by(guardian_id=user.id).delete()
    PairFail.query.filter_by(user_id=user.id).delete()
    SubscriptionRequest.query.filter_by(user_id=user.id).delete()
    AdSettings.query.filter_by(child_id=user.id).delete()
    LinkInvite.query.filter((LinkInvite.guardian_id == user.id) |
                            (LinkInvite.protected_id == user.id)).delete()
    GuardianConsent.query.filter((GuardianConsent.child_id == user.id) |
                                 (GuardianConsent.guardian_id == user.id)).delete()
    for lk in Link.query.filter((Link.guardian_id == user.id) |
                                (Link.protected_id == user.id)).all():
        other = lk.guardian_id if lk.protected_id == user.id else lk.protected_id
        db.session.add(Notification(user_id=other, kind='info', title='تم حذف الحساب',
                                    body=f'{user.username} حذف حسابه وكل بياناته.'))
        db.session.delete(lk)
    links.log(user.id, 'account_delete', 'user', user.id, ip=client_ip(), commit=False)
    db.session.delete(user)
    db.session.commit()


@app.route('/api/summary')
@login_required
def api_summary():
    u = current_user()
    last = _latest_scan(u)
    active = (SOSEvent.query.filter_by(user_id=u.id, status='active')
              .order_by(SOSEvent.created_at.desc()).first())
    return jsonify(ok=True, phone_verified=bool(u.phone_verified),
                   linked=links.link_count(u.id),
                   last_scan=time_ago(last.created_at) if last else None,
                   last_scan_safe=last.safe if last else None,
                   last_scan_level=last.level if last else None,
                   active_sos=bool(active),
                   unread=Notification.query.filter_by(user_id=u.id, read=False).count(),
                   pending_invites=len(links.pending_for_guardian(u.id)) if u.role == 'parent' else 0,
                   role=u.role, lang=u.lang)


@app.route('/api/inbox')
@login_required
def api_inbox():
    user = current_user()
    rows = (Notification.query.filter_by(user_id=user.id)
            .order_by(Notification.created_at.desc()).limit(30).all())
    items = []
    for n in rows:
        item = {'id': n.id, 'kind': n.kind, 'title': n.title, 'body': n.body,
                'read': bool(n.read), 'time': time_ago(n.created_at),
                'created_at': (n.created_at.isoformat() + 'Z') if n.created_at else None}
        if n.event_token:
            ev = SOSEvent.query.filter_by(token=n.event_token).first()
            item['track_url'] = url_for('track', token=n.event_token, _external=True)
            item['status'] = ev.status if ev else 'ended'
            if ev and ev.status == 'active':
                item['lat'], item['lng'] = ev.lat, ev.lng
        items.append(item)
    unread = Notification.query.filter_by(user_id=user.id, read=False).count()
    return jsonify(ok=True, items=items, unread=unread)


@app.route('/api/inbox/read', methods=['POST'])
@login_required
def api_inbox_read():
    user = current_user()
    raw = (request.get_json(silent=True) or {}).get('ids') or []
    if not isinstance(raw, list):
        return _json_error('errors.bad_request', 400)
    ids = []
    for value in raw[:100]:
        try:
            ids.append(int(value))
        except (TypeError, ValueError):
            continue
    if ids:
        Notification.query.filter(Notification.user_id == user.id,
                                  Notification.id.in_(ids)).update({'read': True})
        db.session.commit()
    return jsonify(ok=True)


@app.route('/api/devices', methods=['POST'])
@login_required
def api_devices():
    user = current_user()
    token = str((request.get_json(silent=True) or {}).get('token', '')).strip()
    if len(token) < 20:
        return _json_error('errors.bad_request', 400)
    dev = DeviceToken.query.filter_by(token=token).first()
    if dev:
        dev.user_id = user.id
    else:
        db.session.add(DeviceToken(user_id=user.id, token=token))
    db.session.commit()
    return jsonify(ok=True)


@app.route('/api/notifications')
@login_required
def api_notifications():
    return jsonify(ok=True, alerts=build_alerts(current_user()))


# ==========================================================================
# API: فحص الروابط والتطبيقات
# ==========================================================================
@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    user = current_user()
    if hit_limit('scan:' + str(user.id), app.config['SCAN_PER_HOUR'], timedelta(hours=1)):
        return _json_error('scan.rate_limit', 429)
    d = request.get_json(silent=True) or {}
    url, scan_type, result = run_scan(d.get('url', ''), d.get('type', 'normal'))
    if result is None:
        return _json_error('scan.invalid_url', 400)
    log_scan(user, url, scan_type, result)
    return jsonify(ok=True, url=url, type=scan_type, safe=result['safe'],
                   level=result.get('level'), score=result.get('score', 0),
                   msg=result['msg'], warnings=result.get('warnings', []),
                   sources=result.get('sources', {}), final_url=result.get('final_url', url))


def _store_app_scan(user, result, source='device'):
    row = AppScan(user_id=user.id, source=source,
                  package=str(result.get('package', ''))[:200],
                  label=str(result.get('label', ''))[:200],
                  sha256=str(result.get('sha256', ''))[:64],
                  score=int(result.get('score') or 0),
                  level=str(result.get('level', 'safe'))[:10],
                  verdict=str(result.get('verdict', 'safe'))[:12],
                  findings=json.dumps(result.get('findings', []), ensure_ascii=False)[:8000],
                  permissions=json.dumps(result.get('permissions_risky', []), ensure_ascii=False)[:8000],
                  apis=json.dumps(result.get('apis', []), ensure_ascii=False)[:4000],
                  sources=json.dumps(result.get('sources', {}), ensure_ascii=False)[:2000])
    db.session.add(row)
    db.session.commit()
    return row


@app.route('/api/scan/app', methods=['POST'])
@login_required
def api_scan_app():
    user = current_user()
    if hit_limit('appscan:' + str(user.id), app.config['APP_SCAN_PER_HOUR'], timedelta(hours=1)):
        return _json_error('scan.rate_limit', 429)
    d = request.get_json(silent=True) or {}
    if not isinstance(d, dict) or not (d.get('permissions') or d.get('package') or d.get('package_name')):
        return _json_error('app_scan.invalid', 400)
    result = analyze_app(
        package_name=str(d.get('package') or d.get('package_name') or ''),
        permissions=d.get('permissions') or [],
        apis=d.get('apis') or [],
        label=str(d.get('label') or d.get('app_name') or ''),
        sha256=str(d.get('sha256') or ''),
        signature_type=d.get('signature_type'),
        lang=api_lang(),
        vt_report=d.get('vt_report') if isinstance(d.get('vt_report'), dict) else None)
    _store_app_scan(user, result, 'device')
    return jsonify(ok=True, **result)


@app.route('/api/scan/apps/bulk', methods=['POST'])
@login_required
def api_scan_apps_bulk():
    user = current_user()
    if hit_limit('appscan:' + str(user.id), app.config['APP_SCAN_PER_HOUR'], timedelta(hours=1)):
        return _json_error('scan.rate_limit', 429)
    d = request.get_json(silent=True) or {}
    apps = d.get('apps') if isinstance(d, dict) else None
    if not isinstance(apps, list) or not apps:
        return _json_error('app_scan.bulk_empty', 400)
    if len(apps) > 50:
        return _json_error('app_scan.bulk_limit', 400, max=50)
    results = []
    for app_data in apps[:50]:
        if not isinstance(app_data, dict):
            continue
        result = analyze_app(
            package_name=str(app_data.get('package') or app_data.get('package_name') or ''),
            permissions=app_data.get('permissions') or [],
            apis=app_data.get('apis') or [],
            label=str(app_data.get('label') or app_data.get('app_name') or ''),
            sha256=str(app_data.get('sha256') or ''),
            signature_type=app_data.get('signature_type'),
            lang=api_lang())
        _store_app_scan(user, result, 'device')
        results.append({'package': result.get('package'), 'label': result.get('label'),
                        'safe': result.get('safe'), 'level': result.get('level'),
                        'score': result.get('score'), 'verdict': result.get('verdict'),
                        'msg': result.get('msg'), 'warnings': result.get('warnings', [])})
    return jsonify(ok=True, count=len(results), results=results,
                   unread=Notification.query.filter_by(user_id=user.id, read=False).count())


@app.route('/api/scan/apk', methods=['POST'])
@login_required
def api_scan_apk():
    user = current_user()
    if hit_limit('apkscan:' + str(user.id), 20, timedelta(hours=1)):
        return _json_error('scan.rate_limit', 429)
    upload = request.files.get('file') or request.files.get('apk')
    if not upload or not upload.filename:
        return _json_error('errors.bad_request', 400)
    max_bytes = app.config['MAX_APK_SIZE_MB'] * 1024 * 1024
    data = upload.read(max_bytes + 1)
    if len(data) > max_bytes:
        return _json_error('app_scan.apk_too_large', 413, mb=app.config['MAX_APK_SIZE_MB'])
    result = scan_apk(data, filename=upload.filename, lang=api_lang(),
                      vt_key=app.config['VIRUSTOTAL_API_KEY'])
    if result.get('status') == 'ok' or result.get('package'):
        _store_app_scan(user, result, 'apk')
    return jsonify(ok=True, **result)


@app.route('/api/apps/report')
@login_required
def api_apps_report():
    user = current_user()
    rows = (AppScan.query.filter_by(user_id=user.id)
            .order_by(AppScan.created_at.desc()).limit(50).all())

    def _load(raw):
        try:
            return json.loads(raw or '[]')
        except (TypeError, ValueError):
            return []

    items = [{'id': r.id, 'package': r.package, 'label': r.label, 'score': r.score,
              'level': r.level, 'verdict': r.verdict, 'source': r.source,
              'findings': _load(r.findings), 'permissions': _load(r.permissions),
              'time': time_ago(r.created_at)} for r in rows]
    return jsonify(ok=True, count=len(items), items=items)


# ==========================================================================
# API: الربط الجديد (دعوات + موافقة مزدوجة)
# ==========================================================================
def _invite_json(invite, guardian=None, child=None, external=True):
    return {
        'id': invite.id, 'code': invite.code, 'status': invite.status,
        'created_at': (invite.created_at.isoformat() + 'Z') if invite.created_at else None,
        'expires_at': (invite.expires_at.isoformat() + 'Z') if invite.expires_at else None,
        'expires_in': max(0, int((invite.expires_at - now_utc()).total_seconds())),
        'guardian': guardian.username if guardian else None,
        'child': child.username if child else None,
        'web_link': url_for('invite_page', code=invite.code, _external=external),
        'qr_data': url_for('invite_page', code=invite.code, _external=external),
    }


@app.route('/api/link/invite/create', methods=['POST'])
@guardian_required
def api_invite_create():
    user = current_user()
    ok, invite, payload = links.create_invite(
        user, app.config['INVITE_PER_DAY'], app.config['INVITE_TTL_HOURS'], client_ip())
    if not ok:
        return _json_error(invite, 429 if invite == 'link.too_many_attempts' else 400,
                           **payload)
    full = _invite_json(invite, guardian=user)
    full['message'] = tr('link.invite_created')
    return jsonify(ok=True, **full), 201


@app.route('/api/link/invite/<code>')
def api_invite_get(code):
    invite = links.get_invite(code)
    if not invite:
        return _json_error('link.invite_not_found', 404)
    guardian = db.session.get(User, invite.guardian_id)
    child = db.session.get(User, invite.protected_id) if invite.protected_id else None
    return jsonify(ok=True, **_invite_json(invite, guardian=guardian, child=child))


@app.route('/api/link/invite/accept', methods=['POST'])
@login_required
def api_invite_accept():
    user = current_user()
    if hit_limit('invite_accept:' + str(user.id), app.config['INVITE_MAX_ATTEMPTS'], timedelta(hours=1)):
        return _json_error('link.too_many_attempts', 429)
    d = request.get_json(silent=True) or {}
    invite = links.get_invite(d.get('code', ''))
    ok, key = links.accept_invite(
        user, invite, consent_text=str(d.get('consent_text') or ''),
        consent_version=str(d.get('consent_version') or app.config['CONSENT_VERSION']),
        ip=client_ip())
    if not ok:
        return _json_error(key, 400 if key != 'link.too_many_attempts' else 429)
    return jsonify(ok=True, message=tr(key), invite=_invite_json(invite))


@app.route('/api/link/invite/approve', methods=['POST'])
@guardian_required
def api_invite_approve():
    user = current_user()
    d = request.get_json(silent=True) or {}
    invite = links.get_invite(d.get('code', ''), for_guardian=user.id)
    ok, key = links.approve_invite(user, invite, client_ip())
    if not ok:
        return _json_error(key, 400)
    return jsonify(ok=True, message=tr(key), code=invite.code if invite else None)


@app.route('/api/link/invite/reject', methods=['POST'])
@guardian_required
def api_invite_reject():
    user = current_user()
    d = request.get_json(silent=True) or {}
    invite = links.get_invite(d.get('code', ''), for_guardian=user.id)
    ok, key = links.reject_invite(user, invite, client_ip())
    if not ok:
        return _json_error(key, 400)
    return jsonify(ok=True, message=tr(key))


@app.route('/api/link/pending')
@guardian_required
def api_link_pending():
    user = current_user()
    rows = links.pending_for_guardian(user.id)
    return jsonify(ok=True, invites=[_invite_json(r, guardian=user,
                                                  child=db.session.get(User, r.protected_id) if r.protected_id else None)
                                     for r in rows])


@app.route('/api/link/list')
@login_required
def api_link_list():
    user = current_user()
    guardians, protected = [], []
    for lk in links.links_as_protected(user.id):
        other = db.session.get(User, lk.guardian_id)
        if other:
            guardians.append({'link_id': lk.id, 'user_id': other.id, 'username': other.username, 'since': time_ago(lk.created_at),
                              'can_revoke': True})
    for lk in links.links_as_guardian(user.id):
        other = db.session.get(User, lk.protected_id)
        if other:
            protected.append({'link_id': lk.id, 'user_id': other.id, 'username': other.username, 'since': time_ago(lk.created_at)})
    return jsonify(ok=True, guardians=guardians, protected=protected,
                   limits={'children': user.max_children or 10, 'guardians': 3},
                   allow_child_revoke=bool(user.allow_child_revoke))


@app.route('/api/link/<int:link_id>/revoke', methods=['POST'])
@login_required
def api_link_revoke(link_id):
    user = current_user()
    ok, key = links.revoke_link(user, db.session.get(Link, link_id), client_ip())
    if not ok:
        return _json_error(key, 403 if key == 'link.remove_denied' else 404)
    return jsonify(ok=True, message=tr(key))


@app.route('/api/link/<int:link_id>/remove', methods=['POST'])
@login_required
def api_link_remove_id(link_id):
    user = current_user()
    ok, key = links.remove_link(user, db.session.get(Link, link_id), client_ip())
    if not ok:
        return _json_error(key, 403 if key == 'link.remove_denied' else 404)
    return jsonify(ok=True, message=tr(key))


@app.route('/api/link/remove', methods=['POST'])
@login_required
def api_link_remove():
    """توافق مع نسخ التطبيق القديمة (link_id في الجسم)"""
    user = current_user()
    d = request.get_json(silent=True) or {}
    try:
        link_id = int(d.get('link_id'))
    except (TypeError, ValueError):
        return _json_error('link.not_found', 404)
    ok, key = links.remove_link(user, db.session.get(Link, link_id), client_ip())
    if not ok:
        return _json_error(key, 403 if key == 'link.remove_denied' else 404)
    return jsonify(ok=True, message=tr(key))


@app.route('/api/link/audit')
@login_required
def api_link_audit():
    user = current_user()
    link_ids = {lk.id for lk in Link.query.filter((Link.guardian_id == user.id) |
                                                  (Link.protected_id == user.id)).all()}
    rows = (AuditLog.query.filter(((AuditLog.actor_id == user.id) |
                                   (AuditLog.target_id.in_(link_ids) & AuditLog.target_type.in_(('link', 'link_invite')))))
            .order_by(AuditLog.created_at.desc()).limit(50).all())
    return jsonify(ok=True, items=[{
        'id': r.id, 'action': r.action, 'target_type': r.target_type,
        'target_id': r.target_id, 'meta': links.parse_meta(r),
        'time': time_ago(r.created_at)} for r in rows])


@app.route('/api/link/code', methods=['POST'])
@login_required
def api_link_code():
    """كود الربط القديم (8 حروف) — محتفظين بيه للتوافق"""
    code = _new_pair_code(current_user())
    return jsonify(ok=True, code=code, expires_in=600)


@app.route('/api/link/join', methods=['POST'])
@login_required
def api_link_join():
    ok, val = _join_pair(current_user(), (request.get_json(silent=True) or {}).get('code', ''))
    if not ok:
        return jsonify(ok=False, error=val), (429 if 'كتير' in val or 'Too many' in val else 400)
    return jsonify(ok=True, guardian=val)


# ==========================================================================
# API: تحكم الإعلانات
# ==========================================================================
@app.route('/api/ads/settings', methods=['GET', 'PUT'])
@login_required
def api_ads_settings():
    user = current_user()
    d = request.get_json(silent=True) or {}
    if request.method == 'GET':
        child_id = d.get('child_id') or request.args.get('child_id', type=int) or user.id
    else:
        child_id = d.get('child_id') or user.id
    try:
        child_id = int(child_id)
    except (TypeError, ValueError):
        return _json_error('errors.bad_request', 400)
    if child_id != user.id and not links.active_link(user.id, child_id):
        return _json_error('link.not_found', 404)
    row = links.ads_for(child_id)
    if request.method == 'PUT':
        ok, key = links.update_ads(row, d, max_per_day=50)
        if not ok:
            return _json_error(key, 400)
        links.log(user.id, 'ads_update', 'ad_settings', row.id,
                  {'child_id': child_id}, client_ip())
        return jsonify(ok=True, message=tr(key), settings=links.ads_to_dict(row))
    return jsonify(ok=True, child_id=child_id, settings=links.ads_to_dict(row))


# ==========================================================================
# صفحات الويب الجديدة: دعوة + خصوصية
# ==========================================================================
@app.route('/invite/<code>', methods=['GET', 'POST'])
def invite_page(code):
    invite = links.get_invite(code)
    if not invite:
        return render_template('error.html', code=404, message=tr('link.invite_not_found')), 404
    guardian = db.session.get(User, invite.guardian_id)
    user = current_user()
    message = error = ''
    if request.method == 'POST':
        if not user:
            return redirect(url_for('login', next=url_for('invite_page', code=code)))
        if invite.guardian_id == user.id:
            error = tr('link.self_link')
        else:
            ok, key = links.accept_invite(
                user, invite, consent_text=tr('link.consent_body'),
                consent_version=app.config['CONSENT_VERSION'], ip=client_ip())
            if ok:
                message = tr(key)
            else:
                error = tr(key)
    return render_template('invite.html', invite=invite, guardian=guardian, user=user,
                           message=message, error=error,
                           consent_text=tr('link.consent_body'),
                           consent_version=app.config['CONSENT_VERSION'])


# ==========================================================================
# Health / config العام (للتطبيق + UptimeRobot)
# ==========================================================================
@app.route('/healthz')
def healthz():
    return 'ok', 200


@app.route('/api/health')
def api_health():
    return jsonify(ok=True, status='healthy', time=now_utc_iso(), version='2.0.0')


@app.route('/api/config')
def api_config():
    lang = api_lang()
    return jsonify(
        ok=True, version='2.0.0',
        countries={code: {'name': c[0] if lang == 'ar' else c[3], 'dial': c[1], 'police': c[2]}
                   for code, c in COUNTRIES.items()},
        langs=list(app.config['LANGS']),
        consent_version=app.config['CONSENT_VERSION'],
        limits={'children': app.config['MAX_CHILDREN'], 'guardians': app.config['MAX_GUARDIANS'],
                'invite_ttl_hours': app.config['INVITE_TTL_HOURS'],
                'apk_size_mb': app.config['MAX_APK_SIZE_MB']},
        plans={key: {'monthly': val['monthly'], 'yearly': val['yearly'],
                     'name': val.get(lang) or val['ar']} for key, val in PLAN_INFO.items()},
        support_email=app.config['SUPPORT_EMAIL'])


# ==========================================================================
# أخطاء
# ==========================================================================
@app.errorhandler(404)
def not_found(_e):
    if is_api():
        return _json_error('errors.not_found', 404)
    return render_template('error.html', code=404, message=tr('errors.not_found')), 404


@app.errorhandler(413)
def too_large(_e):
    if is_api():
        return _json_error('errors.too_large', 413)
    return render_template('error.html', code=413, message=tr('errors.too_large')), 413


@app.errorhandler(500)
def server_error(e):
    app.logger.exception('Unhandled error: %s', e)
    db.session.rollback()
    if is_api():
        return _json_error('errors.server', 500)
    return render_template('error.html', code=500, message=tr('errors.server')), 500


@app.errorhandler(HTTPException)
def http_error(e):
    if is_api():
        return _json_error('errors.http', e.code or 500), e.code or 500
    return render_template('error.html', code=e.code, message=e.description), e.code


if __name__ == '__main__':
    # الـ debug بيتفعل بس لو FLASK_DEBUG=1 (ما تسيبوش شغال على الاستضافة)
    app.run(host=os.environ.get('HOST', '127.0.0.1'),
            port=int(os.environ.get('PORT', '5000')),
            debug=os.environ.get('FLASK_DEBUG') == '1')
