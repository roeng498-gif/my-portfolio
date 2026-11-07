import ipaddress
import secrets
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# إعداد قاعدة البيانات وتفعيل الاتصال
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///safeguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


def now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def time_ago(dt):
    """يحول الوقت لنص عربي بسيط: منذ 5 دقائق"""
    if not dt:
        return ''
    secs = int((now_utc() - dt).total_seconds())
    if secs < 60:
        return 'الآن'
    if secs < 3600:
        return f'منذ {secs // 60} دقيقة'
    if secs < 86400:
        return f'منذ {secs // 3600} ساعة'
    return f'منذ {secs // 86400} يوم'


# نموذج جدول المستخدم الشامل (يدعم الاسم، البريد، الهاتف، ونوع الحساب للرقابة الوالدية)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), default='')
    phone = db.Column(db.String(20), default='')
    role = db.Column(db.String(20), default='child')  # 'child' أو 'parent'


# جدول حالات الطوارئ (SOS) وتتبع الموقع
class SOSEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)  # رمز سري في رابط ولي الأمر
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    accuracy = db.Column(db.Float, default=0)
    status = db.Column(db.String(10), default='active')  # 'active' أو 'ended'
    created_at = db.Column(db.DateTime, default=now_utc)
    updated_at = db.Column(db.DateTime, default=now_utc)


# تهيئة قاعدة البيانات (create_all بيضيف الجداول الجديدة بس ومبيمسحش القديم)
with app.app_context():
    db.create_all()
    if not User.query.first():
        default_user = User(
            username='مستخدم Safe Guard',
            email='user@safeguard.com',
            phone='01000000000',
            role='child'
        )
        db.session.add(default_user)
        db.session.commit()


# 1. مسار لوحة التحكم الرئيسية (Index)
@app.route('/', methods=['GET', 'POST'])
def index():
    user = User.query.first()
    return render_template('index.html', user=user)


# ================== الفحص والحماية ==================
UA = {'User-Agent': 'SafeGuardScanner/1.0'}
SCAN_MODES = {
    # (مهلة بالثواني، أقصى عدد تحويلات)
    'quick': (4, 2),
    'normal': (6, 5),
    'full': (10, 5),
}


class BlockedURL(Exception):
    pass


class UnreachableURL(Exception):
    pass


def is_public_host(hostname):
    """True = عنوان عام، False = عنوان داخلي/خاص (ممنوع)، None = مش موجود"""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        if not ip.is_global:
            return False
    return True


def safe_fetch(url, timeout, max_redirects):
    """يفتح الرابط ويتبع التحويلات يدوياً، ويمنع أي عنوان داخلي (حماية SSRF)"""
    hops = [url]
    for _ in range(max_redirects + 1):
        host = urlparse(url).hostname
        if not host:
            raise UnreachableURL()
        public = is_public_host(host)
        if public is None:
            raise UnreachableURL()
        if public is False:
            raise BlockedURL()
        r = requests.get(url, timeout=timeout, allow_redirects=False, headers=UA, stream=True)
        r.close()
        if r.is_redirect:
            url = urljoin(url, r.headers.get('Location', ''))
            hops.append(url)
            continue
        return r, hops
    raise UnreachableURL()


def url_warnings(original, final_url):
    """فحوصات إضافية للفحص الشامل"""
    warnings = []
    p_final = urlparse(final_url)
    host_final = (p_final.hostname or '').removeprefix('www.')
    host_orig = (urlparse(original).hostname or '').removeprefix('www.')

    if p_final.scheme != 'https':
        warnings.append('الرابط لا يستخدم تشفير HTTPS')
    if '@' in original:
        warnings.append('الرابط يحتوي على @ وهي حيلة شائعة في روابط التصيد')
    try:
        ipaddress.ip_address(host_final)
        warnings.append('الرابط يستخدم عنوان IP بدل اسم موقع')
    except ValueError:
        pass
    if len(original) > 200:
        warnings.append('الرابط طويل بشكل غير معتاد')
    if host_orig != host_final:
        warnings.append(f'الرابط يحوّلك إلى موقع مختلف ({host_final})')
    return warnings


# 2. مسار الفحص
@app.route('/scan', methods=['GET', 'POST'])
def scan():
    user = User.query.first()
    scan_result = None
    scanned_url = ""
    scan_type = 'normal'

    if request.method == 'POST':
        scanned_url = request.form.get('url_to_scan', '').strip()
        scan_type = request.form.get('scan_type', 'normal')
        if scan_type not in SCAN_MODES:
            scan_type = 'normal'

        if scanned_url:
            if not scanned_url.startswith(('http://', 'https://')):
                scanned_url = 'https://' + scanned_url
            timeout, max_redirects = SCAN_MODES[scan_type]

            try:
                r, hops = safe_fetch(scanned_url, timeout, max_redirects)
                warnings = url_warnings(hops[0], hops[-1]) if scan_type == 'full' else []

                if r.status_code >= 400:
                    scan_result = {"safe": False, "msg": f"تحذير! الرابط أعاد استجابة غير طبيعية (كود: {r.status_code})."}
                elif warnings:
                    scan_result = {"safe": False, "msg": "تنبيه: " + " • ".join(warnings)}
                else:
                    scan_result = {"safe": True, "msg": f"الرابط متاح ويعمل (كود الاستجابة: {r.status_code})."}
            except BlockedURL:
                scan_result = {"safe": False, "msg": "تم رفض الفحص: الرابط يشير إلى عنوان داخلي أو خاص."}
            except (UnreachableURL, requests.exceptions.RequestException):
                scan_result = {"safe": False, "msg": "تحذير! الرابط غير متاح أو غير موجود، وقد يكون موقعاً وهمياً أو مغلقاً."}

    return render_template('scan.html', user=user, scan_result=scan_result,
                           scanned_url=scanned_url, scan_type=scan_type)


# ================== الطوارئ (SOS) وتتبع الموقع ==================
# 3. صفحة زر الطوارئ (الزر في لوحة التحكم بيبعت POST فيبدأ العد التنازلي تلقائياً)
@app.route('/sos', methods=['GET', 'POST'])
def sos():
    user = User.query.first()
    auto_trigger = request.method == 'POST'
    return render_template('sos.html', user=user, auto_trigger=auto_trigger)


def _valid_coords(data):
    try:
        lat = float(data.get('lat'))
        lng = float(data.get('lng'))
        acc = float(data.get('accuracy') or 0)
    except (TypeError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        return None
    return lat, lng, acc


# إنشاء حالة طوارئ جديدة
@app.route('/api/sos', methods=['POST'])
def api_sos_create():
    user = User.query.first()
    coords = _valid_coords(request.get_json(silent=True) or {})
    if not coords:
        return jsonify(ok=False, error='إحداثيات غير صالحة'), 400
    lat, lng, acc = coords
    ev = SOSEvent(user_id=user.id, token=secrets.token_urlsafe(16), lat=lat, lng=lng, accuracy=acc)
    db.session.add(ev)
    db.session.commit()
    return jsonify(ok=True, token=ev.token, track_url=url_for('track', token=ev.token, _external=True))


# تحديث الموقع أثناء التتبع
@app.route('/api/sos/<token>/update', methods=['POST'])
def api_sos_update(token):
    ev = SOSEvent.query.filter_by(token=token).first_or_404()
    if ev.status != 'active':
        return jsonify(ok=False, error='انتهى التتبع'), 400
    coords = _valid_coords(request.get_json(silent=True) or {})
    if not coords:
        return jsonify(ok=False, error='إحداثيات غير صالحة'), 400
    ev.lat, ev.lng, ev.accuracy = coords
    ev.updated_at = now_utc()
    db.session.commit()
    return jsonify(ok=True)


# إنهاء التتبع
@app.route('/api/sos/<token>/stop', methods=['POST'])
def api_sos_stop(token):
    ev = SOSEvent.query.filter_by(token=token).first_or_404()
    ev.status = 'ended'
    db.session.commit()
    return jsonify(ok=True)


# بيانات الموقع لصفحة ولي الأمر (لو التتبع انتهى مبنرجعش الإحداثيات)
@app.route('/api/track/<token>')
def api_track(token):
    ev = SOSEvent.query.filter_by(token=token).first_or_404()
    if ev.status != 'active':
        return jsonify(status='ended')
    return jsonify(status='active', lat=ev.lat, lng=ev.lng,
                   accuracy=ev.accuracy, updated=time_ago(ev.updated_at))


# صفحة ولي الأمر
@app.route('/track/<token>')
def track(token):
    ev = SOSEvent.query.filter_by(token=token).first_or_404()
    owner = db.session.get(User, ev.user_id)
    return render_template('track.html', ev=ev, owner=owner, updated=time_ago(ev.updated_at))


# 4. مسار الاشتراكات (يدعم الباقة الشهرية والسنوية)
@app.route('/subscriptions', methods=['GET', 'POST'])
def subscriptions():
    user = User.query.first()
    sub_message = ""
    selected_plan = ""
    show_payment = False

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'select_plan':
            plan_type = request.form.get('plan')
            if plan_type == 'monthly':
                selected_plan = "الاشتراك الشهري (4$)"
            elif plan_type == 'yearly':
                selected_plan = "الاشتراك السنوي (80$)"
            show_payment = True

        elif action == 'confirm_payment':
            plan_name = request.form.get('plan_name')
            sub_message = f"تم إتمام الدفع بنجاح وتفعيل {plan_name} لحسابك!"
            show_payment = False

    return render_template('subscriptions.html', user=user, sub_message=sub_message,
                           selected_plan=selected_plan, show_payment=show_payment)


# 5. مسار الملف الشخصي
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user = User.query.first()
    if request.method == 'POST':
        user.username = request.form.get('username', user.username)
        user.email = request.form.get('email', user.email)
        user.phone = request.form.get('phone', user.phone)
        user.role = request.form.get('role', user.role)
        db.session.commit()
    return render_template('profile.html', user=user)


# 6. مسار الرقابة الوالدية
@app.route('/parental', methods=['GET', 'POST'])
def parental():
    user = User.query.first()
    if request.method == 'POST':
        new_role = request.form.get('role')
        if new_role:
            user.role = new_role
            db.session.commit()
    return render_template('parental.html', user=user)


# 7. مسار الإشعارات والتنبيهات (فيها حالات الطوارئ الحقيقية من قاعدة البيانات)
@app.route('/notifications', methods=['GET', 'POST'])
def notifications():
    user = User.query.first()
    alerts = []

    recent_sos = SOSEvent.query.order_by(SOSEvent.created_at.desc()).limit(5).all()
    for ev in recent_sos:
        alerts.append({
            "type": "danger",
            "title": "تم إرسال تنبيه طوارئ",
            "desc": "تم إرسال الموقع الجغرافي ومشاركة رابط التتبع" + (" (التتبع مستمر)" if ev.status == 'active' else " (انتهى التتبع)"),
            "time": time_ago(ev.created_at),
        })

    alerts += [
        {"type": "safe", "title": "اكتمال الفحص التلقائي", "desc": "الجهاز آمن وخالٍ من التطبيقات أو الروابط الضارة", "time": "منذ ساعة"},
        {"type": "info", "title": "تحديث قاعدة البيانات الأمنية", "desc": "تم تحديث جدار الحماية وقواعد الأمان بنجاح", "time": "منذ 3 ساعات"},
    ]
    return render_template('notifications.html', user=user, alerts=alerts)


# 8. مسار الإعدادات
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    user = User.query.first()
    settings_saved = False
    if request.method == 'POST':
        settings_saved = True
    return render_template('settings.html', user=user, settings_saved=settings_saved)


# 9. مسار تسجيل الخروج
@app.route('/logout')
def logout():
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)