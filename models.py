"""جداول قاعدة البيانات (SQLAlchemy).

كل الجداول هنا، والموديلات القديمة محتفظة بنفس أسماء الأعمدة علشان
قاعدة البيانات الموجودة تفضل شغالة من غير ما نمسح أي بيانات.
"""
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

PERMISSION_HINT = 'google play families policy: أقل صلاحيات ممكنة'


def now_utc():
    """وقت UTC نقي (naive) - نفس الصيغة اللي متخزنة في القاعدة"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat() if dt else None


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), default='')
    phone = db.Column(db.String(20), default='')
    role = db.Column(db.String(20), default='child')          # 'child' أو 'parent'
    country = db.Column(db.String(2), default='')             # EG, SA, AE...
    phone_verified = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(255), default='')
    lang = db.Column(db.String(2), default='ar')
    # إعدادات الإشعارات (صفحة /settings بتحفظها فعلاً)
    notify_sos = db.Column(db.Boolean, default=True)
    notify_scans = db.Column(db.Boolean, default=True)
    # حدود الرقابة
    max_children = db.Column(db.Integer, default=10)
    allow_child_revoke = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now_utc)


class SOSEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    accuracy = db.Column(db.Float, default=0)
    status = db.Column(db.String(10), default='active')        # 'active' / 'ended'
    created_at = db.Column(db.DateTime, default=now_utc)
    updated_at = db.Column(db.DateTime, default=now_utc)
    ended_at = db.Column(db.DateTime)


class PhoneCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    code_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    sent_at = db.Column(db.DateTime, default=now_utc)


class SmsLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), index=True)
    ip = db.Column(db.String(64), index=True)
    created_at = db.Column(db.DateTime, default=now_utc, index=True)


class Link(db.Model):
    """ربط نشط بين ولي أمر (guardian) وشخص محمي (protected).

    فك الربط مش بيمسح الصف: بنسجّل status/ended_by/end_reason/ended_at
    علشان سجل العمليات (Audit) يفضل كامل.
    """
    id = db.Column(db.Integer, primary_key=True)
    guardian_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    protected_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(12), default='active')       # active/revoked/removed
    ended_by = db.Column(db.Integer)                          # user id اللي أنهى الربط
    end_reason = db.Column(db.String(30), default='')
    ended_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=now_utc)


class LinkInvite(db.Model):
    """دعوة ربط: ولي الأمر ينشئها، الطفل يقبلها، وولي الأمر يوافق (موافقة مزدوجة)."""
    id = db.Column(db.Integer, primary_key=True)
    guardian_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    code = db.Column(db.String(12), unique=True, nullable=False, index=True)
    status = db.Column(db.String(12), default='pending')      # pending/accepted/approved/rejected/expired/cancelled
    protected_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=now_utc)
    expires_at = db.Column(db.DateTime, nullable=False)
    accepted_at = db.Column(db.DateTime)
    approved_at = db.Column(db.DateTime)
    rejected_at = db.Column(db.DateTime)


class GuardianConsent(db.Model):
    """موافقة صريحة من الطفل قبل أي ربط (مطلوبة لـ COPPA / GDPR-K / Play Families)."""
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('link.id'), index=True)
    child_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    guardian_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    consent_version = db.Column(db.String(20), default='')
    text = db.Column(db.String(500), default='')
    consented_at = db.Column(db.DateTime, default=now_utc)
    ip = db.Column(db.String(64), default='')
    revoked_at = db.Column(db.DateTime)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, index=True)
    action = db.Column(db.String(40), nullable=False, index=True)
    target_type = db.Column(db.String(20), default='')
    target_id = db.Column(db.Integer)
    meta = db.Column(db.Text, default='{}')
    ip = db.Column(db.String(64), default='')
    created_at = db.Column(db.DateTime, default=now_utc, index=True)


class AdSettings(db.Model):
    """تحكم ولي الأمر في إعلانات الطفل (Play Families: إعلانات عائلية فقط)."""
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=False)
    max_per_day = db.Column(db.Integer, default=5)
    blocked_categories = db.Column(db.Text, default='[]')
    allowed_categories = db.Column(db.Text, default='[]')
    child_safe_only = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=now_utc)


class AppScan(db.Model):
    """نتيجة فحص تطبيق (بيانات من الجهاز أو ملف APK مرفوع)."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    source = db.Column(db.String(10), default='device')       # device / apk
    package = db.Column(db.String(200), default='')
    label = db.Column(db.String(200), default='')
    sha256 = db.Column(db.String(64), default='', index=True)
    score = db.Column(db.Integer, default=0)
    level = db.Column(db.String(10), default='safe')
    verdict = db.Column(db.String(12), default='safe')
    findings = db.Column(db.Text, default='[]')
    permissions = db.Column(db.Text, default='[]')
    apis = db.Column(db.Text, default='[]')
    sources = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=now_utc, index=True)


class PairCode(db.Model):
    """(قديم) كود ربط لولي الأمر - محتفظين بيه علشان النسخ القديمة من التطبيق."""
    id = db.Column(db.Integer, primary_key=True)
    guardian_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code_hash = db.Column(db.String(64), nullable=False)
    used = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=False)


class PairFail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=now_utc)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    kind = db.Column(db.String(10), default='info')            # 'sos' أو 'info'
    title = db.Column(db.String(120), nullable=False)
    body = db.Column(db.String(300), default='')
    event_token = db.Column(db.String(64), default='')
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_utc)


class DeviceToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    token = db.Column(db.String(300), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=now_utc)


class ScanLog(db.Model):
    __tablename__ = 'scan_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(10), default='normal')
    safe = db.Column(db.Boolean, default=False)
    msg = db.Column(db.String(300), default='')
    score = db.Column(db.Integer, default=0)
    level = db.Column(db.String(10), default='')
    final_url = db.Column(db.String(500), default='')
    sources = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=now_utc, index=True)


class AppReport(db.Model):
    """تقرير التطبيقات اللي الجهاز نفسه بعتها بعد موافقة صاحب الحساب."""
    __tablename__ = 'app_report'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    app_count = db.Column(db.Integer, default=0)
    names = db.Column(db.Text, default='[]')
    created_at = db.Column(db.DateTime, default=now_utc, index=True)


class RateHit(db.Model):
    __tablename__ = 'rate_hit'
    id = db.Column(db.Integer, primary_key=True)
    bucket = db.Column(db.String(80), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=now_utc, index=True)


class SubscriptionRequest(db.Model):
    """طلب تفعيل باقة - بنخزن الباقة والطلب بس، وممنوع تخزين بيانات كروت."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    plan = db.Column(db.String(20), nullable=False)
    period = db.Column(db.String(10), default='monthly')
    status = db.Column(db.String(12), default='pending')       # pending/active/cancelled
    note = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=now_utc)
