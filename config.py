"""إعدادات SafeGuard في مكان واحد.

كل حاجة بتتقرأ من متغيرات البيئة، والقيم الافتراضية آمنة للتشغيل المحلي.
ممنوع تحط مفاتيح سرية في الكود ده (بيترفع على Git).
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def env_bool(name, default=False):
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on')


def env_int(name, default, minimum=None, maximum=None):
    try:
        value = int(str(os.environ.get(name, '')).strip())
    except (TypeError, ValueError):
        return default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def database_uri():
    """SQLite محلياً، أو PostgreSQL لما DATABASE_URL يكون متاحاً.

    الصيغة القديمة postgres:// بتتحول لـ postgresql:// لأن SQLAlchemy 2 مش بيقبلها.
    """
    uri = (os.environ.get('DATABASE_URL') or '').strip()
    if not uri:
        return 'sqlite:///safeguard.db'
    if uri.startswith('postgres://'):
        uri = 'postgresql://' + uri[len('postgres://'):]
    return uri


class BaseConfig:
    # ---------- أساسيات Flask ----------
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-change-me')
    ENV_NAME = os.environ.get('FLASK_ENV', 'production')

    # ---------- قاعدة البيانات ----------
    SQLALCHEMY_DATABASE_URI = database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = (
        {'connect_args': {'check_same_thread': False, 'timeout': 30}}
        if database_uri().startswith('sqlite')
        else {'pool_pre_ping': True, 'pool_recycle': 280, 'pool_size': 10}
    )

    # ---------- الجلسات والكوكيز ----------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get('COOKIE_SAMESITE', 'Lax')
    SESSION_COOKIE_SECURE = env_bool('COOKIE_SECURE', False)
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 30

    # ---------- اللغات ----------
    LANGS = ('ar', 'en')
    DEFAULT_LANG = os.environ.get('DEFAULT_LANG', 'ar')

    # ---------- الموبايل / OTP ----------
    OTP_TTL = env_int('OTP_TTL', 10 * 60, 60, 60 * 60)
    OTP_MAX_ATTEMPTS = env_int('OTP_MAX_ATTEMPTS', 5, 1, 20)
    OTP_COOLDOWN = env_int('OTP_COOLDOWN', 60, 10, 600)
    OTP_PER_PHONE_DAY = env_int('OTP_PER_PHONE_DAY', 5, 1, 50)
    OTP_PER_IP_HOUR = env_int('OTP_PER_IP_HOUR', 10, 1, 200)
    SMS_PROVIDER = os.environ.get('SMS_PROVIDER', 'console')

    # ---------- الربط (Link / Invite) ----------
    MAX_CHILDREN = env_int('MAX_CHILDREN', 10, 1, 50)
    MAX_GUARDIANS = env_int('MAX_GUARDIANS', 3, 1, 20)
    INVITE_TTL_HOURS = env_int('INVITE_TTL_HOURS', 24, 1, 168)
    INVITE_PER_DAY = env_int('INVITE_PER_DAY', 20, 1, 200)
    INVITE_MAX_ATTEMPTS = env_int('INVITE_MAX_ATTEMPTS', 10, 1, 100)
    CONSENT_VERSION = os.environ.get('CONSENT_VERSION', '2026-11-1')

    # ---------- فحص الروابط ----------
    # (مهلة بالثواني، أقصى عدد تحويلات)
    SCAN_MODES = {
        'quick': (4, 2),
        'normal': (6, 5),
        'full': (10, 5),
    }
    SCAN_PER_HOUR = env_int('SCAN_PER_HOUR', 60, 1, 1000)
    GOOGLE_SAFE_BROWSING_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    URLHAUS_ENABLED = env_bool('SF_URLHAUS_ENABLED', True)
    SCANNER_USER_AGENT = os.environ.get('SCANNER_USER_AGENT', 'SafeGuardScanner/2.0')

    # ---------- فحص التطبيقات ----------
    MAX_APK_SIZE_MB = env_int('MAX_APK_SIZE_MB', 50, 1, 200)
    APP_SCAN_PER_HOUR = env_int('APP_SCAN_PER_HOUR', 60, 1, 500)

    # ---------- إشعارات FCM ----------
    FCM_PROJECT_ID = os.environ.get('FCM_PROJECT_ID', '')
    FCM_CREDENTIALS = os.environ.get('FCM_CREDENTIALS', '')

    # ---------- CORS ----------
    # للتجربة: '*' — قبل النشر حط دومينك فقط
    ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*')

    # ---------- معلومات التطبيق ----------
    APP_NAME = 'SafeGuard'
    SUPPORT_EMAIL = os.environ.get('SUPPORT_EMAIL', 'support@safeguard.app')
    PRIVACY_URL = os.environ.get('PRIVACY_URL', '')

    # ---------- الاشتراكات (بدون أي بيانات كروت على السيرفر) ----------
    PLANS = {
        'free': {'monthly': 0, 'yearly': 0},
        'monthly': {'monthly': 49, 'yearly': 0},
        'yearly': {'monthly': 0, 'yearly': 399},
        'family': {'monthly': 79, 'yearly': 699},
    }


class DevConfig(BaseConfig):
    ENV_NAME = 'development'


class TestConfig(BaseConfig):
    ENV_NAME = 'testing'
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_ENGINE_OPTIONS = {'connect_args': {'check_same_thread': False}}
    WTF_CSRF_ENABLED = False
    SERVER_NAME = 'localhost'


class ProdConfig(BaseConfig):
    ENV_NAME = 'production'
    PREFERRED_URL_SCHEME = 'https'


_CONFIGS = {'development': DevConfig, 'testing': TestConfig, 'production': ProdConfig}


def get_config(name=None):
    """يرجّع كلاس الإعدادات المناسب (للتجربة/التطوير/النشر)"""
    key = (name or os.environ.get('FLASK_ENV') or 'production').strip().lower()
    return _CONFIGS.get(key, ProdConfig)
