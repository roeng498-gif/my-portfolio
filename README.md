# SafeGuard — باك إند الحماية الأسرية

تطبيق حماية للأطفال: فحص روابط وتطبيقات، نجدة SOS مع تتبع مباشر، رقابة والدية بموافقة مزدوجة
وحق الطفل في إلغاء الرقابة، تحكم في الإعلانات، ودعم عربي/إنجليزي.

> **مهم:** الدفعة دي هي الباك إند (المرحلة 1). القوالب والـ Flutter ليهم ملفات منفصلة.

---

## 1) الملفات

| الملف | الوظيفة |
|---|---|
| `app.py` | كل المسارات: ويب + API تطبيق، الجلسات، OTP، SOS، الإشعارات |
| `config.py` | كل الإعدادات من متغيرات البيئة + خطط الاشتراك + الحدود |
| `models.py` | كل جداول قاعدة البيانات (SQLAlchemy) |
| `messages.py` | كل الرسائل عربي/إنجليزي + دالة `t()` |
| `url_scanner.py` | فحص روابط متعدد الطبقات (heuristics + Safe Browsing + URLhaus + VirusTotal) |
| `app_scanner.py` | فحص تطبيقات (صلاحيات + APIs + تركيبات خطيرة + VirusTotal) و APK اختياري |
| `link_service.py` | منطق الربط: دعوات، موافقة مزدوجة، إلغاء، حدود، Audit |
| `templates/` | صفحات الويب |
| `static/style.css` | التنسيق |
| `tests/` | اختبارات الباك إند + المحركات |
| `render.yaml` / `Procfile` | النشر |
| `.env.example` | كل متغيرات البيئة المطلوبة |

## 2) التشغيل المحلي

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

copy .env.example .env          # وعدّل SECRET_KEY
python app.py
```

بعد كده افتح `http://127.0.0.1:5000`.

للإنتاج على ويندوز مش بنستخدم `app.run`:

```bash
gunicorn app:app --workers 2 --threads 4 --timeout 120
```

### الاختبارات

```bash
py -3.14 tests/test_app.py          # كل المسارات (بدون إنترنت)
py -3.14 tests/test_url_scanner.py
py -3.14 tests/test_app_scanner.py
```

## 3) متغيرات البيئة المهمة

| المتغير | الافتراضي | ملاحظات |
|---|---|---|
| `SECRET_KEY` | `dev-only-change-me` | **لازم تغيّره قبل النشر** |
| `DATABASE_URL` | SQLite محلي | PostgreSQL على الاستضافة |
| `COOKIE_SECURE` | `false` | خلّيه `true` على HTTPS |
| `GOOGLE_SAFE_BROWSING_KEY` | فاضي | بدون مفتاح الطبقة دي بتتخطى |
| `VIRUSTOTAL_API_KEY` | فاضي | 500 طلب/يوم مجاناً |
| `SMS_PROVIDER` | `console` | `twilio` للإرسال الحقيقي |
| `MAX_APK_SIZE_MB` | `50` | حد رفع APK |
| `CONSENT_VERSION` | `2026-11-1` | نسخة نص موافقة الطفل |

المفاتيح السرية ممنوع تتحط في الكود — كلها من البيئة.

## 4) نظام الربط

```
ولي أمر ينشئ دعوة (كود 6 أرقام + QR + رابط /invite/<code>)
        ↓
الطفل يفتح الرابط أو يدخل الكود ويقبل (موافقة صريحة + Audit)
        ↓
ولي أمر يوافق  →  Link.status = active
```

* حدود: **10 أطفال** لولي الأمر، **3 أولياء أمور** للطفل، الدعوة **24 ساعة**، **20 دعوة/يوم**.
* الطفل يلغي في أي وقت: `POST /api/link/<id>/revoke` — ولي الأمر بيوصله إشعار، والصف مش بيتمسح (سجل كامل).
* كل عملية بتتسجل في `AuditLog`.

### API الربط

```
POST /api/link/invite/create      إنشاء دعوة (ولي أمر)
GET  /api/link/invite/<code>      بيانات الدعوة (عام)
POST /api/link/invite/accept      قبول الطفل
POST /api/link/invite/approve     موافقة ولي الأمر
POST /api/link/invite/reject      رفض
GET  /api/link/pending            الدعوات المعلقة
GET  /api/link/list               الروابط النشطة
POST /api/link/<id>/revoke        إلغاء الطفل ⭐
POST /api/link/<id>/remove        فك الربط من أي طرف
GET  /api/link/audit              سجل العمليات
```

## 5) فحص الروابط

الطبقات: heuristics محلية (أكثر من 11 فحص) + Google Safe Browsing + URLhaus + VirusTotal.
التصنيف: `safe` 0-19، `medium` 20-44، `high` 45-69، `critical` 70+.

```json
POST /api/scan  {"url": "https://...", "type": "quick|normal|full"}
{
  "ok": true, "safe": false, "level": "critical", "score": 85,
  "msg": "تنبيه: ...", "warnings": ["..."], "sources": {"google": {"status": "hit"}},
  "final_url": "https://..."
}
```

مفيش مفاتيح؟ الفحص المحلي شغال، والطبقات الخارجية بترجع `disabled` — مفيش أعطال.

## 6) فحص التطبيقات

```
POST /api/scan/app        {"package": "...", "permissions": [...], "apis": [...]}
POST /api/scan/apps/bulk  {"apps": [{...}, ...]}   (حد 50)
POST /api/scan/apk        multipart file=app.apk  (حد MAX_APK_SIZE_MB)
GET  /api/apps/report     آخر النتائج
```

* فحص البيانات شغال على أي استضافة (من غير مكتبات ثقيلة).
* فحص APK العميق محتاج `pip install -r requirements-apk.txt`؛ لو مش متثبت بيرجّع `unavailable` مش 500.
* بيرجع صلاحيات خطيرة، تركيبات (SMS stealer، Accessibility، Overlay...)، درجة 0-100، وverdict.

## 7) الطوارئ

```
POST /api/sos                 {"lat": .., "lng": ..}   (حد 5/ساعة)
GET  /api/sos/active
GET  /api/sos/history
POST /api/sos/<token>/update  تحديث الموقع (مفتوح بالتوكن، 8 ثواني بين كل تحديث)
POST /api/sos/<token>/stop
GET  /track/<token>           صفحة ولي الأمر (من غير دخول)
```

لما الطفل يبعت نجدة: إشعار داخلي لكل ولي أمر + FCM لو مضبوط. الموقع مش بيتعرض بعد إنهاء التتبع.

## 8) الإعلانات (Play Families)

```
GET /api/ads/settings?child_id=..
PUT /api/ads/settings  {"child_id": .., "enabled": true, "max_per_day": 5,
                        "blocked_categories": ["games"], "child_safe_only": true}
```

مقفولة افتراضيًا، وولي الأمر بس اللي يقدر يغيّرها، والحد الأقصى 50 إعلان/يوم.

## 9) الأمان

* SSRF: كل تحويلات الروابط بتتحقق من إن العنوان عام (مش 10.x / 192.168.x / 169.254.x …).
* كلمات المرور: `pbkdf2` من Werkzeug، ومفيش أي بيانات كروت بتتخزن (الاشتراكات بتتسجّل كطلب بس).
* Rate limit على: الدخول، التسجيل، الفحص، السجنالات، الدعوات، النجدة.
* OTP: كود 6 أرقام متخزن كـ HMAC، صلاحية 10 دقايق، 5 محاولات، وإعادة إرسال كل 60 ثانية.
* موافقة الطفل متسجلة بنصها ووقتها وIP ونسخة النص.
* حذف الحساب: `DELETE /api/me` بيمسح كل بيانات المستخدم.

## 10) النشر على Render

1. ارفع المشروع على GitHub.
2. Render → New → Blueprint → اختار `render.yaml`.
3. حط `SECRET_KEY` (Render بيولّد واحد) والمفاتيح الاختيارية.
4. اربط UptimeRobot على `https://<app>.onrender.com/healthz` كل 5 دقايق (الباقة المجانية بتنام).

مقاسات الاستضافة المجانية: 750 ساعة/شهر + قاعدة PostgreSQL 500MB — كفاية للتجربة 10 أيام.

## 11) اللغات (عربي/إنجليزي)

* كل رسائل السيرفر والقوالب من `messages.py` (٣٢٧ مفتاح × لغتين) عبر `t()`.
* التبديل: `?lang=en` في أي رابط، أو `/lang/en`، أو من صفحة الإعدادات، أو `Accept-Language` في الـ API.
* الاتجاه (RTL/LTR) بيتغير تلقائيًا حسب اللغة.
* تدقيق الترجمة: `py -3.14 tests/check_i18n.py` (يتأكد إن كل مفتاح في القوالب موجود في اللغتين).

## 12) اللي لسه محتاج شغل

* [x] القوالب: كل الصفحات عربي/إنجليزي + لوحة تحكم ببيانات حقيقية (كانت أرقام وهمية).
* [ ] مشروع Flutter: `pubspec.yaml` + `main.dart` + `api_service.dart` (مش موجودين في المجلد).
* [ ] بوابة دفع حقيقية (Paymob/Fawry) — الصفحة دلوقتي بتسجّل طلب بس وممنوع تدخل بيانات كارت.
* [ ] ترجمة نصوص الإشعارات المخزنة (حاليًا عربي وقت الإنشاء).
* [ ] APK عميق (Androguard) على VPS + MobSF.
* [ ] مزامنة سجل الفحص مع الاحتفاظ 90 يوم (تنظيف دوري).
