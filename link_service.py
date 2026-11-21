"""منطق الربط بين ولي الأمر والطفل.

القواعد المتفق عليها:
  * 3 طرق للربط: كود 6 أرقام، QR، رابط دعوة.
  * موافقة مزدوجة: ولي الأمر ينشئ دعوة ← الطفل يقبل (موافقة صريحة) ← ولي الأمر يوافق.
  * الطفل يقدر يلغي الرقابة في أي وقت، وولي الأمر بيوصله إشعار (COPPA / GDPR-K / Play).
  * حدود: 10 أطفال لولي الأمر، 3 أولياء أمور للطفل، الدعوة 24 ساعة، 20 دعوة يومياً.

الدوال بترجّع (نجح؟، مفتاح رسالة) والمفاتيح بتترجم في app.py بـ t().
"""
import json
import secrets
from datetime import timedelta

from models import (AuditLog, AdSettings, GuardianConsent, Link, LinkInvite,
                    Notification, User, db, now_utc)


# --------------------------------------------------------------------------
# سجل العمليات
# --------------------------------------------------------------------------
def log(actor_id, action, target_type='', target_id=None, meta=None, ip='', commit=True):
    row = AuditLog(actor_id=actor_id, action=action, target_type=target_type,
                   target_id=target_id, meta=json.dumps(meta or {}, ensure_ascii=False)[:2000], ip=ip or '')
    db.session.add(row)
    if commit:
        db.session.commit()
    return row


def parse_meta(row):
    try:
        return json.loads(row.meta or '{}')
    except (TypeError, ValueError):
        return {}


# --------------------------------------------------------------------------
# استعلامات الروابط
# --------------------------------------------------------------------------
def active_link(guardian_id, protected_id):
    return Link.query.filter_by(guardian_id=guardian_id, protected_id=protected_id,
                                status='active').first()


def links_as_guardian(guardian_id):
    return (Link.query.filter_by(guardian_id=guardian_id, status='active')
            .order_by(Link.created_at.desc()).all())


def links_as_protected(protected_id):
    return (Link.query.filter_by(protected_id=protected_id, status='active')
            .order_by(Link.created_at.desc()).all())


def count_children(guardian_id):
    return Link.query.filter_by(guardian_id=guardian_id, status='active').count()


def count_guardians(protected_id):
    return Link.query.filter_by(protected_id=protected_id, status='active').count()


def link_count(user_id):
    return Link.query.filter(
        (Link.guardian_id == user_id) | (Link.protected_id == user_id),
        Link.status == 'active').count()


# --------------------------------------------------------------------------
# الدعوات
# --------------------------------------------------------------------------
def _new_invite_code():
    """6 أرقام (زي ما الطلب) مع ضمان عدم التكرار"""
    for _ in range(12):
        code = f'{secrets.randbelow(10 ** 6):06d}'
        if not LinkInvite.query.filter_by(code=code).first():
            return code
    return secrets.token_hex(4)


def invites_last_day(guardian_id):
    return LinkInvite.query.filter(LinkInvite.guardian_id == guardian_id,
                                   LinkInvite.created_at > now_utc() - timedelta(days=1)).count()


def create_invite(guardian, per_day=20, ttl_hours=24, ip=''):
    """ولي الأمر ينشئ دعوة. يرجّع (نجح؟، invite أو مفتاح خطأ، بيانات إضافية)"""
    if count_children(guardian.id) >= (guardian.max_children or 10):
        return False, 'link.limit_children', {'max': guardian.max_children or 10}
    if invites_last_day(guardian.id) >= per_day:
        return False, 'link.too_many_attempts', {}
    # إلغاء الدعوات القديمة اللي لسه معلقة (دعوة واحدة شغالة في نفس الوقت)
    for old in LinkInvite.query.filter_by(guardian_id=guardian.id, status='pending').all():
        old.status = 'cancelled'
    invite = LinkInvite(guardian_id=guardian.id, code=_new_invite_code(),
                        expires_at=now_utc() + timedelta(hours=ttl_hours), status='pending')
    db.session.add(invite)
    log(guardian.id, 'invite_create', 'link_invite', None, {'code': invite.code}, ip, commit=False)
    db.session.commit()
    payload = {
        'id': invite.id, 'code': invite.code, 'status': invite.status,
        'expires_at': invite.expires_at.isoformat() + 'Z',
        'expires_in': int(ttl_hours * 3600),
        'qr_data': '/invite/' + invite.code,
    }
    return True, invite, payload


def touch_invite(invite):
    """يعلّم الدعوة منتهية لو الوقت عدّى"""
    if invite and invite.status == 'pending' and invite.expires_at < now_utc():
        invite.status = 'expired'
        db.session.commit()
    return invite


def get_invite(code, for_guardian=None):
    code = str(code or '').strip()
    if not code:
        return None
    invite = LinkInvite.query.filter_by(code=code).first()
    if invite and for_guardian is not None and invite.guardian_id != for_guardian:
        return None
    return touch_invite(invite)


def accept_invite(child, invite, consent_text='', consent_version='', ip=''):
    """الطفل يقبل الدعوة ويدّي موافقة صريحة (مشربط فعلي لسه)"""
    invite = touch_invite(invite)
    if not invite:
        return False, 'link.invite_not_found'
    if invite.status == 'pending' and invite.expires_at < now_utc():
        return False, 'link.invite_expired'
    if invite.status == 'accepted':
        return False, 'link.invite_used'
    if invite.status != 'pending':
        return False, 'link.invite_expired'
    if invite.guardian_id == child.id:
        return False, 'link.self_link'
    guardian = db.session.get(User, invite.guardian_id)
    if not guardian:
        return False, 'link.invite_not_found'
    if active_link(guardian.id, child.id):
        return False, 'link.already_linked'
    if count_guardians(child.id) >= 3:
        return False, 'link.limit_guardians', {'max': 3}
    invite.status = 'accepted'
    invite.protected_id = child.id
    invite.accepted_at = now_utc()
    db.session.add(GuardianConsent(child_id=child.id, guardian_id=guardian.id,
                                   consent_version=consent_version, text=(consent_text or '')[:500],
                                   ip=ip or ''))
    db.session.add(Notification(user_id=guardian.id, kind='info', title='طلب ربط جديد',
                                body=f'{child.username} وافق على الدعوة، افتح الرقابة الوالدية لتأكيد الربط.'))
    log(child.id, 'invite_accept', 'link_invite', invite.id,
        {'guardian_id': guardian.id}, ip, commit=False)
    db.session.commit()
    return True, 'link.invite_accepted'


def approve_invite(guardian, invite, ip=''):
    if not invite:
        return False, 'link.invite_not_found'
    if invite.guardian_id != guardian.id:
        return False, 'link.remove_denied'
    if invite.status == 'approved':
        return False, 'link.invite_used'
    if invite.status != 'accepted' or not invite.protected_id:
        return False, 'link.invite_pending'
    child = db.session.get(User, invite.protected_id)
    if not child:
        return False, 'link.invite_not_found'
    if count_children(guardian.id) >= (guardian.max_children or 10):
        return False, 'link.limit_children', {'max': guardian.max_children or 10}
    if count_guardians(child.id) >= 3:
        return False, 'link.limit_guardians', {'max': 3}
    link = active_link(guardian.id, child.id)
    if not link:
        link = Link(guardian_id=guardian.id, protected_id=child.id, status='active')
        db.session.add(link)
        db.session.flush()
    consent = (GuardianConsent.query
               .filter_by(child_id=child.id, guardian_id=guardian.id, link_id=None)
               .order_by(GuardianConsent.consented_at.desc()).first())
    if consent:
        consent.link_id = link.id
    invite.status = 'approved'
    invite.approved_at = now_utc()
    db.session.add(Notification(user_id=child.id, kind='info', title='تم الربط',
                                body=f'تم ربط حسابك بحساب {guardian.username} بعد موافقتك.'))
    log(guardian.id, 'invite_approve', 'link', link.id, {'child_id': child.id}, ip, commit=False)
    db.session.commit()
    return True, 'link.invite_approved'


def reject_invite(guardian, invite, ip=''):
    if not invite or invite.guardian_id != guardian.id:
        return False, 'link.invite_not_found'
    if invite.status not in ('pending', 'accepted'):
        return False, 'link.invite_used'
    invite.status = 'rejected'
    invite.rejected_at = now_utc()
    if invite.protected_id:
        db.session.add(Notification(user_id=invite.protected_id, kind='info', title='تم رفض الدعوة',
                                    body=f'{guardian.username} رفض طلب الربط.'))
    log(guardian.id, 'invite_reject', 'link_invite', invite.id, {}, ip, commit=False)
    db.session.commit()
    return True, 'link.invite_rejected'


def cancel_invite(guardian, invite):
    if not invite or invite.guardian_id != guardian.id:
        return False, 'link.invite_not_found'
    invite.status = 'cancelled'
    db.session.commit()
    return True, 'link.invite_rejected'


def pending_for_guardian(guardian_id):
    """الدعوات المعلّقة (لسه محتاجة موافقة ولي الأمر أو لسه محدش قبلها)"""
    return (LinkInvite.query.filter(LinkInvite.guardian_id == guardian_id,
                                    LinkInvite.status.in_(('pending', 'accepted')))
            .order_by(LinkInvite.created_at.desc()).all())


# --------------------------------------------------------------------------
# فك الربط / إلغاء الرقابة
# --------------------------------------------------------------------------
def _end_link(link, actor, reason, ip=''):
    if not link or link.status != 'active':
        return False, 'link.not_found'
    link.status = 'revoked' if reason == 'child_revoked' else 'removed'
    link.ended_by = actor.id
    link.end_reason = reason
    link.ended_at = now_utc()
    for consent in GuardianConsent.query.filter_by(child_id=link.protected_id,
                                                   guardian_id=link.guardian_id).all():
        if consent.revoked_at is None:
            consent.revoked_at = now_utc()
    other_id = link.guardian_id if actor.id == link.protected_id else link.protected_id
    if reason == 'child_revoked':
        db.session.add(Notification(user_id=other_id, kind='info', title='تم إلغاء الرقابة',
                                    body=f'{actor.username} ألغى الرقابة من حسابه.'))
    else:
        db.session.add(Notification(user_id=other_id, kind='info', title='تم فك الربط',
                                    body=f'{actor.username} فك الربط بينكم.'))
    log(actor.id, reason, 'link', link.id, {'other_id': other_id}, ip, commit=False)
    db.session.commit()
    return True, 'link.revoked' if reason == 'child_revoked' else 'link.removed'


def revoke_link(child, link, ip=''):
    """حق الطفل: إلغاء الرقابة في أي وقت من غير موافقة ولي الأمر"""
    if not link:
        return False, 'link.not_found'
    if link.protected_id != child.id:
        return False, 'link.remove_denied'
    return _end_link(link, child, 'child_revoked', ip)


def remove_link(user, link, ip=''):
    """أي طرف يفك الربط، والتاني بيتبلّغ"""
    if not link:
        return False, 'link.not_found'
    if user.id not in (link.guardian_id, link.protected_id):
        return False, 'link.remove_denied'
    reason = 'guardian_removed' if user.id == link.guardian_id else 'child_removed'
    return _end_link(link, user, reason, ip)


# --------------------------------------------------------------------------
# توافق مع الكود القديم (PairCode)
# --------------------------------------------------------------------------
def create_legacy_link(guardian_id, protected_id, ip=''):
    if active_link(guardian_id, protected_id):
        return False, 'link.already_linked'
    if count_children(guardian_id) >= 10:
        return False, 'link.limit_children'
    if count_guardians(protected_id) >= 3:
        return False, 'link.limit_guardians'
    link = Link(guardian_id=guardian_id, protected_id=protected_id, status='active')
    db.session.add(link)
    log(protected_id, 'link_join', 'link', None, {'guardian_id': guardian_id}, ip, commit=False)
    db.session.commit()
    return True, 'link.created'


# --------------------------------------------------------------------------
# إعدادات الإعلانات
# --------------------------------------------------------------------------
def ads_for(child_id):
    row = AdSettings.query.filter_by(child_id=child_id).first()
    if not row:
        row = AdSettings(child_id=child_id)
        db.session.add(row)
        db.session.commit()
    return row


def ads_to_dict(row):
    def _load(raw):
        try:
            value = json.loads(raw or '[]')
            return [str(x) for x in value] if isinstance(value, list) else []
        except (TypeError, ValueError):
            return []

    return {'enabled': bool(row.enabled), 'max_per_day': int(row.max_per_day or 0),
            'blocked_categories': _load(row.blocked_categories),
            'allowed_categories': _load(row.allowed_categories),
            'child_safe_only': bool(row.child_safe_only)}


def update_ads(row, data, max_per_day=50):
    if not isinstance(data, dict):
        return False, 'ads.invalid'
    try:
        if 'max_per_day' in data:
            value = int(data['max_per_day'])
            if value < 0 or value > max_per_day:
                return False, 'ads.max_range'
            row.max_per_day = value
        for flag in ('enabled', 'child_safe_only'):
            if flag in data:
                setattr(row, flag, bool(data[flag]))
        for field in ('blocked_categories', 'allowed_categories'):
            if field in data:
                value = data[field]
                if not isinstance(value, list) or len(value) > 50:
                    return False, 'ads.invalid'
                setattr(row, field, json.dumps([str(v)[:40] for v in value], ensure_ascii=False))
    except (TypeError, ValueError):
        return False, 'ads.invalid'
    row.updated_at = now_utc()
    db.session.commit()
    return True, 'ads.saved'
