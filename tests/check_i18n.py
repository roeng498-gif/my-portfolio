"""تدقيق الترجمة: كل مفتاح في القوالب لازم يكون موجود في العربي والإنجليزي.

التشغيل:  py -3.14 tests/check_i18n.py
"""
import glob
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import messages  # noqa: E402

KEYS = set(messages.MESSAGES['ar']) | set(messages.MESSAGES['en'])
problems = []

# 1) مفاتيح مستخدمة في القوالب لازم تكون موجودة
pattern = re.compile(r"""\bt\(\s*['"]([a-zA-Z0-9_.]+)['"]""")
used = set()
for path in glob.glob(os.path.join(BASE, 'templates', '*.html')):
    with open(path, encoding='utf-8') as fh:
        text = fh.read()
    for key in pattern.findall(text):
        used.add(key)
        if key.endswith('_') or key.endswith('.'):
            continue          # بادئة ديناميكية: scan.level. + <level>
        if key not in messages.MESSAGES['ar']:
            problems.append(f'{os.path.basename(path)}: missing ar key {key}')
        if key not in messages.MESSAGES['en']:
            problems.append(f'{os.path.basename(path)}: missing en key {key}')

# 2) مفاتيح ديناميكية (بتتبني في وقت التشغيل) لازم تكون كلها موجودة
dynamic = ['scan.type_quick', 'scan.type_normal', 'scan.type_full',
           'scan.st_hit', 'scan.st_clean', 'scan.st_skipped', 'scan.st_disabled', 'scan.st_error',
           'scan.level.safe', 'scan.level.medium', 'scan.level.high', 'scan.level.critical',
           'app_scan.level.safe', 'app_scan.level.low', 'app_scan.level.medium',
           'app_scan.level.high', 'app_scan.level.critical']
for key in dynamic:
    if key not in messages.MESSAGES['ar'] or key not in messages.MESSAGES['en']:
        problems.append(f'dynamic key missing: {key}')

# 3) توازي المفاتيح
only_ar = set(messages.MESSAGES['ar']) - set(messages.MESSAGES['en'])
only_en = set(messages.MESSAGES['en']) - set(messages.MESSAGES['ar'])
if only_ar:
    problems.append(f'keys only in ar: {sorted(only_ar)[:10]}')
if only_en:
    problems.append(f'keys only in en: {sorted(only_en)[:10]}')

# 4) صياغة {placeholders} متساوية بين اللغتين
for key in KEYS:
    ar = messages.MESSAGES['ar'][key]
    en = messages.MESSAGES['en'][key]
    if sorted(re.findall(r'\{(\w+)\}', ar)) != sorted(re.findall(r'\{(\w+)\}', en)):
        problems.append(f'placeholder mismatch: {key}')

print(f'templates scanned: {len(glob.glob(os.path.join(BASE, "templates", "*.html")))}')
print(f'keys used in templates: {len(used)} | total keys: {len(KEYS)}')
if problems:
    print('\nPROBLEMS:')
    for item in problems:
        print(' -', item)
    sys.exit(1)
print('\nI18N OK')
