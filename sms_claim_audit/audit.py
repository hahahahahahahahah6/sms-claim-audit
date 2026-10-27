"""Offline AST audit. Audited source is never imported or executed."""
import argparse
import ast
import fnmatch
import json
import re
from pathlib import Path

from . import __version__

SMS = ('support for sms', 'sms notifications', 'sms notification', 'sms messaging',
       'sms messages', 'sms message', 'sms alerts', 'sms alert', 'sends sms',
       'send sms', 'sms support', 'sms enabled', 'sms powered', 'sms based',
       'supports sms', 'uses sms', 'using sms', 'over sms', 'via sms', 'with sms')
NOSMS = ('no sms support', 'does not support sms', 'does not send sms',
         'does not use sms', 'sms not supported', 'no sms notifications',
         'without sms', 'no sms')


def pattern(phrases):
    return re.compile(r'\b(?:' + '|'.join(re.escape(p) for p in
                      sorted(phrases, key=len, reverse=True)) + r')\b')


def normalize(text):
    return re.sub(r'\s+', ' ', text.lower().replace("n't", ' not').replace('-', ' '))


def claims(text):
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence):
                fence = None
            lines.append('')
        elif match:
            fence = match[1]
            lines.append('')
        else:
            lines.append(line)
    positive = negative = False
    for paragraph in re.split(r'\n\s*\n', '\n'.join(lines)):
        text = normalize(paragraph)
        negative |= bool(pattern(NOSMS).search(text))
        text = pattern(NOSMS).sub(' ', text)
        positive |= bool(pattern(SMS).search(text))
    return positive, negative


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + '.' + node.attr if base else None
    return None


def evidence(text):
    tree = ast.parse(text)
    constructors, modules = set(), {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and 'twilio' in node.module.split('.'):
            constructors.update(a.asname or a.name for a in node.names if a.name == 'Client')
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if 'twilio' in alias.name.split('.'):
                    modules[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]

    def creation(node):
        if not isinstance(node, ast.Call):
            return False
        if isinstance(node.func, ast.Name):
            return node.func.id in constructors
        path = dotted(node.func)
        if not path or not path.endswith('.Client'):
            return False
        first, *rest = path.split('.')
        resolved = modules.get(first, '').split('.') + rest[:-1]
        return first in modules and 'twilio' in resolved

    bindings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and creation(node.value):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            bindings.update(filter(None, (dotted(t) for t in targets)))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'create':
            receiver = node.func.value
            if isinstance(receiver, ast.Attribute) and receiver.attr == 'messages':
                if creation(receiver.value) or dotted(receiver.value) in bindings:
                    return True
    return False


def audit(root, ignores=()):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('root must be a readable directory')
    # Force a directory read: recursive globbing can suppress permission errors.
    list(root.iterdir())
    positive = negative = False
    prod, tests = [], []
    excluded = {'fixtures', 'docs', 'examples'}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        name = relative.as_posix()
        if path.is_symlink() or any((root / Path(*relative.parts[:i])).is_symlink()
                                   for i in range(1, len(relative.parts))):
            continue
        if any(fnmatch.fnmatchcase(name, glob) for glob in ignores):
            continue
        if not path.is_file():
            continue
        if name == 'README.md' or ('docs' in relative.parts[:-1] and path.suffix.lower() == '.md'):
            yes, no = claims(path.read_text(encoding='utf-8'))
            positive |= yes
            negative |= no
        if path.suffix != '.py' or excluded.intersection(relative.parts[:-1]):
            continue
        try:
            found = evidence(path.read_text(encoding='utf-8'))
        except (SyntaxError, UnicodeError):
            found = False
        if found:
            is_test = 'tests' in relative.parts[:-1] or path.name.startswith('test_') or path.name.endswith('_test.py')
            (tests if is_test else prod).append(name)
    findings = []
    if positive and not prod:
        findings.append({'rule': 'documented-sms-claim-false',
                         'severity': 'MEDIUM' if tests else 'HIGH',
                         'message': 'Documented outbound text delivery lacks production creation and direct send evidence.'})
    if negative and prod:
        findings.append({'rule': 'documented-no-sms-claim-false', 'severity': 'HIGH',
                         'message': 'Documented absence of outbound text delivery contradicts production evidence.'})
    return {'findings': findings, 'evidence': prod, 'test_evidence': tests}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', action='append', default=[])
    parser.add_argument('--fail-on', choices=['HIGH', 'MEDIUM'], default='HIGH')
    parser.add_argument('--version', action='version', version=__version__)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 1
    try:
        result = audit(args.root, args.ignore)
    except (OSError, ValueError) as exc:
        if args.json:
            print(json.dumps({'error': str(exc)}))
        else:
            print('Error: ' + str(exc))
        return 1
    failed = any(f['severity'] == 'HIGH' or args.fail_on == 'MEDIUM' for f in result['findings'])
    result['verdict'] = 'FAIL' if failed else 'PASS'
    if args.json:
        print(json.dumps(result))
    else:
        print(result['verdict'])
        for finding in result['findings']:
            print('{severity} {rule}: {message}'.format(**finding))
        if args.verbose:
            print('Production evidence: ' + ', '.join(result['evidence']))
            print('Test evidence: ' + ', '.join(result['test_evidence']))
    return 2 if failed else 0
