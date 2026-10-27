import contextlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from sms_claim_audit.audit import SMS, NOSMS, audit, claims, main, normalize, pattern

ROOT = Path(__file__).resolve().parents[1]
GOOD = 'from twilio.rest import Client\nc = Client()\nc.messages.create(body="hello")\n'


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            code = main([str(self.root), *args])
        return code, output.getvalue()

    def case(self, claim='sms notifications', source=GOOD, severity=None, rule='documented-sms-claim-false'):
        self.write('README.md', claim)
        if source is not None:
            self.write('app.py', source)
        code, output = self.cli('--json')
        result = json.loads(output)
        self.assertEqual(code, 2 if severity == 'HIGH' else 0)
        self.assertEqual(result['verdict'], 'FAIL' if severity == 'HIGH' else 'PASS')
        self.assertEqual([(f['rule'], f['severity']) for f in result['findings']],
                         [(rule, severity)] if severity else [])

    def test_01_plain(self):
        self.case()

    def test_02_module_alias(self):
        self.case('sms support', 'import twilio.rest as tr\nc=tr.Client()\nc.messages.create()')

    def test_03_attribute_path(self):
        self.case('uses sms', 'import twilio\nc=twilio.rest.Client()\nc.messages.create()')

    def test_04_chained(self):
        self.case('sends sms', 'from twilio.rest import Client\nClient().messages.create()')

    def test_05_self(self):
        self.case('sms alerts', 'from twilio.rest import Client\nclass Sender:\n def go(self):\n  self.client=Client()\n  self.client.messages.create()')

    def test_06_from_alias(self):
        self.case('supports sms', 'from twilio.rest import Client as TwilioClient\nc=TwilioClient()\nc.messages.create()')

    def test_07_import_only(self):
        self.case(source='import twilio.rest', severity='HIGH')

    def test_08_creation_only(self):
        self.case(source='from twilio.rest import Client\nc=Client()', severity='HIGH')

    def test_09_unbound(self):
        self.case(source='client.messages.create()', severity='HIGH')

    def test_10_other_create(self):
        self.case(source='from twilio.rest import Client\nc=Client()\nc.create()', severity='HIGH')

    def test_11_intermediate(self):
        self.case(source='from twilio.rest import Client\nc=Client()\nmsgs=c.messages\nmsgs.create()', severity='HIGH')

    def test_12_inbound(self):
        self.case(source='@app.post("/incoming")\ndef receive():\n return request.form["Body"]', severity='HIGH')

    def test_13_email(self):
        self.case(source='import smtplib\nsmtplib.SMTP().sendmail("a", "b", "c")', severity='HIGH')

    def test_14_strings(self):
        self.case(source='channel="sms"\nsid="AC_MARKER"\nphone="+15550000000"', severity='HIGH')

    def test_15_boundary(self):
        self.write('other.py', 'c.messages.create()')
        self.case(source='from twilio.rest import Client\nc=Client()', severity='HIGH')

    def test_16_negative(self):
        self.case('no sms support', severity='HIGH', rule='documented-no-sms-claim-false')

    def test_17_no_claim(self):
        self.case('Delivery utilities')

    def test_18_bare(self):
        self.case('the sms chapter explains messaging', 'import twilio.rest')

    def test_19_email_claim(self):
        self.case('email notifications', 'smtp.sendmail()')

    def test_20_webhook_claim(self):
        self.case('webhook', '@app.post("/")\ndef receive():\n return "ok"')

    def test_21_push_claim(self):
        self.case('push notifications', 'push.send()')

    def test_22_no_source(self):
        self.case(source=None, severity='HIGH')
        self.case('no sms support', None)

    def test_23_tests_only(self):
        for name in ('tests/sender.py', 'test_sender.py', 'sender_test.py'):
            with self.subTest(name=name):
                self.write(name, GOOD)
                self.case(source=None, severity='MEDIUM')
                self.assertEqual(self.cli('--fail-on', 'MEDIUM')[0], 2)
                (self.root / name).unlink()

    def test_24_fences_inline(self):
        self.case('```text\nsms notifications\n```', None)
        self.case('`sms notifications`', None, 'HIGH')
        self.case('~~~\nsms notifications\n~~~', None)

    def test_25_negation(self):
        self.assertEqual(claims('does not send sms'), (False, True))
        self.case('does not send sms', severity='HIGH', rule='documented-no-sms-claim-false')

    def test_26_self(self):
        result = audit(ROOT)
        self.assertEqual(result['findings'], [])
        self.assertEqual(claims((ROOT / 'README.md').read_text()), (False, False))
        for path in ROOT.rglob('*.md'):
            if path == ROOT / 'README.md' or 'docs' in path.relative_to(ROOT).parts[:-1]:
                text = normalize(path.read_text())
                self.assertIsNone(pattern(SMS + NOSMS).search(text), str(path))

    def test_27_cli(self):
        self.case()
        self.assertEqual(self.cli('--version'), (0, '0.1.0\n'))
        self.assertIn('app.py', self.cli('--verbose')[1])
        self.write('docs/claim.md', 'no sms support')
        self.assertEqual(self.cli()[0], 2)
        self.assertEqual(self.cli('--ignore', 'docs/*')[0], 0)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.root / 'missing')]), 1)
        self.assertEqual(self.cli('--unknown')[0], 1)

    def test_28_env_guard(self):
        self.write('.env', 'MARKER_ONLY')
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            self.case()

    def test_29_packaging(self):
        for path in list((ROOT / 'sms_claim_audit').glob('*.py')) + list((ROOT / 'tests').rglob('*.py')) + [ROOT / 'README.md']:
            self.assertIsNone(re.search(r'\b' + 'py' + r'thon\b', path.read_text()), str(path))
        metadata = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('setuptools>=77', metadata)
        self.assertIn('license = "MIT"', metadata)
        self.assertIn('requires-' + 'py' + 'thon = ">=3.9"', metadata)
        self.assertIn('recursive-include tests', (ROOT / 'MANIFEST.in').read_text())

    def test_30_all_phrases(self):
        for phrase in SMS:
            self.assertEqual(claims(phrase), (True, False), phrase)
        for phrase in NOSMS:
            self.assertEqual(claims(phrase), (False, True), phrase)
        self.assertEqual(claims("doesn't send sms"), (False, True))
        self.assertEqual(claims('SMS-\nnotifications'), (True, False))
        self.assertEqual(claims('send\n\nsms'), (False, False))
        self.assertEqual(claims('resend smsx'), (False, False))

    def test_31_exclusions(self):
        for name in ('fixtures/a.py', 'docs/a.py', 'examples/a.py'):
            self.write(name, GOOD)
        self.case(source=None, severity='HIGH')
        self.write('outside.txt', GOOD)
        (self.root / 'linked.py').symlink_to(self.root / 'outside.txt')
        self.case(source=None, severity='HIGH')

    def test_32_non_evidence(self):
        for source in ('from database import Client\nc=Client()\nc.messages.create()',
                       'class Client: pass\nc=Client()\nc.messages.create()',
                       'push.send()', 'ses.send_email()', 'import re\nre.match("phone", "123")',
                       'def sms():\n print("sent")', repr(GOOD)):
            self.case(source=source, severity='HIGH')

    def test_33_both_families(self):
        self.write('README.md', 'sms notifications.\n\nno sms support')
        result = audit(self.root)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['rule'], 'documented-sms-claim-false')

    def test_35_unreadable_root(self):
        with patch.object(Path, 'iterdir', side_effect=PermissionError('unreadable')):
            self.assertEqual(self.cli('--json')[0], 1)

    def test_34_module_forms(self):
        for source in ('import twilio.rest\napp.client=twilio.rest.Client()\napp.client.messages.create()',
                       'import twilio as tw\nc=tw.rest.Client()\nc.messages.create()',
                       'from vendor.twilio.rest import Client\nc: object=Client()\nc.messages.create()'):
            self.case(source=source)


if __name__ == '__main__':
    unittest.main()
