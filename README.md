# sms-claim-audit

Version 0.1.0 audits documented text-message delivery claims against Python AST evidence. It runs offline, requires Python 3.9 or later, has no runtime dependencies, and never executes audited code or reads environment files.

Install and run:

```sh
python3 -m pip install .
sms-claim-audit .
python3 -m sms_claim_audit . --json
python3 -m sms_claim_audit --version
```

The positional root defaults to the current directory. Options are `--json`, `--verbose` (lists evidence files), repeatable `--ignore <glob>` (relative paths), and `--fail-on {HIGH,MEDIUM}` (default HIGH). Exit codes are 0 for PASS, 2 for findings meeting the threshold, and 1 for usage or filesystem errors. JSON includes verdict, findings with rule/severity/message, production evidence, and test evidence.

## Scope and limitations

Only the fixed positive and negative phrase templates in `sms_claim_audit/audit.py` count as claims; a bare channel noun does not. Email, webhook, websocket, server-sent events, GraphQL, gRPC, MQTT, and push claims are outside scope. Root README.md and Markdown files beneath any docs path component are scanned. Inline code counts; fenced blocks do not. Matching lowercases, expands contracted negation, replaces hyphens, joins paragraph lines, and uses word boundaries. Negative spans are removed before positive matching; phrases cannot span blank paragraphs.

Evidence requires a Twilio Client creation and direct messages.create call in the same module. Imported aliases, attribute bindings, and chained calls count. An intermediate messages alias does not. Imports alone, idle clients, inbound handlers, other channels, strings, validation, and unrelated clients do not establish delivery. This static structural check does not verify credentials, reachability, runtime success, control flow, reassignment, or network delivery. Invalid Python syntax supplies no evidence.

Production scanning excludes tests, test filename patterns, fixtures, docs, examples, and symbolic links. Test evidence alone produces MEDIUM; absent production and test evidence produces HIGH for a positive claim. A negative claim contradicted by production evidence produces HIGH even in a docs page. There is at most one finding per family. Absent claims always pass. A positive claim without source fails; a negative claim without source passes.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m build
```

Tests and fixtures ship in the source distribution. MIT licensed.
