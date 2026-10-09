"""Bounded passive detection on recorded bytes. No network or provider calls."""
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit
import zlib

from .data import DataStore, canonical, digest, require
from .integrations import IntegrationStore
from .pipeline import BoundDatabase
from .policy import normalize_target
from .programs import ProgramStore
from .scope import action_is_allowed, target_is_in_scope

VERSION = 'passive-1'
LIMIT = 1024 * 1024
RULES = ['credentialed_cors', 'session_cookie', 'exposed_config',
         'external_redirect', 'server_trace']


def message(raw, *, response=False, method=None):
    """Decode only complete, unambiguous captures; reject conflicting framing."""
    require(isinstance(raw, bytes) and len(raw) <= LIMIT, 'Capture exceeds 1 MiB')
    head, sep, body = raw.partition(b'\r\n\r\n')
    require(sep and len(head) <= 65536, 'Missing or oversized HTTP headers')
    lines = head.decode('iso-8859-1').split('\r\n')
    if response:
        match = re.fullmatch(r'HTTP/(?:1\.0|1\.1|2) ([1-5][0-9]{2})(?: [^\r\n]*)?', lines[0])
        require(match, 'Unsupported response status line')
        start = int(match[1])
    else:
        parts = lines[0].split(' ')
        require(len(parts) == 3 and parts[2] in {'HTTP/1.0', 'HTTP/1.1', 'HTTP/2'}, 'Unsupported request line')
        require(parts[0] in {'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT'}, 'Unsupported method')
        start = parts
    headers = {}
    for line in lines[1:]:
        key, colon, value = line.partition(':')
        require(colon and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key), 'Invalid HTTP header')
        require(not any(ord(c) < 32 and c != '\t' for c in value), 'Invalid header value')
        headers.setdefault(key.lower(), []).append(value.strip())
    single = {'host','origin','location','content-length','transfer-encoding','content-encoding',
              'access-control-allow-origin','access-control-allow-credentials','content-type'}
    require(all(len(headers.get(k, [])) <= 1 for k in single), 'Ambiguous duplicate HTTP headers')
    require(not ('content-length' in headers and 'transfer-encoding' in headers), 'Conflicting HTTP framing')
    if method == 'HEAD' and response:
        require(not body, 'HEAD capture unexpectedly has a body')
        return start, headers, b''
    length = headers.get('content-length', [None])[0]
    if length is not None:
        require(re.fullmatch(r'[0-9]+', length) and int(length) == len(body), 'Truncated or inconsistent HTTP body')
    if 'transfer-encoding' in headers:
        require(headers['transfer-encoding'] == ['chunked'], 'Unsupported transfer encoding')
        remaining, decoded = body, bytearray()
        for _ in range(10000):
            size_line, marker, rest = remaining.partition(b'\r\n')
            require(marker and re.fullmatch(b'[0-9a-fA-F]{1,8}', size_line), 'Invalid chunk framing')
            size = int(size_line, 16)
            if size == 0:
                require(rest == b'\r\n', 'Unsupported trailers or trailing chunk bytes')
                body = bytes(decoded)
                break
            require(size <= LIMIT - len(decoded) and len(rest) >= size + 2 and rest[size:size+2] == b'\r\n', 'Truncated or oversized chunk')
            decoded.extend(rest[:size]); remaining = rest[size+2:]
        else:
            raise ValueError('Too many HTTP chunks')
    encoding = headers.get('content-encoding', ['identity'])[0].lower()
    if encoding == 'gzip':
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        body = decoder.decompress(body, LIMIT + 1)
        require(len(body) <= LIMIT and decoder.eof and not decoder.unused_data, 'Invalid or oversized gzip body')
    else:
        require(encoding == 'identity', 'Unsupported content encoding; export decoded traffic')
    return start, headers, body


def origin(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.path not in {'','/'} or parsed.query or parsed.fragment:
            return None
        return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == 'https' else 80)
    except ValueError:
        return None


def sensitive_json(body):
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        return False
    pending = [(value, 0)]
    keys = {'email','address','balance','access_token','password','ssn','phone','bank_account'}
    inspected = 0
    while pending and inspected < 10000:
        item, depth = pending.pop(); inspected += 1
        if isinstance(item, dict):
            if any(str(k).lower() in keys and v not in (None, '', [], {}) for k, v in item.items()):
                return True
            if depth < 10: pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list) and depth < 10:
            pending.extend((v, depth + 1) for v in item)
    return False


def detect(url, request, response):
    req, rh, _ = message(request)
    status, sh, body = message(response, response=True, method=req[0])
    parsed = urlsplit(url)
    require(req[1] == (parsed.path or '/') + ('?' + parsed.query if parsed.query else ''), 'Capture URL differs from request')
    require(len(rh.get('host', [])) == 1, 'Capture requires one Host header')
    authority = normalize_target(parsed.scheme + '://' + rh['host'][0] + '/')
    target = normalize_target(url)
    require((authority.host, authority.port) == (target.host, target.port), 'Capture Host differs from URL')
    candidates, notes = [], []

    def add(rule, title, confidence, facts, impact, validation):
        candidates.append({'rule': rule, 'title': title, 'confidence': confidence,
            'facts': facts, 'potential_impact': impact, 'validation_steps': validation,
            'severity': 'unassigned', 'automatically_verified': False})

    supplied = rh.get('origin', [''])[0]
    cors = sh.get('access-control-allow-origin', [''])[0]
    credentials = sh.get('access-control-allow-credentials', [''])[0] == 'true'
    external = origin(supplied) and origin(supplied) != origin(parsed.scheme + '://' + parsed.netloc)
    if cors:
        if req[0] not in {'OPTIONS','HEAD'} and 200 <= status < 300 and external and cors == supplied and credentials and rh.get('cookie') and sensitive_json(body):
            add('credentialed_cors', 'Credentialed cross-origin access to potentially sensitive data', 'medium',
                ['The supplied cross-origin Origin was returned as the allowed origin.',
                 'Allow-Credentials is true; the recorded request sent a cookie.',
                 'A successful JSON response contains a potentially sensitive field. Values are omitted.'],
                'A foreign site might read private account data; intended sharing and browser behavior are unverified.',
                ['Confirm that the data is private and belongs to your approved test account.',
                 'Reproduce in a browser from an unrelated origin using only that test account.',
                 'Check cookie SameSite rules, intended origin allowlists and actual readability.'])
        else:
            notes.append('CORS headers observed; a successful credentialed private-data browser read is not established.')
    for cookie in sh.get('set-cookie', []):
        pieces = [p.strip() for p in cookie.split(';')]
        name, equals, value = pieces[0].partition('=')
        if not equals or not value or name.lower() not in {'session','sessionid','phpsessid','jsessionid','connect.sid','auth_token','__host-session','__secure-session'}:
            continue
        attrs = {p.partition('=')[0].lower(): p.partition('=')[2].lower() for p in pieces[1:]}
        if attrs.get('max-age') == '0': continue
        missing = [flag for flag in ('secure','httponly') if flag not in attrs]
        if missing:
            add('session_cookie', 'Session-like cookie lacks protective attributes', 'medium',
                ['A session-like Set-Cookie has missing attributes: ' + ', '.join(missing) + '. Cookie value omitted.'],
                'A sensitive session cookie could be exposed through unencrypted transport or page scripts; session purpose is unverified.',
                ['Confirm this cookie authenticates an approved test account.',
                 'Assess transport and script exposure without accessing another account.',
                 'Apply Secure and HttpOnly where appropriate; do not infer account takeover from attributes alone.'])
    if 200 <= status < 300 and req[0] != 'HEAD' and re.search(r'/(?:\.env(?:\.[A-Za-z0-9_-]+)?)$', parsed.path):
        assignments = re.findall(rb'(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,60})\s*=\s*([^\r\n]+)', body)
        secret_names = [name.decode() for name, value in assignments
            if re.search(rb'(PASSWORD|SECRET|TOKEN|PRIVATE_KEY|API_KEY)', name)
            and len(value.strip(b' "\'')) >= 8
            and value.strip().lower() not in {b'example',b'changeme',b'your_token',b'your_api_key'}]
        if len(assignments) >= 2 and secret_names and b'<html' not in body.lower():
            add('exposed_config', 'Configuration file exposes secret-like assignments', 'high',
                ['A successful .env response contains multiple configuration assignments.',
                 'Secret-like field names: ' + ', '.join(sorted(set(secret_names))[:10]) + '. Values omitted.'],
                'If these are active secrets, exposed configuration could permit unauthorized service access.',
                ['Confirm file ownership and rule eligibility; avoid using or copying the secrets further.',
                 'Ask the owner to assess validity, revoke exposed values and restrict access.',
                 'Rule out a deliberate sample configuration or public documentation.'])
    location = sh.get('location', [''])[0]
    if status in {301,302,303,307,308} and location and len(parsed.query) <= 8192:
        destination = urlsplit(location)
        params = parse_qs(parsed.query, max_num_fields=64)
        matched = any(location in values for key, values in params.items()
                      if key.lower() in {'next','url','redirect','redirect_uri','returnurl','return_to','continue'})
        if matched and destination.scheme in {'http','https'} and destination.hostname and destination.hostname.lower() != parsed.hostname.lower():
            add('external_redirect', 'External redirect follows a supplied destination', 'medium',
                ['The redirect Location exactly matches a recognized request destination parameter.',
                 'The destination host differs from the source host; query values are omitted.'],
                'A redirect may enable misleading links; legitimate navigation and program eligibility are unverified.',
                ['Confirm whether unrestricted external navigation is intended.',
                 'Reproduce only with a harmless destination and check program exclusions.',
                 'Demonstrate an eligible security impact before reporting.'])
    if status >= 500 and req[0] != 'HEAD':
        traces = [(b'Traceback (most recent call last):', b'File "'), (b'java.lang.', b'\tat '),
                  (b'Stack trace:', b'Fatal error:')]
        if any(a in body and b in body for a, b in traces):
            add('server_trace', 'Server error includes a runtime stack trace', 'medium',
                ['A 5xx response contains multiple recognizable stack-trace markers. Paths and values omitted.'],
                'Debug details may reveal implementation information; meaningful security impact needs review.',
                ['Check for sensitive details in the original local evidence.',
                 'Assess program exclusions and a concrete impact; do not trigger additional errors at volume.'])
    if not candidates:
        notes.append('No supported candidate pattern found in this capture. This is not a full security assessment.')
    return {'method': req[0], 'status': status, 'candidates': candidates, 'notes': notes}


class TrafficAnalyzer:
    def __init__(self, database): self.database = database

    def run(self, record_id):
        with self.database.transaction(write=True) as c:
            db = BoundDatabase(c); integrations = IntegrationStore(db)
            require(not c.execute('SELECT stopped FROM engine_control WHERE id=1').fetchone()['stopped'], 'Emergency stop blocks new analysis')
            source = integrations.read(c, record_id)
            require(source['kind'] in {'burp_import','manual_http_baseline'}, 'Expected imported HTTP traffic')
            program = ProgramStore.read(c, source['program_id'])
            require(action_is_allowed(program, 'analyze_http').allowed, 'Policy does not allow offline HTTP analysis')
            key = digest(canonical({'source':source, 'version':VERSION, 'policy':program.revision}).encode())
            if source['kind'] == 'burp_import':
                entries = [e for e in source['payload']['entries'] if e['kind'] == 'item']
            else:
                entries = [{'url':source['payload']['target'], 'artifact_names':['request.bin','response.bin']}]
            require(entries, 'No HTTP item captures; scanner claims cannot be analyzed as traffic')
            require(all(target_is_in_scope(program, e['url']).allowed for e in entries), 'Analysis requires current scope')
            for artifact in source['artifacts']:
                integrations.bytes(record_id, artifact['name'])
            previous = [integrations.read(c, row['id']) for row in c.execute(
                "SELECT id FROM integration_records WHERE program_id=? AND kind='traffic_analysis' ORDER BY rowid", (program.id,))]
            prior = next((r for r in previous if r['payload']['analysis_key'] == key), None)
            if prior:
                for item in prior['payload']['results']:
                    for candidate in item['candidates']:
                        for eid in candidate['evidence_ids']: DataStore(db).show(eid)
                return prior
            results, findings = [], []
            store = DataStore(db)
            for entry in entries:
                names = entry['artifact_names']
                request_name = next((n for n in names if n.endswith('/request') or n == 'request.bin'), None)
                response_name = next((n for n in names if n.endswith('/response') or n == 'response.bin'), None)
                target = normalize_target(entry['url']).display
                item = {'target':target, 'candidates':[], 'notes':[]}
                if not request_name or not response_name:
                    item['notes'].append('Skipped incomplete request/response pair.'); results.append(item); continue
                request = integrations.bytes(record_id, request_name)
                response = integrations.bytes(record_id, response_name)
                try:
                    inspection = detect(entry['url'], request, response)
                    require(inspection['method'] in {'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'}, 'Unsupported endpoint method')
                except (ValueError,UnicodeError,zlib.error):
                    item['notes'].append('Skipped unsupported or inconsistent HTTP framing.'); results.append(item); continue
                item.update(method=inspection['method'], status=inspection['status'], notes=inspection['notes'],
                    request_sha256=digest(request), response_sha256=digest(response))
                for candidate in inspection['candidates']:
                    asset = store.create('asset', program.id, {'target':target}, actor='passive-analyzer')
                    endpoint = store.create('endpoint', program.id, {'target':target, 'method':inspection['method']}, parent_id=asset['id'], actor='passive-analyzer')
                    observation = store.create('observation', program.id, {'fact':' '.join(candidate['facts'])}, parent_id=endpoint['id'], actor='passive-analyzer')
                    hypothesis = candidate['potential_impact'] + '\nValidation required:\n' + '\n'.join(candidate['validation_steps'])
                    finding = store.create('finding', program.id, {'title':candidate['title'], 'hypothesis':hypothesis}, parent_id=observation['id'], actor='passive-analyzer')
                    evidence_ids = []
                    for category, content in [('request',request), ('response',response)]:
                        evidence = store.create('evidence', program.id, {'label':'Imported HTTP '+category, 'category':category,
                            'origin':'raw_import', 'captured_at':source['created_at']}, parent_id=finding['id'], actor='passive-analyzer', content=content)
                        evidence_ids.append(evidence['id'])
                    candidate.update(finding_id=finding['id'], evidence_ids=evidence_ids,
                        source_record_id=record_id, capture_time_basis='source import time, not independently verified capture time')
                    item['candidates'].append(candidate); findings.append(finding['id'])
                results.append(item)
            payload = {'analysis_key':key, 'analyzer_version':VERSION, 'source_record_id':record_id,
                'results':results, 'finding_ids':findings, 'candidate_count':len(findings), 'verified_count':0,
                'execution_enabled':False, 'scope_revision':program.revision,
                'synthetic_training': program.id == 'analysis-training' and 'Generated local fixture only' in program.authorization_source,
                'limitations':['Passive patterns only; no live testing or browser reproduction.',
                    'Confidence refers to the observed pattern, not vulnerability validity.',
                    'Severity and program eligibility require human validation.']}
            return integrations.save(program.id, 'traffic_analysis', payload, {}, targets=[e['url'] for e in entries])

    def report(self, record_id):
        record = IntegrationStore(self.database).show(record_id)
        require(record['kind'] == 'traffic_analysis', 'Expected an analysis record')
        payload = record['payload']
        lines = ['# HTTP traffic assessment', '', 'Status: candidates require validation; no automatically verified vulnerabilities.',
                 '', 'Program: ' + record['program_id'], 'Analysis: ' + record_id,
                 'Candidates: ' + str(payload['candidate_count']), '', 'Raw evidence remains in the local vault. Derived notes omit secret values.', '']
        if payload.get('synthetic_training'):
            lines.extend(['SYNTHETIC TRAINING FIXTURES: no live target was tested and these are not Mercado Libre findings.', ''])
        for index, item in enumerate(payload['results'], 1):
            lines.extend(['## Capture ' + str(index), '', '`' + item['target'] + '`', ''])
            lines.extend('- ' + note for note in item['notes'])
            for candidate in item['candidates']:
                lines.extend(['', '### ' + candidate['title'], '',
                    'Pattern confidence: ' + candidate['confidence'] + '; severity: unassigned; status: needs validation.',
                    'Finding ID: ' + candidate['finding_id'], '', 'Observed:', ''])
                lines.extend('- ' + fact for fact in candidate['facts'])
                lines.extend(['', 'Potential impact: ' + candidate['potential_impact'], '', 'Validation:', ''])
                lines.extend('- ' + step for step in candidate['validation_steps'])
                lines.extend(['', 'Evidence IDs: ' + ', '.join(candidate['evidence_ids']),
                    'Request SHA-256: ' + item['request_sha256'], 'Response SHA-256: ' + item['response_sha256'], ''])
        return '\n'.join(lines) + '\n'


def register(commands):
    sub = commands.add_parser('analysis', help='Detect candidates from imported traffic locally').add_subparsers(dest='analysis_command', required=True)
    sub.add_parser('rules')
    sub.add_parser('demo', help='Generate and analyze labeled synthetic training captures')
    run = sub.add_parser('run'); run.add_argument('record_id')
    report = sub.add_parser('report'); report.add_argument('record_id'); report.add_argument('destination', type=Path)


def dispatch(args, database):
    analyzer = TrafficAnalyzer(database)
    if args.analysis_command == 'rules':
        result = {'version':VERSION, 'rules':RULES, 'mode':'passive_imported_captures'}
    elif args.analysis_command == 'demo':
        from .analysis_demo import run_demo
        result = run_demo(database)
    elif args.analysis_command == 'run': result = analyzer.run(args.record_id)
    else:
        content = analyzer.report(args.record_id)
        with args.destination.open('x', encoding='utf-8') as output: output.write(content)
        result = {'destination':str(args.destination), 'status':'candidate_assessment_not_submission'}
    return {'ok':True, 'analysis':result, 'execution_enabled':False}
