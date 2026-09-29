"""Fixed Kali command plans and bounded offline capture parsers. No subprocess API."""
import base64
import binascii
import ipaddress
import re
from .data import canonical
from .policy import normalize_target

MAX_OUTPUT = 65536
OPERATIONS = {'resolve_dns': None, 'probe_http': 'HEAD'}


class ToolError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise ToolError(reason)


def plan(action, target, method):
    require(action in OPERATIONS and method == OPERATIONS[action], 'Unsupported tool action or method')
    require(isinstance(target, str) and '?' not in target, 'Invalid tool target')
    parsed = normalize_target(target)
    if action == 'resolve_dns':
        require(parsed.scheme is None and parsed.port is None and parsed.path is None, 'DNS adapter requires a bare hostname')
        try:
            ipaddress.ip_address(parsed.host)
        except ValueError:
            pass
        else:
            raise ToolError('DNS adapter requires a hostname, not an IP address')
        argv = ['/usr/bin/dig', '-r', '+time=3', '+tries=1', '+nosearch', '+noall', '+comments', '+answer', parsed.host + '.', 'A']
    else:
        require(parsed.scheme in {'http', 'https'}, 'HTTP adapter requires an explicit URL')
        argv = ['/usr/bin/curl', '--disable', '--silent', '--show-error', '--head', '--globoff',
                '--proto', '=http,https', '--connect-timeout', '3', '--max-time', '5',
                '--max-redirs', '0', '--noproxy', '*', '--url', parsed.display]
    return {'adapter_version': 1, 'action': action, 'target': parsed.display, 'method': method,
            'argv': argv, 'shell': False, 'timeout_ms': 6000, 'max_output_bytes': MAX_OUTPUT,
            'follow_redirects': False, 'execution_enabled': False, 'dry_run': True}


def decode(value):
    require(isinstance(value, str) and len(value) <= 4 * ((MAX_OUTPUT + 2)//3), 'Capture exceeds output limit')
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ToolError('Invalid base64 capture') from error
    require(len(result) <= MAX_OUTPUT, 'Capture exceeds output limit')
    return result


def validate_input(action, target, method, payload):
    plan(action, target, method)
    require(isinstance(payload, dict) and set(payload) == {'version', 'capture'}, 'Invalid tool input fields')
    require(type(payload['version']) is int and payload['version'] == 1, 'Unsupported tool input version')
    capture = payload['capture']
    if capture is not None:
        require(isinstance(capture, dict) and set(capture) == {'stdout_base64', 'stderr_base64', 'exit_code', 'elapsed_ms'}, 'Invalid capture fields')
        decode(capture['stdout_base64']); decode(capture['stderr_base64'])
        require(type(capture['exit_code']) is int and 0 <= capture['exit_code'] <= 255, 'Invalid tool exit code')
        require(type(capture['elapsed_ms']) is int and 0 <= capture['elapsed_ms'] <= 3600000, 'Invalid capture duration')
    return canonical(payload)


def parse_dns(raw):
    try:
        lines = raw.decode('ascii').splitlines()
    except UnicodeError as error:
        raise ToolError('DNS output must be ASCII') from error
    statuses = re.findall(r'status: ([A-Z]+),', '\n'.join(lines))
    require(len(statuses) == 1 and statuses[0] in {'NOERROR', 'NXDOMAIN'}, 'Missing or failed DNS response status')
    records = []
    for line in lines:
        if not line.strip() or line.startswith(';'):
            continue
        fields = line.split()
        require(len(fields) == 5, 'Malformed DNS answer')
        name, ttl, dns_class, kind, value = fields
        require(ttl.isascii() and ttl.isdecimal() and len(ttl) <= 10 and int(ttl) <= 2147483647 and dns_class == 'IN', 'Malformed DNS answer metadata')
        require(kind in {'A', 'AAAA', 'CNAME'}, 'Unsupported DNS answer type')
        require(normalize_target(name).display == name.rstrip('.').lower(), 'Malformed DNS owner')
        if kind == 'CNAME':
            alias = normalize_target(value)
            require(alias.scheme is None and alias.port is None and alias.path is None, 'Invalid DNS alias')
        else:
            try:
                address = ipaddress.ip_address(value)
                require(address.version == (4 if kind == 'A' else 6), 'DNS address type mismatch')
            except ValueError as error:
                raise ToolError('Invalid DNS address') from error
        records.append({'name': name, 'ttl': int(ttl), 'type': kind, 'value': value, 'grants_scope': False})
        require(len(records) <= 100, 'Too many DNS answers')
    require(statuses[0] != 'NXDOMAIN' or not records, 'NXDOMAIN response contains answers')
    return {'dns_status': statuses[0], 'records': records}


def parse_http(raw):
    require(b'\x00' not in raw, 'Invalid HTTP header bytes')
    text = raw.decode('iso-8859-1')
    require(text.endswith('\r\n\r\n') or text.endswith('\n\n'), 'Incomplete HTTP headers')
    lines = text.splitlines()
    match = re.fullmatch(r'HTTP/(?:1\.[01]|2|3) ([1-5][0-9]{2})(?: [^\r\n]*)?', lines[0]) if lines else None
    require(match is not None and int(match[1]) >= 200, 'Invalid or informational HTTP response')
    headers = []
    ended = False
    for line in lines[1:]:
        if not line:
            ended = True
            continue
        require(not ended, 'Multiple responses or body data are not supported')
        name, separator, value = line.partition(':')
        require(separator and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is not None, 'Malformed HTTP header')
        require(all(ord(c) >= 32 or c == '\t' for c in value) and '\x7f' not in value, 'Invalid HTTP header control character')
        headers.append({'name': name, 'value': value.strip()})
        require(len(headers) <= 200, 'Too many HTTP headers')
    return {'status_code': int(match[1]), 'headers': headers, 'redirect_followed': False,
            'redirect_requires_new_job': 300 <= int(match[1]) < 400}


def interpret(command, payload):
    capture = payload['capture']
    result = {'plan': command, 'source': 'dry_run_plan' if capture is None else 'supplied_capture_unverified',
              'executed': False, 'observations': None, 'error': None}
    if capture is None:
        return result
    if capture['elapsed_ms'] > command['timeout_ms']:
        result['error'] = 'tool_timeout'
    elif capture['exit_code'] != 0:
        result['error'] = 'tool_exit_nonzero'
    else:
        try:
            result['observations'] = (parse_dns if command['action'] == 'resolve_dns' else parse_http)(decode(capture['stdout_base64']))
        except (ToolError, ValueError):
            result['error'] = 'invalid_tool_output'
    return result
