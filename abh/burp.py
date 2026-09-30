"""Read-only Burp XML adapter. No invented Burp API endpoints."""
import base64
import binascii
from pathlib import Path
import re
from typing import Protocol
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from .data import require
from .integrations import IntegrationStore
from .policy import normalize_target


class BurpAdapter(Protocol):
    def status(self) -> dict: ...
    def ingest(self, program_id: str, raw: bytes) -> dict: ...


class BurpXmlAdapter:
    def __init__(self, database):
        self.store = IntegrationStore(database)

    def status(self):
        return {'adapter': 'burp_xml', 'available': True, 'connected': False, 'edition': 'community',
                'capabilities': ['import_http_items', 'import_scanner_issues', 'export_original_artifacts'],
                'scanner_execution_available': False, 'live_api': 'not_configured', 'execution_enabled': False}

    @staticmethod
    def field(element, name, *, required=True):
        found = element.findall(name)
        require(len(found) <= 1 and (not required or len(found) == 1), 'Missing or duplicate Burp XML field')
        value = found[0].text or '' if found else ''
        require(not required or bool(value.strip()), 'Empty Burp XML field')
        require(len(value) <= 65536, 'Burp metadata field too large')
        return value

    @staticmethod
    def message(element):
        require(element.attrib.get('base64') == 'true', 'Export Burp request/response with Base64 encoding enabled')
        try:
            raw = base64.b64decode(''.join((element.text or '').split()), validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError('Invalid Burp base64 data') from error
        require(len(raw) <= 1024*1024, 'Burp message exceeds 1 MiB')
        return raw

    def ingest(self, program_id, raw):
        require(isinstance(raw, bytes) and len(raw) <= 10*1024*1024, 'Burp export exceeds 10 MiB')
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeError as error:
            raise ValueError('Burp export must be UTF-8') from error
        require('\x00' not in text and not re.search(r'<!ENTITY|\b(?:SYSTEM|PUBLIC)\s+[\"\x27]', text, re.I), 'XML entities or external declarations are not supported')
        # Parse decoded Unicode so an XML encoding declaration cannot bypass the checks.
        try:
            root = ET.fromstring(text)
        except ET.ParseError as error:
            raise ValueError('Invalid Burp XML') from error
        require(root.tag in {'items', 'issues'}, 'Expected Burp items or issues XML')
        require(0 < len(root) <= 100, 'Import requires 1 to 100 items')
        artifacts = {'export.xml': raw}
        entries = []
        targets = []
        for index, element in enumerate(root):
            expected = 'item' if root.tag == 'items' else 'issue'
            require(element.tag == expected, 'Unexpected Burp XML entry')
            if expected == 'item':
                url = self.field(element, 'url')
                method = self.field(element, 'method')
                require(method in {'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT'}, 'Invalid imported HTTP method')
                metadata = {'method': method, 'status': self.field(element, 'status', required=False),
                            'captured_at': self.field(element, 'time', required=False)}
                containers = [element]
            else:
                host = self.field(element, 'host')
                location = self.field(element, 'path', required=False) or '/'
                require(location.startswith('/') and not location.startswith('//'), 'Invalid issue path')
                url = host.rstrip('/') + location
                metadata = {key: self.field(element, key, required=key in {'name','severity','confidence'})
                            for key in ('serialNumber','name','severity','confidence','issueBackground','issueDetail','remediationBackground','remediationDetail')}
                containers = element.findall('requestresponse')
                require(len(containers) <= 20, 'Too many issue messages')
            parsed = normalize_target(url)
            require(parsed.scheme in {'http','https'}, 'Burp URL must use HTTP or HTTPS')
            targets.append(parsed.display)
            refs = []
            for pair, container in enumerate(containers):
                for stream in ('request','response'):
                    messages = container.findall(stream)
                    require(len(messages) <= 1, 'Duplicate Burp message')
                    if not messages:
                        continue
                    content = self.message(messages[0])
                    if stream == 'request':
                        first = content.split(b'\n',1)[0].rstrip(b'\r').decode('ascii', errors='strict').split(' ')
                        require(len(first) == 3 and first[2] in {'HTTP/1.0','HTTP/1.1','HTTP/2'}, 'Invalid request line')
                        path = urlsplit(url).path or '/'
                        query = urlsplit(url).query
                        require(first[1] == path + ('?'+query if query else ''), 'Request path differs from export URL')
                        if expected == 'item': require(first[0] == method, 'Request method differs from metadata')
                        header_block = content.split(b'\r\n\r\n', 1)[0]
                        hosts = [line.split(b':',1)[1].strip().decode('ascii') for line in header_block.split(b'\r\n')[1:] if line.lower().startswith(b'host:')]
                        require(len(hosts) == 1, 'Imported request requires exactly one Host header')
                        authority = normalize_target(parsed.scheme + '://' + hosts[0] + '/')
                        require(authority.host == parsed.host and authority.port == parsed.port, 'Request Host differs from export URL')
                    name = f'{index}/{pair}/{stream}'
                    artifacts[name] = content
                    refs.append(name)
            entries.append({'index': index, 'kind': expected, 'url': url, 'scope_target': parsed.display,
                            'metadata': metadata, 'artifact_names': refs, 'status': 'imported_unverified'})
        return self.store.save(program_id, 'burp_import', {'source': 'burp_xml', 'entries': entries, 'execution_enabled': False}, artifacts, targets=targets)


def register(commands):
    commands = commands.add_parser('burp', help='Read-only Burp XML import').add_subparsers(dest='burp_command', required=True)
    commands.add_parser('status')
    importer = commands.add_parser('import')
    importer.add_argument('file', type=Path)
    importer.add_argument('--program', required=True)
    listing = commands.add_parser('list'); listing.add_argument('--program')
    show = commands.add_parser('show'); show.add_argument('record_id')
    export = commands.add_parser('export'); export.add_argument('record_id'); export.add_argument('name'); export.add_argument('destination', type=Path)


def dispatch(args, database):
    adapter = BurpXmlAdapter(database)
    try:
        if args.burp_command == 'status': result = adapter.status()
        elif args.burp_command == 'import':
            with args.file.open('rb') as source: raw = source.read(10*1024*1024+1)
            result = adapter.ingest(args.program, raw)
        elif args.burp_command == 'list': result = adapter.store.list(args.program, 'burp_import')
        elif args.burp_command == 'show': result = adapter.store.show(args.record_id)
        else: result = adapter.store.export(args.record_id, args.name, args.destination)
    except (ValueError, UnicodeError) as error:
        from .data import DataError
        if isinstance(error, DataError): raise
        raise DataError('Burp import format is invalid; check UTF-8 XML, Base64 messages and matching metadata') from error
    return {'ok': True, 'burp': result, 'execution_enabled': False}
