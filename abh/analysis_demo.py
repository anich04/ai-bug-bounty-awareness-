"""Clearly labeled synthetic fixtures for learning and offline benchmarking."""
import base64
import xml.etree.ElementTree as ET

from .analysis import TrafficAnalyzer
from .burp import BurpXmlAdapter
from .data import require
from .policy import Program
from .programs import ProgramStore


def demo_xml():
    host = 'training.local.test'
    fixtures = [
        ('/private-profile', 'GET', {'Origin':'https://other.test', 'Cookie':'session=LAB_ONLY'},
         200, {'Content-Type':'application/json','Access-Control-Allow-Origin':'https://other.test','Access-Control-Allow-Credentials':'true'},
         b'{"email":"alice@example.test","address":"Fictional lab address"}'),
        ('/login', 'GET', {}, 200, {'Set-Cookie':'sessionid=LAB_ONLY; Path=/'}, b'Lab session'),
        ('/.env', 'GET', {}, 200, {'Content-Type':'text/plain'}, b'APP_ENV=training\nDB_PASSWORD=LAB_ONLY_NOT_A_REAL_SECRET\n'),
        ('/go?next=https%3A%2F%2Fother.test%2F', 'GET', {}, 302, {'Location':'https://other.test/'}, b''),
        ('/error', 'GET', {}, 500, {'Content-Type':'text/plain'}, b'Traceback (most recent call last):\n  File "lab.py", line 1\nValueError: synthetic fixture\n'),
        ('/catalog', 'GET', {'Origin':'https://other.test'}, 200, {'Content-Type':'application/json','Access-Control-Allow-Origin':'*'}, b'{"category":"public"}'),
        ('/.env.production', 'GET', {}, 404, {'Content-Type':'text/plain'}, b'DB_PASSWORD=LAB_ONLY_NOT_A_REAL_SECRET\nAPP_ENV=example\n'),
        ('/no-header', 'GET', {}, 200, {}, b'Public page without security headers'),
    ]
    root = ET.Element('items')
    for path, method, headers, status, response_headers, body in fixtures:
        request = (method+' '+path+' HTTP/1.1\r\nHost: '+host+'\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode()
        response = ('HTTP/1.1 '+str(status)+' Fixture\r\n'+''.join(k+': '+v+'\r\n' for k,v in response_headers.items())+'Content-Length: '+str(len(body))+'\r\n\r\n').encode()+body
        item = ET.SubElement(root, 'item')
        for name, value in [('url','https://'+host+path),('method',method),('status',str(status))]:
            ET.SubElement(item,name).text=value
        for name, raw in [('request',request),('response',response)]:
            ET.SubElement(item,name,base64='true').text=base64.b64encode(raw).decode()
    return ET.tostring(root)


def run_demo(database):
    document = {'id':'analysis-training', 'name':'Synthetic training captures - not real target findings',
        'authorization_status':'confirmed', 'authorization_source':'Generated local fixture only; no network requests or real credentials.',
        'valid_until':'2099-01-01T00:00:00Z',
        'scope':[{'id':'training','effect':'include','host':'training.local.test','schemes':['https'],'ports':[443],'path_prefix':'/'}],
        'actions':[{'action':'analyze_http','allowed':True,'requires_approval':True}],
        'rate_limit':{'requests':5,'window_seconds':60}}
    program = Program.from_dict(document)
    programs = ProgramStore(database)
    existing = next((p for p in programs.list() if p['id']==program.id), None)
    if existing: require(programs.get(program.id).revision == program.revision, 'Training program exists with a different policy')
    else: programs.save(program)
    adapter = BurpXmlAdapter(database)
    records = adapter.store.list(program.id,'burp_import')
    source = next((r for r in records if adapter.store.bytes(r['id'],'export.xml')==demo_xml()), None)
    source = source or adapter.ingest(program.id,demo_xml())
    result = TrafficAnalyzer(database).run(source['id'])
    rules = [candidate['rule'] for item in result['payload']['results'] for candidate in item['candidates']]
    require(sorted(rules)==sorted(['credentialed_cors','session_cookie','exposed_config','external_redirect','server_trace']), 'Synthetic benchmark did not match expected detections')
    return {'label':'Synthetic learning demo only; not a finding on Mercado Libre or any live target',
        'fixtures':8, 'expected_candidates':5, 'actual_candidates':len(rules), 'false_positive_controls':3,
        'source_record_id':source['id'], 'analysis_record_id':result['id'], 'finding_ids':result['payload']['finding_ids'],
        'network_requests':0, 'automatically_verified_vulnerabilities':0}
