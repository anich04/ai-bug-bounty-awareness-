"""Loopback-only dashboard with per-process bearer authentication."""
import hmac
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
from urllib.parse import urlsplit, parse_qs
from .data import DataStore, DataError, require
from .integrations import IntegrationStore
from .programs import ProgramStore
from .jobs import JobQueue
from .pipeline import FindingPipeline
from .agent_contracts import REGISTRY
from .tool_runtime import ToolRuntime
from .models import ModelRouter
from .analysis import TrafficAnalyzer
from .burp import BurpXmlAdapter


def overview(database):
    with database.transaction() as c:
        objects = [DataStore._read(c,r['id']) for r in c.execute('SELECT id FROM data_objects ORDER BY created_at DESC LIMIT 500')]
    return {'programs': [json.loads(ProgramStore(database).get(p['id']).document) for p in ProgramStore(database).list()],
            'objects': objects, 'jobs': JobQueue(database).list()[-500:], 'engine': JobQueue(database).status(),
            'agents': [definition.describe() for definition in REGISTRY.values()],
            'tool_runs': ToolRuntime(JobQueue(database)).runs()[-100:],
            'integrations': IntegrationStore(database).list()[-200:],
            'models': ModelRouter().health(), 'mode':'Local development · dry run', 'submission_enabled':False}


def make_server(database, port=8765, token=None):
    token = token or secrets.token_urlsafe(32)
    require(isinstance(token,str) and len(token)>=24,'Dashboard token must be at least 24 characters')
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)
        def log_message(self, *_): pass
        def respond(self, status, value, content_type='application/json'):
            body=value if isinstance(value,bytes) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type',content_type)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers(); self.wfile.write(body)
        def authorized(self):
            actual_port=self.server.server_address[1]
            host=f'127.0.0.1:{actual_port}'
            if self.headers.get('Host')!=host: self.respond(403,{'error':'Invalid host'});return False
            origin=self.headers.get('Origin')
            if origin and origin!='http://'+host: self.respond(403,{'error':'Invalid origin'});return False
            supplied=self.headers.get('Authorization','')
            if not hmac.compare_digest(supplied,'Bearer '+token): self.respond(401,{'error':'Open the dashboard using its local access link'});return False
            return True
        def do_GET(self):
            path=urlsplit(self.path)
            static={'/':'dashboard.html','/app.js':'dashboard.js','/style.css':'dashboard.css'}
            if path.path in static:
                host=f'127.0.0.1:{self.server.server_address[1]}'
                if self.headers.get('Host')!=host: self.respond(403,{'error':'Invalid host'});return
                mime={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[path.path]
                self.respond(200,(Path(__file__).parent/'web'/static[path.path]).read_bytes(),mime);return
            if not self.authorized(): return
            try:
                if path.path=='/api/overview': result=overview(database)
                elif path.path=='/api/finding': result=FindingPipeline(database).show(parse_qs(path.query).get('id',[''])[0])
                elif path.path=='/api/analysis-report':
                    result={'markdown':TrafficAnalyzer(database).report(parse_qs(path.query).get('id',[''])[0])}
                elif path.path=='/api/evidence':
                    evidence_id=parse_qs(path.query).get('id',[''])[0]
                    with database.transaction() as c:
                        item=DataStore._read(c,evidence_id); raw=DataStore._artifact(c,item)
                    import base64
                    result={'metadata':item,'base64':base64.b64encode(raw).decode()}
                else:self.respond(404,{'error':'Not found'});return
                self.respond(200,result)
            except (ValueError,KeyError): self.respond(400,{'error':'Requested record is unavailable or failed validation'})
        def do_POST(self):
            if not self.authorized(): return
            if self.path not in {"/api/action", "/api/import-burp"}: self.respond(404,{"error":"Not found"});return
            try:
                require(self.headers.get('Content-Type')=='application/json','Expected JSON')
                bound = 14*1024*1024 if self.path == '/api/import-burp' else 131072
                length=int(self.headers.get('Content-Length','0'));require(0<length<=bound,'Invalid request size')
                from .data_cli import pairs
                value=json.loads(self.rfile.read(length),object_pairs_hook=pairs)
                require(isinstance(value,dict),'Expected object')
                if self.path == '/api/import-burp':
                    require(set(value)=={'program','base64'},'Invalid import fields')
                    require(isinstance(value['base64'],str) and isinstance(value['program'],str),'Invalid import values')
                    raw=base64.b64decode(value['base64'],validate=True)
                    result=BurpXmlAdapter(database).ingest(value['program'],raw)
                    self.respond(200,{'ok':True,'result':result});return
                action=value.get('action'); queue=JobQueue(database); pipeline=FindingPipeline(database)
                if action in {'approve_job','reject_job'}:
                    result=queue.review(value['id'],approve=action=='approve_job')
                elif action=='cancel_job':result=queue.cancel(value['id'])
                elif action=='stop':result=queue.emergency_stop()
                elif action=='resume':result=queue.resume()
                elif action=='review_finding': result=pipeline.review(value['id'],value['decision'],value['checks'],value['rationale'])
                elif action=='draft_report': result=pipeline.draft(value['id'],value['title'],value['questions'])
                elif action=='approve_report':result=pipeline.approve_report(value['id'])
                elif action=='analyze_traffic':result=TrafficAnalyzer(database).run(value['id'])
                else:raise DataError('Unknown dashboard action')
                self.respond(200,{'ok':True,'result':result})
            except (ValueError,KeyError,TypeError,RecursionError):self.respond(400,{'error':'Action could not be completed. Check required fields, current scope, evidence and workflow status.'})
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.daemon_threads=True
    return server,token


def register(commands):
    cmd=commands.add_parser('dashboard',help='Serve the local review dashboard')
    cmd.add_argument('--port',type=int,default=8765)


def serve(database,port):
    require(0<=port<=65535,'Invalid dashboard port')
    server,token=make_server(database,port)
    print('Open local dashboard: http://127.0.0.1:'+str(server.server_address[1])+'/#'+token,flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
