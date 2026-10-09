import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
import base64
from abh.dashboard import make_server
from abh.database import SQLiteDatabase

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.db=SQLiteDatabase(Path(self.temp.name)/'db');self.db.initialize()
        self.server,self.token=make_server(self.db,0)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.close)
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join()
    def request(self,path,method='GET',body=None,headers=None,auth=True):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_address[1],timeout=3)
        h={'Authorization':'Bearer '+self.token} if auth else {}
        if body is not None:h['Content-Type']='application/json';body=json.dumps(body)
        h.update(headers or {})
        connection.request(method,path,body,h);response=connection.getresponse();data=response.read();status=response.status;connection.close();return status,data
    def test_static_is_public_api_requires_token(self):
        self.assertEqual(self.request('/',auth=False)[0],200)
        self.assertEqual(self.request('/api/overview',auth=False)[0],401)
        status,data=self.request('/api/overview');self.assertEqual(status,200)
        self.assertFalse(json.loads(data)['submission_enabled'])
    def test_foreign_host_and_origin_blocked(self):
        self.assertEqual(self.request('/api/overview',headers={'Host':'attacker.example'})[0],403)
        self.assertEqual(self.request('/api/action','POST',{'action':'stop'},headers={'Origin':'https://attacker.example'})[0],403)
    def test_authenticated_emergency_stop(self):
        status,_=self.request('/api/action','POST',{'action':'stop'});self.assertEqual(status,200)
        _,data=self.request('/api/overview');self.assertTrue(json.loads(data)['engine']['stopped'])
    def test_unknown_route_and_bad_action(self):
        self.assertEqual(self.request('/api/missing')[0],404)
        self.assertEqual(self.request('/api/action','POST',{'action':'arbitrary_shell'})[0],400)
        self.assertEqual(self.request('/api/missing','POST',{'action':'stop'})[0],404)

    def test_analysis_end_to_end_is_authenticated(self):
        from abh.analysis_demo import run_demo
        result=run_demo(self.db)
        self.assertEqual(self.request('/api/action','POST',{'action':'analyze_traffic','id':result['source_record_id']},auth=False)[0],401)
        status,body=self.request('/api/action','POST',{'action':'analyze_traffic','id':result['source_record_id']})
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['result']['payload']['candidate_count'],5)
        status,body=self.request('/api/analysis-report?id='+result['analysis_record_id'])
        self.assertEqual(status,200);self.assertIn('SYNTHETIC',json.loads(body)['markdown'])
        self.assertEqual(self.request('/api/analysis-report?id='+result['analysis_record_id'],auth=False)[0],401)

    def test_burp_upload_scope_and_authentication(self):
        from abh.analysis_demo import run_demo, demo_xml
        run_demo(self.db)
        body={'program':'analysis-training','base64':base64.b64encode(demo_xml()).decode()}
        self.assertEqual(self.request('/api/import-burp','POST',body,auth=False)[0],401)
        self.assertEqual(self.request('/api/import-burp','POST',body,headers={'Origin':'https://other.test'})[0],403)
        self.assertEqual(self.request('/api/import-burp','POST',body)[0],200)
        body['base64']=base64.b64encode(demo_xml().replace(b'training.local.test',b'outside.test')).decode()
        self.assertEqual(self.request('/api/import-burp','POST',body)[0],400)
        self.assertEqual(self.request('/api/import-burp','POST',{'program':'analysis-training','base64':'!!!'})[0],400)
