import base64
import contextlib
import gzip
import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from abh.analysis import TrafficAnalyzer, detect, message
from abh.analysis_demo import run_demo
from abh.burp import BurpXmlAdapter
from abh.cli import main
from abh.data import DataError, DataStore
from abh.database import SQLiteDatabase
from abh.integrations import IntegrationStore
from abh.pipeline import FindingPipeline
from abh.policy import Program
from abh.programs import ProgramStore
from test_scope import policy


def capture(path='/app', status=200, headers=None, body=b'{}', request_headers=None, method='GET'):
    request = (method+' '+path+' HTTP/1.1\r\nHost: example.test\r\n'+''.join(k+': '+v+'\r\n' for k,v in (request_headers or {}).items())+'\r\n').encode()
    response = ('HTTP/1.1 '+str(status)+' Test\r\n'+''.join(k+': '+v+'\r\n' for k,v in (headers or {}).items())+'Content-Length: '+str(len(body))+'\r\n\r\n').encode()+body
    root = ET.Element('items'); item = ET.SubElement(root,'item')
    for k,v in [('url','https://example.test'+path),('method',method),('status',str(status))]: ET.SubElement(item,k).text=v
    for k,v in [('request',request),('response',response)]: ET.SubElement(item,k,base64='true').text=base64.b64encode(v).decode()
    return request, response, ET.tostring(root)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.db=SQLiteDatabase(self.root/'db');self.db.initialize()
        self.doc=policy();self.doc['actions'].append({'action':'analyze_http','allowed':True,'requires_approval':True})
        self.program=Program.from_dict(self.doc);ProgramStore(self.db).save(self.program)
        self.adapter=BurpXmlAdapter(self.db);self.analyzer=TrafficAnalyzer(self.db)
        self.addCleanup(self.close_log)

    def close_log(self):
        logger=logging.getLogger('abh')
        for handler in logger.handlers[:]:handler.close();logger.removeHandler(handler)

    def run_capture(self, **kwargs):
        request,response,raw=capture(**kwargs)
        source=self.adapter.ingest(self.program.id,raw)
        return source,self.analyzer.run(source['id']),request,response

    def test_cors_candidate_and_full_raw_provenance(self):
        source,result,request,response=self.run_capture(body=b'{"email":"test@example.test"}',
            headers={'Access-Control-Allow-Origin':'https://other.test','Access-Control-Allow-Credentials':'true'},
            request_headers={'Origin':'https://other.test','Cookie':'session=SECRET_COOKIE'})
        self.assertEqual(result['payload']['candidate_count'],1)
        candidate=result['payload']['results'][0]['candidates'][0]
        self.assertEqual(candidate['rule'],'credentialed_cors')
        state=FindingPipeline(self.db).show(candidate['finding_id'])
        self.assertEqual(state['status'],'needs_validation');self.assertEqual(len(state['detections']),1)
        self.assertEqual([x['kind'] for x in state['provenance']],['asset','endpoint','observation','finding'])
        with self.db.transaction() as c:
            originals=[DataStore._artifact(c,e) for e in state['evidence']]
        self.assertCountEqual(originals,[request,response])
        self.assertNotIn('SECRET_COOKIE',self.analyzer.report(result['id']))
        self.assertNotIn('test@example.test',self.analyzer.report(result['id']))
        self.assertFalse(candidate['automatically_verified'])

    def test_cors_false_positive_controls(self):
        for status,body,cookie,creds,allowed in [(200,b'{"category":"public"}',True,True,'https://other.test'),
            (403,b'{"email":"test@example.test"}',True,True,'https://other.test'),
            (200,b'{"email":"test@example.test"}',False,True,'https://other.test'),
            (200,b'{"email":"test@example.test"}',True,False,'https://other.test'),
            (200,b'{"email":"test@example.test"}',True,True,'*')]:
            with self.subTest(status=status,cookie=cookie,creds=creds,allowed=allowed):
                rh={'Origin':'https://other.test'}
                if cookie:rh['Cookie']='session=lab'
                request,response,_=capture(status=status,body=body,request_headers=rh,
                    headers={'Access-Control-Allow-Origin':allowed,'Access-Control-Allow-Credentials':str(creds).lower()})
                self.assertEqual(detect('https://example.test/app',request,response)['candidates'],[])

    def test_preflight_and_same_origin_are_not_cors_bugs(self):
        for method,orig in [('OPTIONS','https://other.test'),('GET','https://example.test')]:
            request,response,_=capture(method=method,request_headers={'Origin':orig,'Cookie':'session=lab'},
                headers={'Access-Control-Allow-Origin':orig,'Access-Control-Allow-Credentials':'true'},body=b'{"email":"test@example.test"}')
            self.assertEqual(detect('https://example.test/app',request,response)['candidates'],[])

    def test_cookie_multiple_headers_and_safe_control(self):
        request,response,_=capture(headers={'Set-Cookie':'sessionid=LAB_VALUE; Path=/'})
        response=response.replace(b'Content-Length:',b'Set-Cookie: analytics=LAB_VALUE\r\nContent-Length:')
        self.assertEqual(len(detect('https://example.test/app',request,response)['candidates']),1)
        for cookie in ['sessionid=LAB_VALUE; Secure; HttpOnly', 'sessionid=; Max-Age=0', 'analytics=LAB_VALUE']:
            request,response,_=capture(headers={'Set-Cookie':cookie})
            self.assertEqual(detect('https://example.test/app',request,response)['candidates'],[])

    def test_exposed_config_redaction_and_status_controls(self):
        source,result,_,_=self.run_capture(path='/app/.env',body=b'APP_ENV=production\nDB_PASSWORD=NEVER_PRINT_SECRET\n')
        self.assertEqual(result['payload']['candidate_count'],1)
        self.assertNotIn('NEVER_PRINT_SECRET',self.analyzer.report(result['id']))
        self.assertIn('DB_PASSWORD',self.analyzer.report(result['id']))
        for status,body in [(403,b'APP_ENV=test\nDB_PASSWORD=SECRET_VALUE\n'),(200,b'<html>documentation</html>\nAPP_ENV=test\nDB_PASSWORD=SECRET_VALUE\n')]:
            req,res,_=capture(path='/app/.env',status=status,body=body)
            self.assertEqual(detect('https://example.test/app/.env',req,res)['candidates'],[])

    def test_redirect_requires_actual_matching_external_location(self):
        path='/app/go?next=https%3A%2F%2Fother.test%2F'
        for location,count in [('https://other.test/',1),('/app/home',0),('https://different.test/',0)]:
            req,res,_=capture(path=path,status=302,headers={'Location':location})
            self.assertEqual(len(detect('https://example.test'+path,req,res)['candidates']),count)

    def test_server_trace_requires_error_and_multiple_markers(self):
        for status,body,count in [(500,b'Traceback (most recent call last):\n  File "lab.py"',1),
                                 (200,b'Traceback (most recent call last):\n  File "example.py"',0),
                                 (500,b'Traceback',0)]:
            req,res,_=capture(status=status,body=body)
            self.assertEqual(len(detect('https://example.test/app',req,res)['candidates']),count)

    def test_duplicate_conflicting_and_truncated_framing(self):
        req,res,_=capture()
        bad=[res.replace(b'Content-Length:',b'Content-Length: 2\r\nContent-Length:'),
            res.replace(b'Content-Length:',b'Transfer-Encoding: chunked\r\nContent-Length:'),res[:-1],
            res.replace(b'Content-Length:',b'Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Origin: https://other.test\r\nContent-Length:')]
        for raw in bad:
            with self.subTest(raw=raw[:80]), self.assertRaises(DataError):message(raw,response=True)

    def test_chunked_and_bounded_gzip(self):
        raw=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n'
        self.assertEqual(message(raw,response=True)[2],b'{}')
        for body,valid in [(b'{}',True),(b'a'*(1024*1024+1),False)]:
            req,res,_=capture(headers={'Content-Encoding':'gzip'},body=gzip.compress(body))
            if valid:self.assertEqual(message(res,response=True)[2],body)
            else:
                with self.assertRaises(DataError):message(res,response=True)

    def test_idempotence_and_corrupt_source_rejected(self):
        source,result,_,_=self.run_capture(headers={'Set-Cookie':'sessionid=LAB_VALUE'})
        self.assertEqual(self.analyzer.run(source['id'])['id'],result['id'])
        self.assertEqual(len(DataStore(self.db).list(self.program.id,'finding')),1)
        with self.db.transaction(write=True) as c:c.execute('UPDATE artifacts SET content=?',(b'corrupt',))
        with self.assertRaises(DataError):self.analyzer.run(source['id'])

    def test_current_scope_and_action_are_enforced(self):
        source,result,_,_=self.run_capture()
        for change in ['expired','denied']:
            document=json.loads(self.program.document)
            if change=='expired':document['valid_until']='2000-01-01T00:00:00Z'
            else:document['actions'][-1]['allowed']=False
            ProgramStore(self.db).save(Program.from_dict(document),replace=True)
            with self.assertRaises(DataError):self.analyzer.run(source['id'])

    def test_analysis_rolls_back_if_persistence_fails(self):
        _,_,raw=capture(headers={'Set-Cookie':'sessionid=LAB_VALUE'})
        source=self.adapter.ingest(self.program.id,raw)
        with patch.object(DataStore,'create',side_effect=DataError('forced')):
            with self.assertRaises(DataError):self.analyzer.run(source['id'])
        self.assertEqual(DataStore(self.db).list(self.program.id),[])
        self.assertEqual(IntegrationStore(self.db).list(self.program.id,'traffic_analysis'),[])

    def test_malformed_response_is_not_a_bug(self):
        req,res,_=capture();root=ET.fromstring(capture()[2])
        root[0].find('response').text=base64.b64encode(b'NOT HTTP').decode()
        source=self.adapter.ingest(self.program.id,ET.tostring(root))
        result=self.analyzer.run(source['id'])
        self.assertEqual(result['payload']['candidate_count'],0)
        self.assertIn('Skipped',result['payload']['results'][0]['notes'][0])

    def test_synthetic_demo_and_cli(self):
        with patch('socket.create_connection',side_effect=AssertionError('No networking')):
            result=run_demo(self.db)
        self.assertEqual(result['actual_candidates'],5)
        self.assertEqual(result['network_requests'],0)
        self.assertEqual(run_demo(self.db)['finding_ids'],result['finding_ids'])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['--root',str(self.root),'init']),0)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['--root',str(self.root),'analysis','demo']),0)
        self.assertEqual(json.loads(output.getvalue())['analysis']['actual_candidates'],5)

    def test_report_rejects_non_analysis_record(self):
        self.assertRaises(DataError,self.analyzer.report,self.adapter.ingest(self.program.id,capture()[2])['id'])

    def test_emergency_stop_blocks_new_analysis(self):
        source=self.adapter.ingest(self.program.id,capture()[2])
        with self.db.transaction(write=True) as c:c.execute('UPDATE engine_control SET stopped=1 WHERE id=1')
        with self.assertRaises(DataError):self.analyzer.run(source['id'])


if __name__=='__main__':unittest.main()
