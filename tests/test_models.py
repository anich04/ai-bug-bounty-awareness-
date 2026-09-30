import json
import unittest
from unittest.mock import patch
from abh.models import ModelRouter, ProviderConfig, parse_response
from abh.data import DataError

class ModelTests(unittest.TestCase):
    def test_disabled_default_and_no_secret_health(self):
        with patch.dict('os.environ', {'OPENAI_API_KEY':'private-key'}):
            health = ModelRouter().health()
            self.assertNotIn('private-key', json.dumps(health))
        with self.assertRaises(DataError): ModelRouter().select('analysis')

    def test_route_and_three_request_contracts(self):
        for name in ('openai','claude','kimi'):
            router = ModelRouter({name: ProviderConfig(name,True,'explicit-model','https://provider.example/api')}, {'analysis':name})
            request = router.request('analysis','Synthetic input')
            self.assertFalse(request['execution_enabled'])
            self.assertEqual(request['body']['model'],'explicit-model')
            self.assertNotIn('Authorization', request)
            with self.assertRaises(DataError): router.select('validation')

    def test_endpoint_validation(self):
        for endpoint in ('http://host/', 'https://user:pass@host/', 'https://host/?key=secret'):
            with self.assertRaises(DataError): ProviderConfig('openai',True,'model',endpoint).validate()

    def test_openai_output_and_usage(self):
        raw = json.dumps({'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':'Evidence is insufficient.'}]}],'usage':{'input_tokens':10,'output_tokens':4}}).encode()
        result = parse_response('openai',raw)
        self.assertEqual(result['usage']['input_tokens'],10)
        self.assertIsNone(result['cost_usd'])

    def test_claude_and_kimi_output(self):
        result = parse_response('claude',b'{"stop_reason":"end_turn","content":[{"type":"text","text":"Review needed"}]}')
        self.assertIsNone(result['usage']['input_tokens'])
        result = parse_response('kimi',b'{"choices":[{"finish_reason":"stop","message":{"content":"Needs evidence"}}],"usage":{"prompt_tokens":3,"completion_tokens":4}}')
        self.assertEqual(result['usage']['output_tokens'],4)

    def test_errors_partial_tool_calls_and_oversize(self):
        for provider, raw in [('openai',b'{"status":"incomplete"}'),('claude',b'{"stop_reason":"tool_use"}'),('kimi',b'{"choices":[]}'),('openai',b'x'*1048577),('openai',b'{"error":{}}')]:
            with self.assertRaises(DataError): parse_response(provider,raw)
