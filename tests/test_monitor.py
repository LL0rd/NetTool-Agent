from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from nettool_agent.engine import Engine
from nettool_agent.monitor import Relay, base_url, save_config


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.calls=[]
        def run(spec,*args):
            self.calls.append(spec['id']);return {'status':'passed','detail':'Measured','durationMS':1,'data':{'password':'local-only'}}
        self.engine=Engine(Path(self.directory.name),'lo',runner=run)
        self.engine.set_checks([{'id':'one','name':'One','kind':'tcp','target':'127.0.0.1'}, {'id':'two','name':'Two','kind':'http','target':'https://example.com'}])
        save_config(Path(self.directory.name)/'monitor.json',{'baseURL':'https://example.com','token':'nta_'+'x'*43,'checkIDs':['one'],'allowRemoteChecks':False})

    def tearDown(self):self.engine.close();self.directory.cleanup()

    def test_summary_allowlist_and_acknowledged_cursor(self):
        self.engine.run('one',scheduled=True);self.engine.run('two',scheduled=True)
        sent=[]
        def transport(base,path,body,token):
            sent.append(body);return {'accepted':[e['id'] for e in body['events']],'commands':[]}
        relay=Relay(self.engine,transport);relay.tick();relay.tick()
        self.assertEqual(len(sent[0]['events']),1);self.assertEqual(sent[0]['events'][0]['checkID'],'one')
        self.assertNotIn('password',json.dumps(sent));self.assertEqual(sent[1]['events'],[])
        self.assertTrue(self.engine.metadata('monitor-last-success'))

    def test_failed_delivery_keeps_cursor_for_retry(self):
        self.engine.run('one',scheduled=True)
        def transport(*args):raise OSError('offline')
        with self.assertRaises(OSError):Relay(self.engine,transport).tick()
        self.assertIsNone(self.engine.metadata('monitor-sequence'))

    def test_remote_command_requires_opt_in_selected_check_and_is_at_most_once(self):
        config=json.loads((Path(self.directory.name)/'monitor.json').read_text());config['allowRemoteChecks']=True
        save_config(Path(self.directory.name)/'monitor.json',config)
        command={'id':'command-1','checkID':'one','expiresAt':(datetime.now(timezone.utc)+timedelta(seconds=80)).isoformat()}
        def transport(base,path,body,token):return {'accepted':[e['id']for e in body['events']],'commands':[command]}
        relay=Relay(self.engine,transport);relay.tick();relay.tick()
        self.assertEqual(self.calls,['one'])
        command['id']='command-2';command['checkID']='two';relay.tick()
        self.assertEqual(self.calls,['one'])
        config['allowRemoteChecks']=False;save_config(Path(self.directory.name)/'monitor.json',config)
        command['id']='command-3';command['checkID']='one';relay.tick()
        self.assertEqual(self.calls,['one'])

    def test_https_only_and_private_file(self):
        for bad in ('http://example.com','https://user:secret@example.com','https://example.com/?secret=x'):
            with self.assertRaises(ValueError):base_url(bad)
        self.assertEqual((Path(self.directory.name)/'monitor.json').stat().st_mode & 0o777,0o600)
