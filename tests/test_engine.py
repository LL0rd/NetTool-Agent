import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import ipaddress
import struct
from nettool_agent.engine import Engine, validate_checks
from nettool_agent import ipv6, checks


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.now=[1000000.0];self.calls=[]
        def runner(spec,interface,routers):self.calls.append(spec['id']);return {'status':'passed','detail':'fixture','durationMS':2,'data':None}
        self.engine=Engine(Path(self.directory.name),'eth0',runner=runner,clock=lambda:self.now[0])
    def tearDown(self):self.engine.close();self.directory.cleanup()
    def spec(self,**changes):return dict({'id':'router','name':'Router','kind':'tcp','target':'192.0.2.1','port':443,'intervalSeconds':60,'enabled':False},**changes)
    def test_only_explicit_schedules_run_and_interval_is_enforced(self):
        self.engine.set_checks([self.spec()]);self.engine.tick();self.assertEqual(self.calls,[])
        self.engine.set_checks([self.spec(enabled=True)]);self.engine.tick();self.engine.tick();self.assertEqual(self.calls,['router'])
        self.now[0]+=60;self.engine.tick();self.assertEqual(len(self.calls),2)
        history=self.engine.history();self.assertEqual(len(history['events']),2);self.assertGreater(history['events'][0]['sequence'],history['events'][1]['sequence'])
    def test_history_retention_sequence_resume_and_delete(self):
        self.engine.set_checks([self.spec()]);first=self.engine.run('router')['event'];self.now[0]+=31*86400
        self.engine.run('router');self.assertEqual(len(self.engine.history()['events']),1)
        self.assertEqual(len(self.engine.history(after=first['sequence'])['events']),1)
        self.engine.delete_history();self.assertEqual(self.engine.history()['events'],[])
    def test_failed_measurements_do_not_fabricate_success_or_leak_credentials(self):
        self.engine.set_checks([self.spec()]);self.engine.runner=lambda *a: (_ for _ in ()).throw(OSError('secret token and router password'))
        event=self.engine.run('router')['event'];self.assertEqual(event['status'],'unavailable');self.assertNotIn('secret',json.dumps(event))
    def test_config_survives_restart_without_disclosing_router_secrets(self):
        self.engine.set_checks([self.spec()]);self.engine.config['routers']={'home':{'password':'secret'}}
        self.assertNotIn('secret',json.dumps(self.engine.status()))
        second=Engine(Path(self.directory.name),'eth0')
        try:self.assertEqual(second.status()['checks'][0]['target'],'192.0.2.1')
        finally:second.close()
        self.assertEqual((Path(self.directory.name)/'checks.json').stat().st_mode&0o777,0o600)
    def test_validation_rejects_command_arguments_duplicate_ids_and_unbounded_jobs(self):
        for candidate in [[self.spec(target='-oProxyCommand=bad')],[self.spec(intervalSeconds=1)],[self.spec(),self.spec()],[self.spec(port=True)],[self.spec(kind='iperf',enabled=True)],[self.spec(unknown='value')]]:
            with self.assertRaises(ValueError):validate_checks(candidate)
        with self.assertRaises(ValueError):self.engine.history(limit=201)
        with self.assertRaises(ValueError):self.engine.run('not-configured')
    def test_dhcp_cooldown_is_shared_with_legacy_endpoint(self):
        from nettool_agent.server import AgentService, APIError
        self.engine.set_checks([self.spec(kind='dhcp')])
        service=AgentService('eth0','x'*32,engine=self.engine,probe=lambda *a:{'offers':[]},clock=lambda:self.now[0])
        service.discover(3)
        event=self.engine.run('router')['event']
        self.assertEqual(event['status'],'unavailable');self.assertEqual(self.calls,[])
        self.now[0]+=61
        self.engine.run('router');self.assertEqual(self.calls,['router'])
        with self.assertRaises(APIError) as error:service.discover(3)
        self.assertEqual(error.exception.status,429)

    def test_manual_rate_limit_and_metadata(self):
        self.engine.set_checks([self.spec()]);self.engine.run('router')
        with self.assertRaises(RuntimeError):self.engine.run('router')
        self.engine.metadata('cloud-sequence','17');self.assertEqual(self.engine.metadata('cloud-sequence'),'17')

    def test_observation_baselines_ignore_absence_and_survive_restart(self):
        spec=self.spec(kind='ssdp')
        def result(*addresses):return {'status':'passed','data':{'devices':[{'address':a,'usn':a} for a in addresses]}}
        self.assertFalse(self.engine.observation_changed(spec,result('192.0.2.1')))
        self.assertFalse(self.engine.observation_changed(spec,result()))
        self.assertTrue(self.engine.observation_changed(spec,result('192.0.2.2')))
        self.assertFalse(self.engine.observation_changed(spec,result('192.0.2.1','192.0.2.2')))
        other=Engine(Path(self.directory.name),'eth0')
        try:self.assertFalse(other.observation_changed(spec,result('192.0.2.2')))
        finally:other.close()

    def test_dhcp_changes_compare_options_not_offer_address_or_timing(self):
        spec=self.spec(kind='dhcp')
        def result(address='192.0.2.10',dns='192.0.2.1'):
            return {'status':'passed','data':{'offers':[{'serverIdentifier':'192.0.2.1','offeredAddress':address,'responseMS':42,'options':{'6':dns}}]}}
        self.assertFalse(self.engine.observation_changed(spec,result()))
        self.assertFalse(self.engine.observation_changed(spec,result(address='192.0.2.11')))
        self.assertTrue(self.engine.observation_changed(spec,result(dns='192.0.2.2')))
        for kind,minimum in [('dhcp',3600),('ssdp',300),('ipv6-observe',300),('openwrt',300)]:
            with self.assertRaises(ValueError):validate_checks([self.spec(kind=kind,target='router',intervalSeconds=minimum-60,enabled=True)])
            self.assertEqual(validate_checks([self.spec(kind=kind,target='router',intervalSeconds=minimum,enabled=True)])[0]['enabled'],True)


class IPv6Tests(unittest.TestCase):
    def frame(self,body,next_header=58,hop=255,source='fe80::1',destination='ff02::1'):
        src=ipaddress.IPv6Address(source).packed;dst=ipaddress.IPv6Address(destination).packed
        body=bytearray(body);pseudo=src+dst+len(body).to_bytes(4,'big')+bytes([0,0,0,next_header])
        index=2 if next_header==58 else 6;body[index:index+2]=ipv6.checksum(pseudo+body).to_bytes(2,'big')
        header=bytes([0x60,0,0,0])+len(body).to_bytes(2,'big')+bytes([next_header,hop])+src+dst
        return b'\0'*12+b'\x86\xdd'+header+body
    def test_valid_ra_and_malformed_options_or_hop_limit(self):
        prefix=bytes([3,4,64,192])+struct.pack('!III',3600,1800,0)+ipaddress.IPv6Address('2001:db8::').packed
        ra=bytes([134,0,0,0,64,192])+struct.pack('!HII',1800,0,0)+prefix
        frame=self.frame(ra);decoded=ipv6.decode(frame)
        self.assertEqual(decoded['prefixes'][0]['prefix'],'2001:db8::/64');self.assertTrue(decoded['managed'])
        self.assertIsNone(ipv6.decode(self.frame(ra,hop=64)))
        self.assertIsNone(ipv6.decode(self.frame(ra,source='2001:db8::1')))
        for length in range(len(frame)):self.assertIsNone(ipv6.decode(frame[:length]))
        self.assertIsNone(ipv6.decode(self.frame(ra[:16]+b'\x03\x00')))
    def test_dhcpv6_retains_option_presence_not_duid(self):
        message=bytes([2,1,2,3])+struct.pack('!HH',2,6)+b'SECRET'
        udp=struct.pack('!HHHH',547,546,8+len(message),0)+message
        decoded=ipv6.decode(self.frame(udp,next_header=17,destination='fe80::2',hop=64))
        self.assertEqual(decoded['message'],'ADVERTISE');self.assertNotIn('SECRET',json.dumps(decoded));self.assertEqual(decoded['options'],[{'code':2,'length':6}])


class CheckTests(unittest.TestCase):
    def test_real_loopback_dns_and_isolated_failure(self):
        self.assertEqual(checks.resolve('127.0.0.1'),['127.0.0.1'])
        result=checks.run_isolated({'id':'dns','kind':'dns','target':'127.0.0.1'},'lo',{})
        self.assertEqual(result['status'],'passed');self.assertEqual(result['data']['addresses'],['127.0.0.1'])
    def test_router_rpc_is_read_only_and_does_not_return_credentials(self):
        calls=[]
        def fake(address,payload,ca):
            calls.append(payload['params'][1:3]);obj,method=payload['params'][1:3]
            if method=='login':value={'ubus_rpc_session':'SESSION'}
            elif obj=='uci':value={'values':{'host':{'.type':'host','name':'Printer','ip':'192.0.2.3','password':'secret'},'other':{'.type':'wifi','key':'secret'}}}
            elif method=='devices':value={'devices':['wlan0']}
            else:value={'up':True}
            return {'result':[0,value]}
        with patch.object(checks,'http_json',side_effect=fake):result=checks.openwrt({'url':'https://router.example/ubus','username':'nettool','password':'secret'})
        self.assertEqual(calls,[['session','login'],['system','board'],['network.interface','dump'],['dhcp','ipv4leases'],['dhcp','ipv6leases'],['uci','get'],['iwinfo','devices'],['iwinfo','assoclist']]);self.assertNotIn('secret',json.dumps(result))
        self.assertEqual(result['dhcp.configuration'],[{'.type':'host','name':'Printer','ip':'192.0.2.3'}])
