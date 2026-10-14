"""Offline pathping statistics are measured from guest ICMP responses."""

import tempfile
import unittest
from pathlib import Path

from emumee.persona import load_persona
from tests import test_tracert
from tests.test_icmp import _Memory, address_value
from emumee.icmp import GuestICMP


def persona():
    return load_persona(None, document={
        'icmp_responses': [
            {'address':'203.0.113.9','round_trip_ms':10,'ttl':57,
             'reply_pattern':[True,True,False,True,False],
             'hops':[{'address':'192.168.1.1','round_trip_ms':1,'ttl':64}]},
            {'address':'192.168.1.1','round_trip_ms':1,'ttl':64,
             'reply_pattern':[True,False,False,False]}],
        'dns_records': [
            {'name':'loss.example','type':'A','data':'203.0.113.9','ttl':60},
            {'name':'1.1.168.192.in-addr.arpa','type':'PTR','data':'router.example','ttl':60}]})


class PathpingTests(unittest.TestCase):
    run_case = test_tracert.TracertTests.run_case

    def test_loss_patterns_validate_repeat_and_reset_with_process(self):
        base={'address':'203.0.113.9','round_trip_ms':1,'ttl':64}
        for pattern in ([],[1],[None],'yes',[True]*1025):
            with self.subTest(pattern=str(pattern)[:30]), self.assertRaisesRegex(ValueError,'reply_pattern'):
                load_persona(None,document={'icmp_responses':[{**base,'reply_pattern':pattern}]})
        model=GuestICMP(load_persona(None,document={'icmp_responses':[{**base,'reply_pattern':[True,False]}]}))
        memory=_Memory(8)
        handle=model._create(memory,'',None,[])
        params=[handle,address_value(base['address']),memory.base+0x100,0,0,memory.base+0x2000,128,20]
        self.assertEqual([model._echo(memory,'IcmpSendEcho',None,params) for _ in range(5)],[1,0,1,0,1])
        self.assertEqual([e['reply_pattern_index'] for e in model.events],[0,1,0,1,0])
        model.cleanup_process(memory,memory.get_current_process())
        self.assertEqual(model.reply_counters,{})

    def test_native_queries_measure_router_and_destination_loss(self):
        for arch in ('x86','x64'):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                result,report=self.run_case(Path(directory),arch,
                    ['-h','2','-q','4','-p','10','-w','20','loss.example'],persona(),program='pathping.exe',child=True)
                self.assertEqual(result['guest_exit_code'],0)
                output=result['console_output']['stdout']
                for value in ('router.example [192.168.1.1]','Source to Here','This Node/Link',
                              '3/4 = 75%','2/4 = 50%','1/4 = 25%','Trace complete.'):
                    self.assertIn(value,output)
                events=[e for e in report['network_events'] if e['event']=='guest_icmp_echo']
                self.assertEqual(len(events),10)
                self.assertEqual([e['request_ttl'] for e in events],[1,2]+[255]*8)
                self.assertEqual([e['status'] for e in events],[11013,0,0,0,11010,11010,11010,0,11010,11010])
                self.assertTrue(all(e['network_used'] is False for e in report['network_events']))

    def test_numeric_output_unknown_hops_and_validation(self):
        for arch in ('x86','x64'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                result,report=self.run_case(root,arch,['/n','/h','2','/q','2','/p','0','/w','20','loss.example'],persona(),program='pathping.exe')
                self.assertEqual(result['guest_exit_code'],0)
                self.assertNotIn('router.example',result['console_output']['stdout'])
                self.assertFalse(any(e['event']=='guest_dns_query' and e['record_type']==12 for e in report['network_events']))
                result,report=self.run_case(root,arch,['-n','-h','2','-q','1','-p','0','-w','0','203.0.113.250'],program='pathping.exe')
                self.assertEqual(result['guest_exit_code'],0)
                self.assertEqual(len([e for e in report['network_events'] if e['event']=='guest_icmp_echo']),6)
                self.assertIn('* * *',result['console_output']['stdout'])
                self.assertNotIn('100%',result['console_output']['stdout'])
                for args,code in (([],0),(['/?'],0),(['-h','0','localhost'],87),(['-q','0','localhost'],87),
                                  (['-q','1001','localhost'],87),(['-N','localhost'],87),(['-n','-n','localhost'],87),
                                  (['-g','localhost'],87),(['-6','localhost'],87),(['missing.invalid'],1)):
                    result,_=self.run_case(root,arch,args,program='pathping.exe')
                    self.assertEqual(result['guest_exit_code'],code,args)

    def test_default_queries_and_full_hop_range(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            result,report=self.run_case(root,'x64',['-n','-p','0','localhost'],program='pathping.exe')
            self.assertEqual(result['guest_exit_code'],0)
            self.assertIn('0/100 = 0%',result['console_output']['stdout'])
            self.assertEqual(len([e for e in report['network_events'] if e['event']=='guest_icmp_echo']),101)
            result,report=self.run_case(root,'x64',['-n','-h','255','-q','1','-w','0','203.0.113.250'],program='pathping.exe')
            self.assertEqual(result['guest_exit_code'],0)
            self.assertEqual(len([e for e in report['network_events'] if e['event']=='guest_icmp_echo']),765)


if __name__=='__main__':
    unittest.main()
