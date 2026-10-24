"""Offline route fixtures, ICMP error reply layouts, and native traceroute."""

import hashlib
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from emumee.clock import VirtualClock
from emumee.enumeration_programs import enumeration_programs
from emumee.icmp import GuestICMP
from emumee.native import run_native
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_icmp import _Memory, address_value
from tests.fixtures.build_native import build_host_winexec_probe


def route():
    return {'address':'203.0.113.9','round_trip_ms':12,'ttl':57,
            'hops':[{'address':'192.168.1.1','round_trip_ms':1,'ttl':64}, None,
                    {'address':'198.51.100.1','round_trip_ms':7,'ttl':63}]}


def document():
    return {'clock_utc':'2026-10-14T12:00:00Z','icmp_responses':[route()], 'dns_records':[
        {'name':'trace.example','type':'A','data':'203.0.113.9','ttl':60},
        {'name':'1.1.168.192.in-addr.arpa','type':'PTR','data':'router.example','ttl':60},
        {'name':'1.100.51.198.in-addr.arpa','type':'PTR','data':'transit.example','ttl':60},
        {'name':'9.113.0.203.in-addr.arpa','type':'PTR','data':'trace.example','ttl':60}]}


class TracertTests(unittest.TestCase):
    def test_route_validation_and_legacy_fixture_compatibility(self):
        item=route()
        self.assertEqual(load_persona(None,document={'icmp_responses':[item]})['icmp_responses'],[item])
        old={k:v for k,v in item.items() if k!='hops'}
        self.assertEqual(load_persona(None,document={'icmp_responses':[old]})['icmp_responses'],[old])
        hop=item['hops'][0]
        bad=[{**item,'hops':None},{**item,'hops':[None]*255},{**item,'responds':1},
             {**item,'hops':[{'address':'::1','round_trip_ms':1,'ttl':64}]},
             {**item,'hops':[{**hop,'round_trip_ms':True}]},
             {**item,'hops':[{**hop,'ttl':0}]}, {**item,'hops':[{**hop,'extra':True}]}]
        bad += [{**item,'hops':[{**hop,'address':a}]} for a in
                ('203.0.113.9','192.168.1.107','192.168.1.255','127.0.0.1','0.0.0.0','224.0.0.1','255.255.255.255')]
        for value in bad:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError,'icmp_responses'):
                load_persona(None,document={'icmp_responses':[value]})
        self.assertEqual(len(load_persona(None,document={'icmp_responses':[{**old,'hops':[None]*254,'responds':False}]})['icmp_responses'][0]['hops']),254)

    def test_ttl_errors_silent_hops_destination_replies_and_virtual_clock(self):
        for width in (4,8):
            emu=_Memory(width)
            persona=load_persona(None,document=document())
            clock=VirtualClock(persona)
            api=GuestICMP(persona,clock)
            handle=api._create(emu,'',None,[])
            request,options,output=emu.base+0x100,emu.base+0x500,emu.base+0x2000
            emu.mem_write(request,b'hello')
            for ttl,expected,peer,rtt in ((1,11013,'192.168.1.1',1),(2,11010,None,20),
                (3,11013,'198.51.100.1',7),(4,0,'203.0.113.9',12),(255,0,'203.0.113.9',12)):
                with self.subTest(width=width,ttl=ttl):
                    emu.mem_write(options,bytes((ttl,0,0,0)))
                    before=clock.uptime_ms
                    count=api._echo(emu,'IcmpSendEcho',None,[handle,address_value('203.0.113.9'),request,5,options,output,128,20])
                    self.assertEqual(count,0 if expected==11010 else 1)
                    self.assertEqual(clock.uptime_ms,before+rtt)
                    self.assertEqual(api.events[-1]['status'],expected)
                    self.assertFalse(api.events[-1]['network_used'])
                    if peer:
                        self.assertEqual(emu.mem_read(output,4),address_value(peer).to_bytes(4,'little'))
                        self.assertEqual(struct.unpack('<I',emu.mem_read(output+4,4))[0],expected)
                        size=int.from_bytes(emu.mem_read(output+12,2),'little')
                        self.assertEqual(size,5 if expected==0 else 0)
                        pointer=int.from_bytes(emu.mem_read(output+16,width),'little')
                        self.assertEqual(pointer,output+(28 if width==4 else 40) if expected==0 else 0)
            api.responses['203.0.113.9']['responds']=False
            emu.mem_write(options,bytes((4,0,0,0)))
            self.assertEqual(api._echo(emu,'',None,[handle,address_value('203.0.113.9'),request,5,options,output,128,20]),0)
            self.assertEqual(emu.error,11010)

    def run_case(self,root,arch,args,persona=None,program='tracert.exe',child=False,timeout=30):
        persona=persona or load_persona(None,document=document())
        image=enumeration_programs(arch=='x64',persona)[program]
        guest_args=args
        if child:
            import subprocess
            data=bytearray(build_host_winexec_probe(0x8664 if arch=='x64' else 0x14c,'unused-marker'))
            command=(subprocess.list2cmdline([program,*args])+'\0').encode('ascii')
            data[0x700:0x900]=b'\0'*0x200
            data[0x700:0x700+len(command)]=command
            image=bytes(data)
            guest_args=[]
        folder=root/str(len(list(root.iterdir())))
        with patch.object(socket,'socket',side_effect=AssertionError('Host network used')), patch.object(socket,'getaddrinfo',side_effect=AssertionError('Host resolver used')):
            result=run_native(image,inspect_pe(image,'parent.exe' if child else program),persona,folder,[],timeout,2_000_000,guest_args=guest_args)
        self.assertEqual(result['errors'],[])
        report=json.loads((folder/result['engine_report']).read_text(encoding='utf-8'))
        return result,report

    def test_native_routes_ptr_suppression_and_child_invocations(self):
        for arch in ('x86','x64'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                result,report=self.run_case(root,arch,['-h','4','-w','20','trace.example'],child=True)
                text=result['console_output']['stdout']
                for value in ('Tracing route to trace.example [203.0.113.9]','router.example [192.168.1.1]',
                              'Request timed out.','transit.example [198.51.100.1]','trace.example [203.0.113.9]','Trace complete.'):
                    self.assertIn(value,text)
                echoes=[e for e in report['network_events'] if e['event']=='guest_icmp_echo']
                self.assertEqual([e['status'] for e in echoes],[11013]*3+[11010]*3+[11013]*3+[0]*3)
                self.assertTrue(all(e['network_used'] is False for e in report['network_events']))
                self.assertEqual([e['request_ttl'] for e in echoes],[1]*3+[2]*3+[3]*3+[4]*3)
                self.assertTrue(any(e['event']=='virtual_process_create' and e.get('success') for e in report['virtual_process_events']))
                result,report=self.run_case(root,arch,['-d','/4','/h','4','/w','20','trace.example'])
                self.assertEqual(result['guest_exit_code'],0)
                self.assertNotIn('router.example',result['console_output']['stdout'])
                self.assertFalse(any(e['event']=='guest_dns_query' and e['record_type']==12 for e in report['network_events']))

    def test_loopback_unknown_targets_timeouts_and_bad_flags(self):
        for arch in ('x86','x64'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                result,report=self.run_case(root,arch,['127.0.0.1'])
                self.assertIn('localhost [127.0.0.1]',result['console_output']['stdout'])
                self.assertEqual(len([e for e in report['network_events'] if e['event']=='guest_icmp_echo']),3)
                result,report=self.run_case(root,arch,['-d','-h','2','-w','0','203.0.113.250'])
                self.assertEqual(result['guest_exit_code'],0)
                self.assertEqual(result['console_output']['stdout'].count('Request timed out.'),2)
                for args,expected in ((['missing.invalid'],1),(['-h','0','localhost'],87),(['-h','256','localhost'],87),
                                      (['-d','-d','localhost'],87),(['-6','localhost'],87),(['-j','127.0.0.1','localhost'],87)):
                    result,_=self.run_case(root,arch,args)
                    self.assertEqual(result['guest_exit_code'],expected,args)

    def test_full_ttl_range_and_ping_ttl_error_statistics(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            result,report=self.run_case(root,'x64',['-d','-h','255','-w','0','203.0.113.250'],timeout=60)
            self.assertEqual(result['guest_exit_code'],0)
            self.assertEqual(len([e for e in report['network_events'] if e['event']=='guest_icmp_echo']),765)
            self.assertIn('  255',result['console_output']['stdout'])
            persona=load_persona(None,document={'icmp_responses':[{'address':'203.0.113.9','round_trip_ms':1,'ttl':64,
                'hops':[{'address':'192.168.1.1','round_trip_ms':1,'ttl':64}]*128}]})
            for arch in ('x86','x64'):
                result,_=self.run_case(root,arch,['-n','1','203.0.113.9'],persona,program='ping.exe')
                text=result['console_output']['stdout']
                self.assertEqual(result['guest_exit_code'],0)
                self.assertIn('TTL expired in transit.',text)
                self.assertIn('Received = 1',text)
                self.assertNotIn('Average =',text)
