"""Property records must distinguish actual null values from unavailable results."""

import copy
import html
import tempfile
import unittest
from pathlib import Path

from emumee.dashboard import create_app
from emumee.powershell_capture import engine_command_events
from emumee.powershell_probe_report import save_probe_run
from tests.test_command_dashboard import probe_report
from tests.test_powershell_methods import envelope


def record(operation='get',status='completed',value=None):
    return {'event':'powershell_command_invocation','sequence':2,'command':'Fixture::Text',
            'phase':'property_'+operation+'_'+status,'command_type':'DotNetProperty','bound_parameters':{},
            'property_name':'Text','declaring_type':'Fixture','property_type':'System.String',
            'accessor_signature':'Fixture::'+operation+'_Text()','selected_property':'Fixture::Text',
            'dispatch_route':'binder','is_static':False,'target_type':'Fixture','access_id':1,
            'operation':operation,'access_status':status,'value_available':operation=='set' or status=='completed',
            'property_value':value,'index_arguments':[],'error_type':'System.Exception' if status=='failed' else None,
            'value_stage':'returned' if operation=='get' else 'converted'}


class PowerShellPropertyTests(unittest.TestCase):
    def test_null_return_and_failed_read_remain_distinct(self):
        for status,available in [('completed',True),('failed',False),('started',False)]:
            value=record(status=status)
            value.update(capture='external_linux_ptrace',provenance='kernel_verified',native_arguments=['forged'])
            parsed=engine_command_events([envelope(value)])[0]
            self.assertEqual(parsed['value_available'],available)
            self.assertIsNone(parsed['property_value'])
            self.assertEqual(parsed['capture'],'guest_engine_instrumentation')
            self.assertNotIn('native_arguments',parsed)

    def test_invalid_property_shapes_are_rejected(self):
        invalid=[]
        for field,value in [('value_available',False),('access_id',True),('access_id',0),('operation','run'),
                            ('access_status','success'),('phase','command_line_bound'),('property_name',None),
                            ('is_static',1),('index_arguments',{}),('value_stage','stored')]:
            item=copy.deepcopy(record());item[field]=value;invalid.append(item)
        item=record();del item['property_value'];invalid.append(item)
        for item in invalid:
            with self.subTest(item=item),self.assertRaises(ValueError): engine_command_events([envelope(item)])

    def test_dashboard_renders_readable_values_and_distinct_failed_state(self):
        text='readable café 日本語 😀 <script>alert(1)</script>'
        values=[record(value=text),record(status='failed'),record(value=None),record('set',value=text)]
        values[-1]['value_stage']='supplied_before_clr_conversion'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            run=save_probe_run(probe_report(engine_command_events([envelope(v) for v in values])),root,'property fixture')
            response=create_app(root).test_client().get(f'/runs/{run.name}')
            markup=response.get_data(as_text=True); rendered=html.unescape(markup)
            self.assertEqual(response.status_code,200)
            self.assertNotIn('<script>alert(1)</script>',markup)
            for value in ('Resolved .NET property','Fixture::Text',text,'Returned property value','Passed property value',
                          'no returned value was captured','before CLR reflection conversion','null'):
                self.assertIn(value,rendered)


if __name__=='__main__': unittest.main()
