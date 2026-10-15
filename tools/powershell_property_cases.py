"""Harmless property accesses with independently known names and values."""

from tools.powershell_obfuscation_cases import TEXT, decode, compressed_layer


PRELUDE = r'''
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
namespace EmumeePropertyFixture {
 public class Probe {
  public int Gets, Sets;
  string text;
  public virtual string Text { get { Gets++; return text; } set { Sets++; text=value; } }
  public static string Global { get; set; }
  public int Number { get; set; }
  public int? Optional { get; set; }
  int[] numbers;
  public int[] Numbers { get { return numbers; } set { numbers=value; value[0]=99; } }
  public string Empty { get { return ""; } }
  public string Null { get { return null; } }
  public string ThrowRead { get { Gets++; throw new InvalidOperationException("read failure"); } }
  public string ThrowWrite { set { Sets++; throw new InvalidOperationException("write failure"); } }
  public object Opaque { get { Gets++; return new Trap(); } }
  Dictionary<int,string> items=new Dictionary<int,string>();
  public string this[int index] { get { Gets++; return items[index]; } set { Sets++; items[index]=value+"|stored"; } }
 }
 public class Derived : Probe {
  public override string Text { get { return "derived:"+base.Text; } set { base.Text=value; } }
 }
 public class Convertible {
  public static int Calls;
  public override string ToString() { Calls++; return "convert-once"; }
 }
 public class Trap : IEnumerable {
  public static int Calls;
  public string Getter { get { Calls++; return "trap"; } }
  public override string ToString() { Calls++; return "trap"; }
  public IEnumerator GetEnumerator() { Calls++; throw new Exception("trap enumerated"); }
 }
}
'@
$p=[EmumeePropertyFixture.Probe]::new()
'''


def expected(name, operation, value=None, status='completed', **extra):
    return {'property_name':name,'operation':operation,'access_status':status,
            'property_value':value,'declaring_type':'EmumeePropertyFixture.Probe',**extra}


def cases():
    result=[]
    def add(name,body,matches):
        result.append({'name':name,'source':PRELUDE+body+"\n[Console]::WriteLine('CASE-DONE="+name+"')",'expected':matches})
    counts=";if($p.Gets -ne 1 -or $p.Sets -ne 1){throw 'Accessor count differs'}"
    dynamic="$name=-join [char[]](84,101,120,116);$p.$name=("+decode(TEXT)+");$value=$p.('Te'+'xt')"
    add('dynamic-property-name',dynamic+counts,[expected('Text','set',TEXT),expected('Text','get',TEXT)])
    add('encoded-property-name','$name=('+decode('Text')+');$p.$name=('+decode(TEXT)+');$null=$p.$name'+counts,
        [expected('Text','set',TEXT),expected('Text','get',TEXT)])
    add('powershell-class-property','class PSPropertyFixture { [string]$Text };$p=[PSPropertyFixture]::new();'
        '$name=('+decode('Text')+');$p.$name=('+decode(TEXT)+');$null=$p.$name',
        [expected('Text','set',TEXT,declaring_type='PSPropertyFixture'),expected('Text','get',TEXT,declaring_type='PSPropertyFixture')])
    add('static-property',"$type=[type]('EmumeePropertyFixture.'+'Probe');$name=('Glo'+'bal');$type::$name=("+decode(TEXT)+");$value=$type::$name",
        [expected('Global','set',TEXT,is_static=True),expected('Global','get',TEXT,is_static=True)])
    add('converted-value',"$p.('Num'+'ber')=('4'+'2');$value=$p.Number",[expected('Number','set',42),expected('Number','get',42)])
    add('nullable-values',"$p.Optional=$null;$null=$p.Optional;$p.Optional=('4'+'2');$null=$p.Optional",
        [expected('Optional','set',None),expected('Optional','get',None),expected('Optional','set',42),expected('Optional','get',42)])
    add('setter-mutates-array',"$p.Numbers=[int[]]@(1,2);$null=$p.Numbers",
        [expected('Numbers','set',[1,2]),expected('Numbers','get',[99,2])])
    add('empty-and-null',"$null=$p.('Em'+'pty');$null=$p.('Nu'+'ll')",[expected('Empty','get',''),expected('Null','get',None)])
    add('throwing-getter',"try{$null=$p.('Throw'+'Read')}catch{};if($p.Gets -ne 1){throw 'Getter ran twice'}",
        [expected('ThrowRead','get',None,status='failed',value_available=False)])
    add('throwing-setter',"try{$p.('Throw'+'Write')=("+decode(TEXT)+")}catch{};if($p.Sets -ne 1){throw 'Setter ran twice'}",
        [expected('ThrowWrite','set',TEXT,status='failed')])
    add('conversion-once',"$p.Text=[EmumeePropertyFixture.Convertible]::new();if([EmumeePropertyFixture.Convertible]::Calls -ne 1){throw 'Conversion count differs'};$null=$p.Text"+counts,
        [expected('Text','set','convert-once'),expected('Text','get','convert-once')])
    add('expressions-once',"$script:names=0;$script:values=0;function Get-Name{$script:names++;return ('Te'+'xt')};function Get-Once{$script:values++;return ("+decode(TEXT)+")};"
        "$p.(Get-Name)=(Get-Once);$null=$p.Text;if($script:names -ne 1 -or $script:values -ne 1){throw 'Expression evaluated twice'}"+counts,
        [expected('Text','set',TEXT),expected('Text','get',TEXT)])
    add('virtual-property',"$p=[EmumeePropertyFixture.Derived]::new();"+dynamic+counts,
        [expected('Text','set',TEXT,declaring_type='EmumeePropertyFixture.Derived'),expected('Text','get','derived:'+TEXT,declaring_type='EmumeePropertyFixture.Derived')])
    reflection="$prop=[EmumeePropertyFixture.Probe].GetProperty(('Te'+'xt'));$prop.SetValue($p,("+decode(TEXT)+"));$value=$prop.GetValue($p)"
    add('reflection-property',reflection+counts,[expected('Text','set',TEXT,dispatch_route='reflection',value_stage='supplied_before_clr_conversion'),expected('Text','get',TEXT,dispatch_route='reflection')])
    add('reflection-virtual-property',"$p=[EmumeePropertyFixture.Derived]::new();"+reflection+counts,
        [expected('Text','set',TEXT,declaring_type='EmumeePropertyFixture.Derived'),expected('Text','get','derived:'+TEXT,declaring_type='EmumeePropertyFixture.Derived')])
    add('property-adapter',"$name=('Te'+'xt');$p.PSObject.Properties[$name].Value=("+decode(TEXT)+");$value=$p.PSObject.Properties[$name].Value"+counts,
        [expected('Text','set',TEXT,dispatch_route='adapter'),expected('Text','get',TEXT,dispatch_route='adapter')])
    add('indexer',"$p[('4'+'2')]=("+decode(TEXT)+");$value=$p[42]"+counts,
        [expected('Item','set',TEXT,index_arguments=[42]),expected('Item','get',TEXT+'|stored',index_arguments=[42])])
    add('explicit-accessor',"$p.('set_'+'Text')(("+decode(TEXT)+"));$value=$p.('get_'+'Text')()"+counts,
        [expected('Text','set',TEXT),expected('Text','get',TEXT)])
    add('opaque-return-no-getters',"$null=$p.Opaque;if($p.Gets -ne 1 -or [EmumeePropertyFixture.Trap]::Calls -ne 0){throw 'Snapshot executed user code'}",
        [expected('Opaque','get',{'type':'EmumeePropertyFixture.Trap','capture_status':'opaque_value_not_evaluated'})])
    for depth in (8,40):
        body=dynamic+counts
        for layer in range(depth): body=compressed_layer(body,layer)
        add(f'compressed-{depth}-layers',body,[expected('Text','set',TEXT),expected('Text','get',TEXT)])
    return result
