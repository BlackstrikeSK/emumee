"""Benign .NET calls with known method identities and evaluated arguments."""

from tools.powershell_obfuscation_cases import TEXT, decode, compressed_layer


PRELUDE = r'''
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections;
namespace EmumeeMethodFixture {
 public static class Probe {
  public static string Echo(string value) { Console.WriteLine("STRING="+value); return value; }
  public static int Echo(int value) { Console.WriteLine("INT="+value); return value; }
  public static int TakeNumber(int number) { return number; }
  public static T Identity<T>(T value) { return value; }
  public static string Pack(string prefix, params string[] parts) { return prefix+string.Join("/",parts); }
  public static int Optional(string value, int count=7) { return count; }
  public static void Ping() { Console.WriteLine("PING"); }
  public static void AcceptOpaque(object value) { Console.WriteLine("OPAQUE-ACCEPTED"); }
  public static string StringOnly(string value) { return value; }
  public static void Bump(ref int number, string text) { number++; Console.WriteLine("REF="+text); }
 }
 public class Holder {
  public static int StringCalls;
  string value;
  public Holder(string value) { this.value=value; }
  public string Repeat(int count) { return value+count; }
  public override string ToString() { StringCalls++; return value; }
 }
 public class Base { public virtual string Speak(string value) { return "base"; } public virtual T Generic<T>(T value) { return value; } }
 public class Derived : Base { public override string Speak(string value) { Console.WriteLine("DERIVED="+value); return value; } public override T Generic<T>(T value) { return value; } }
 public interface IProbe { T Run<T>(T value); }
 public class ExplicitProbe : IProbe { T IProbe.Run<T>(T value) { return value; } }
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
'''


def expected(type_name, method, values, **extra):
    return {'declaring_type':type_name,'method_name':method,'values':values,**extra}


def cases():
    prefix='EmumeeMethodFixture.'
    result=[]

    def add(name, body, matches):
        result.append({'name':name,'source':PRELUDE+body+"\n[Console]::WriteLine('CASE-DONE="+name+"')",
                       'expected':matches})

    add('static-dynamic-name', '$type=[type](\'EmumeeMethodFixture.\'+\'Probe\');$method=-join [char[]](69,99,104,111);'
        '$text='+decode(TEXT)+';$type::$method($text);$type::TakeNumber((\'4\'+\'2\'))',
        [expected(prefix+'Probe','Echo',[TEXT]),expected(prefix+'Probe','TakeNumber',[42])])
    add('instance-constructor-zero-arguments', '$text='+decode(TEXT)+
        ';$holder=[EmumeeMethodFixture.Holder]::new($text);'
        '$holder.(\'Re\'+\'peat\')((\'2\'));[EmumeeMethodFixture.Probe]::AcceptOpaque($holder);'
        "if([EmumeeMethodFixture.Holder]::StringCalls -ne 0){throw 'Snapshot invoked ToString'};"
        "$null=$holder.ToString();if([EmumeeMethodFixture.Holder]::StringCalls -ne 1){throw 'ToString count differs'}",
        [expected(prefix+'Holder','.ctor',[TEXT]),expected(prefix+'Holder','Repeat',[2]),expected(prefix+'Holder','ToString',[])])
    add('ref-out', '$number=0;[int]::TryParse(('+decode('42')+'),[ref]$number);'
        "if($number -ne 42){throw 'TryParse copy-out failed'};"
        '[EmumeeMethodFixture.Probe]::Bump([ref]$number,('+decode(TEXT)+'));'
        "if($number -ne 43){throw 'Reference mutation failed'}",
        [expected('System.Int32','TryParse',['42',0]),expected(prefix+'Probe','Bump',[42,TEXT])])
    add('params-optional', '$text='+decode(TEXT)+
        ";[EmumeeMethodFixture.Probe]::Pack($text,('al'+'pha'),('be'+'ta'));"
        '[EmumeeMethodFixture.Probe]::Optional($text);[EmumeeMethodFixture.Probe]::Ping()',
        [expected(prefix+'Probe','Pack',[TEXT,['alpha','beta']]),
         expected(prefix+'Probe','Optional',[TEXT,7],supplied_argument_count=1),expected(prefix+'Probe','Ping',[])])
    add('generic', '[EmumeeMethodFixture.Probe]::Identity[string](('+decode(TEXT)+'))',
        [expected(prefix+'Probe','Identity',[TEXT],generic_arguments=['System.String'])])
    add('reflection', "$type=[type]('EmumeeMethodFixture.'+'Probe');$method=$type.GetMethod(('Ec'+'ho'),[type[]]@([string]));"
        '$method.Invoke($null,[object[]]@(('+decode(TEXT)+')))',
        [expected(prefix+'Probe','Echo',[TEXT],phase='reflection_arguments_supplied')])
    add('reflection-constructor', "$type=[type]('EmumeeMethodFixture.'+'Holder');$ctor=$type.GetConstructor([type[]]@([string]));"
        '$ctor.Invoke([object[]]@(('+decode(TEXT)+')))',
        [expected(prefix+'Holder','.ctor',[TEXT],phase='reflection_arguments_supplied')])
    add('delegate', "$m=[EmumeeMethodFixture.Probe].GetMethod(('Ec'+'ho'),[type[]]@([string]));"
        '$d=$m.CreateDelegate([Func[string,string]]);$d.Invoke(('+decode(TEXT)+'))',
        [{'method_name':'Invoke','values':[TEXT],'delegate_target':'EmumeeMethodFixture.Probe::Echo(System.String)'}])
    add('virtual-dispatch', '$obj=[EmumeeMethodFixture.Derived]::new();$obj.(\'Sp\'+\'eak\')(('+decode(TEXT)+'));'
        '$obj.Generic[string](('+decode(TEXT)+'))',
        [expected(prefix+'Derived','Speak',[TEXT]),expected(prefix+'Derived','Generic',[TEXT],generic_arguments=['System.String'])])
    add('reflection-virtual-generic', '$obj=[EmumeeMethodFixture.Derived]::new();'
        "$m=[EmumeeMethodFixture.Base].GetMethod(('Gen'+'eric')).MakeGenericMethod([type[]]@([string]));"
        '$m.Invoke($obj,[object[]]@(('+decode(TEXT)+')))',
        [expected(prefix+'Derived','Generic',[TEXT],generic_arguments=['System.String'],phase='reflection_arguments_supplied')])
    add('reflection-interface-generic', '$obj=[EmumeeMethodFixture.ExplicitProbe]::new();'
        "$m=[EmumeeMethodFixture.IProbe].GetMethod(('R'+'un')).MakeGenericMethod([type[]]@([string]));"
        '$m.Invoke($obj,[object[]]@(('+decode(TEXT)+')))',
        [expected(prefix+'ExplicitProbe','EmumeeMethodFixture.IProbe.Run',[TEXT],generic_arguments=['System.String'],phase='reflection_arguments_supplied')])
    add('throwing-method', 'try{[int]::Parse(('+decode('not-a-number')+'))}catch{[Console]::WriteLine(\'parse-caught\')}',
        [expected('System.Int32','Parse',['not-a-number'])])
    add('conversion-once', '$value=[EmumeeMethodFixture.Convertible]::new();'
        "$text=[EmumeeMethodFixture.Probe]::StringOnly($value);"
        "if($text -ne 'convert-once' -or [EmumeeMethodFixture.Convertible]::Calls -ne 1){throw 'Conversion evaluated more than once'}",
        [expected(prefix+'Probe','StringOnly',['convert-once'])])
    add('argument-expression-once', '$script:calls=0;function Get-Once{$script:calls++;return ('+decode(TEXT)+')};'
        "[EmumeeMethodFixture.Probe]::Echo((Get-Once));if($script:calls -ne 1){throw 'Argument evaluated twice'}",
        [expected(prefix+'Probe','Echo',[TEXT])])
    add('opaque-argument-no-getters', '$trap=[EmumeeMethodFixture.Trap]::new();[EmumeeMethodFixture.Probe]::AcceptOpaque($trap);'
        "if([EmumeeMethodFixture.Trap]::Calls -ne 0){throw 'Snapshot executed user code'}",
        [expected(prefix+'Probe','AcceptOpaque',[{'type':prefix+'Trap','capture_status':'opaque_value_not_evaluated'}])])
    inner='[EmumeeMethodFixture.Probe]::Echo(('+decode(TEXT)+'))'
    for depth in (8,40):
        body=inner
        for layer in range(depth):
            body=compressed_layer(body,layer)
        add(f'compressed-{depth}-layers',body,[expected(prefix+'Probe','Echo',[TEXT])])
    return result
