using System;
using System.IO;

try
{
    throw new InvalidOperationException("harmless unhandled fixture");
}
finally
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\unhandled-finally.txt", "unhandled finally marker");
}
