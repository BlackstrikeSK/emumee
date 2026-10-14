using System;
using System.IO;

try
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\before-finally.txt", "before finally marker");
}
finally
{
    Console.WriteLine("finally marker");
}

try
{
    try
    {
        throw new InvalidOperationException("harmless unwind fixture");
    }
    finally
    {
        File.WriteAllText(@"C:\Users\Alex\Downloads\exception-finally.txt", "exception finally marker");
    }
}
catch (InvalidOperationException)
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\after-finally.txt", "outer catch marker");
}

try
{
    ThrowWithFinally();
}
catch (ArgumentException)
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\cross-method-catch.txt", "cross method catch marker");
}

try
{
    try
    {
        try
        {
            throw new ApplicationException("harmless nested finally fixture");
        }
        finally
        {
            File.WriteAllText(@"C:\Users\Alex\Downloads\inner-finally.txt", "inner finally marker");
        }
    }
    finally
    {
        File.WriteAllText(@"C:\Users\Alex\Downloads\outer-finally.txt", "outer finally marker");
    }
}
catch (ApplicationException)
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\after-nested-finally.txt", "nested finally catch marker");
}

try
{
    try
    {
        Console.WriteLine("normal nested marker");
    }
    finally
    {
        File.WriteAllText(@"C:\Users\Alex\Downloads\normal-inner-finally.txt", "normal inner marker");
    }
}
finally
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\normal-outer-finally.txt", "normal outer marker");
}

static void ThrowWithFinally()
{
    try
    {
        throw new ArgumentException("harmless cross method fixture");
    }
    finally
    {
        File.WriteAllText(@"C:\Users\Alex\Downloads\cross-method-finally.txt", "cross method finally marker");
    }
}
