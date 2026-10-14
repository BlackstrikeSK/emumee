using System;
using System.IO;

try
{
    throw new InvalidOperationException("harmless fixture exception");
}
catch (InvalidOperationException)
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\managed-caught.txt", "managed catch marker");
}

try
{
    ThrowNested();
}
catch (ArgumentException)
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\managed-nested.txt", "nested catch marker");
}

try
{
    Convert.FromBase64String("not base64!");
}
catch (FormatException)
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\managed-format.txt", "format catch marker");
}

try
{
    File.ReadAllBytes(@"C:\Users\Alex\Downloads\absent-fixture.bin");
}
catch (FileNotFoundException)
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\managed-missing.txt", "missing catch marker");
}

try
{
    try
    {
        try
        {
            throw new InvalidOperationException("harmless rethrow fixture");
        }
        catch (InvalidOperationException)
        {
            File.WriteAllText(@"C:\Users\Alex\Downloads\rethrow-inner.txt", "inner rethrow marker");
            throw;
        }
    }
    finally
    {
        File.WriteAllText(@"C:\Users\Alex\Downloads\rethrow-finally.txt", "rethrow finally marker");
    }
}
catch (InvalidOperationException)
{
    File.WriteAllText(@"C:\Users\Alex\Downloads\rethrow-outer.txt", "outer rethrow marker");
}

static void ThrowNested()
{
    throw new ArgumentException("harmless nested exception");
}
