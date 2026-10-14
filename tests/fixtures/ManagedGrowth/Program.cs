using System;
using System.IO;

string value = "x";
for (int i = 0; i < 27; i++)
{
    value = String.Concat(value, value);
}
File.WriteAllText(@"C:\Users\Alex\Downloads\growth.txt", value);
