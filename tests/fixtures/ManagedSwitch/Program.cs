using System;
using System.IO;

byte[] scratch = new byte[12];
string branch;
switch (scratch.Length % 7)
{
    case 0: branch = "zero"; break;
    case 1: branch = "one"; break;
    case 2: branch = "two"; break;
    case 3: branch = "three"; break;
    case 4: branch = "four"; break;
    case 5: branch = "five"; break;
    case 6: branch = "six"; break;
    default: branch = "invalid"; break;
}
File.WriteAllText(@"C:\Users\Alex\Downloads\switch.txt", branch);
