using System;
using System.IO;

var bytes = Convert.FromBase64String("Nzs0Oz0/Pno2NTUqeio7IzY1Oz4=");
for (var index = 0; index < bytes.Length; index++)
{
    bytes[index] ^= 0x5A;
}
File.WriteAllBytes(@"C:\Users\Alex\Downloads\loop-payload.bin", bytes);
