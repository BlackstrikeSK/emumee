using System;
using System.IO;
using System.IO.Compression;

var encoded = "H4sIAAAAAAAC/8tILMrNSS0uVshNzEtMT01RSK/KLFAoSKzMyU9MAQCPYCfPHQAAAA==";
var input = new MemoryStream(Convert.FromBase64String(encoded));
var gzip = new GZipStream(input, CompressionMode.Decompress);
var output = new MemoryStream();
gzip.CopyTo(output);
File.WriteAllBytes(@"C:\Users\Alex\Downloads\gzip-payload.bin", output.ToArray());

var deflateEncoded = "y0gsys1JLS5WyE3MS0xPTVFISU3LSSxJVShIrMzJT0wBAA==";
var deflateInput = new MemoryStream(Convert.FromBase64String(deflateEncoded));
var deflate = new DeflateStream(deflateInput, CompressionMode.Decompress);
var deflateOutput = new MemoryStream();
deflate.CopyTo(deflateOutput);
File.WriteAllBytes(@"C:\Users\Alex\Downloads\deflate-payload.bin", deflateOutput.ToArray());
