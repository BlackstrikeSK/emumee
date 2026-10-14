using System;
using System.IO;
using System.Reflection;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
Assembly assembly = Assembly.GetExecutingAssembly();
string[] names = assembly.GetManifestResourceNames();
using Stream source = assembly.GetManifestResourceStream("payload.dat")!;
using MemoryStream destination = new();
source.CopyTo(destination);
byte[] payload = destination.ToArray();
File.WriteAllBytes(Path.Combine(roaming, "managed-resource-payload.bin"), payload);
bool missing = assembly.GetManifestResourceStream("missing.dat") is null;
bool good = names.Length == 1 && names[0] == "payload.dat" && missing &&
            payload.Length == 25 && payload[0] == (byte)'e' && payload[23] == (byte)'!' &&
            payload[24] == (byte)'\n';
File.WriteAllText(Path.Combine(roaming, "managed-resource-state.txt"),
                  good ? "resource-ok" : "wrong");
