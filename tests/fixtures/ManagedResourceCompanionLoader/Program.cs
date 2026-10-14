using System;
using System.IO;
using ResourcePayload;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
byte[] payload = Stage.Recover();
File.WriteAllBytes(Path.Combine(roaming, "managed-companion-resource.bin"), payload);
File.WriteAllText(Path.Combine(roaming, "managed-companion-resource-state.txt"),
                  payload.Length == 23 && payload[0] == (byte)'c' ? "companion-resource-ok" : "wrong");
