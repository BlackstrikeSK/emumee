using System;
using System.IO;
using StaticFieldPayload;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
bool first = SharedStage.Count == 7 && SharedStage.Marker == "ready";
SharedStage.Count = 11;
bool second = SharedStage.Count == 11 && SharedStage.Marker == "ready";
File.WriteAllText(Path.Combine(roaming, "managed-companion-static-state.txt"),
                  first && second ? "companion-static-ok" : "wrong");
