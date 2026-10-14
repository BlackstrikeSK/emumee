using System;
using System.IO;
using Companion;

BaseStage stage = new DerivedStage("derived");
string result = stage.Run();
BaseStage shadow = new ShadowStage("shadow");
string shadowResult = shadow.Run();
string fixedResult = shadow.Fixed();
BaseStage shadowChild = new ShadowChildStage("shadow-child");
string shadowChildResult = shadowChild.Run();
string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
File.WriteAllText(Path.Combine(roaming, "managed-virtual-companion-state.txt"),
                  result + ";" + shadowResult + ";" + fixedResult + ";" + shadowChildResult);
