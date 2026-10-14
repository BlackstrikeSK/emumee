using System.IO;

File.WriteAllText("bundled-output.txt", File.ReadAllText(@"data\message.txt"));
