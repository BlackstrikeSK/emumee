using System;
using System.Reflection;

byte[] raw = Convert.FromBase64String(EmbeddedPayload.Library);
Assembly loaded = Assembly.Load(raw);
Type stage = loaded.GetType("Payload.Stage")!;
object instance = Activator.CreateInstance(stage)!;
MethodInfo run = stage.GetMethod("Run")!;
object? result = run.Invoke(instance, new object?[] { " stage" });
Console.WriteLine(result);
Console.WriteLine(stage.GetMethod("CreateAndRun")!.Invoke(null, null));

Assembly executable = Assembly.Load(Convert.FromBase64String(EmbeddedPayload.Executable));
executable.EntryPoint!.Invoke(null, new object?[] { new string[0] });
