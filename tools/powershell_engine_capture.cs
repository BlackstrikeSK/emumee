// Experimental instrumentation injected into a pinned PowerShell source tree.
// Guest-generated data is NOT an independent proof of engine behavior.
using System;
using System.Collections.Generic;
using System.Collections;
using System.Collections.Specialized;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text.Json;
using System.Threading;

namespace System.Management.Automation
{
    internal static unsafe class EmumeeInvocationCapture
    {
        private static int s_sequence;
        [ThreadStatic] private static bool s_recording;

        [DllImport("libc", EntryPoint = "write", SetLastError = true)]
        private static extern nint Write(int descriptor, byte* buffer, nuint count);

        internal static void Record(InvocationInfo info, string phase)
        {
            if (s_recording) return;
            s_recording = true;
            try
            {
                var bound = new Dictionary<string, object>();
                foreach (var item in info.BoundParameters)
                {
                    if (bound.Count == 64)
                    {
                        bound["capture_truncated"] = true;
                        break;
                    }

                    bound[item.Key] = Snapshot(item.Value, 0);
                }

                string sourceLine = info.Line ?? string.Empty;
                int previewLength = Math.Min(sourceLine.Length, 1024);
                if (previewLength < sourceLine.Length && previewLength > 0 &&
                        char.IsHighSurrogate(sourceLine[previewLength - 1])) --previewLength;
                var record = new Dictionary<string, object>
                {
                    ["event"] = "powershell_command_invocation",
                    ["timestamp_utc"] = DateTime.UtcNow.ToString("O"),
                    ["capture"] = "guest_engine_instrumentation",
                    ["phase"] = phase,
                    ["command"] = info.MyCommand?.Name ?? "<scriptblock>",
                    ["command_type"] = info.MyCommand?.CommandType.ToString(),
                    ["invocation_name"] = info.InvocationName,
                    ["bound_parameters"] = bound,
                    ["unbound_arguments"] = Snapshot(info.UnboundArguments?.ToArray(), 0),
                    ["source_line"] = sourceLine.Substring(0, previewLength),
                    ["source_line_length"] = sourceLine.Length,
                    ["source_line_truncated"] = previewLength < sourceLine.Length,
                    ["script_name"] = info.ScriptName,
                    ["script_line_number"] = info.ScriptLineNumber,
                    ["provenance"] = "in_process_data"
                };
                Emit(record);
            }
            catch (Exception error)
            {
                Environment.FailFast("Emumee invocation capture failed", error);
            }
            finally { s_recording = false; }
        }

        private static int Emit(Dictionary<string, object> record)
        {
            int sequence = Interlocked.Increment(ref s_sequence);
            if (sequence > 2000) Environment.FailFast("Emumee invocation budget exceeded");
            record["sequence"] = sequence;
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(record);
            if (bytes.Length > 65536) Environment.FailFast("Emumee invocation record exceeds limit");
            fixed (byte* pointer = bytes)
            {
                if (Write(198, pointer, (nuint)bytes.Length) != bytes.Length)
                    Environment.FailFast("Emumee invocation transport unavailable");
            }

            return sequence;
        }

        private static bool RuntimeMetadata(MethodBase method)
        {
            if (method == null || method.GetType().Assembly != typeof(object).Assembly) return false;
            string type = method.GetType().FullName;
            return type == "System.Reflection.RuntimeMethodInfo" || type == "System.Reflection.RuntimeConstructorInfo";
        }

        private static string Signature(MethodBase method)
        {
            var names = new List<string>();
            foreach (var parameter in method.GetParameters()) names.Add(parameter.ParameterType.FullName ?? parameter.ParameterType.Name);
            return (method.DeclaringType?.FullName ?? "") + "::" + method.Name + "(" + string.Join(", ", names) + ")";
        }

        private static MethodBase ResolveDispatch(MethodBase selected, object target, string route)
        {
            if (target == null || selected is not MethodInfo info || !info.IsVirtual || route == "NonVirtual") return selected;
            Type receiver = target.GetType();
            MethodInfo definitionInfo = info.IsGenericMethod ? info.GetGenericMethodDefinition() : info;
            MethodInfo Close(MethodInfo candidate) => info.IsGenericMethod && !info.IsGenericMethodDefinition
                && candidate.IsGenericMethodDefinition ? candidate.MakeGenericMethod(info.GetGenericArguments()) : candidate;
            if (info.DeclaringType.IsInterface)
            {
                var map = receiver.GetInterfaceMap(info.DeclaringType);
                for (int i = 0; i < map.InterfaceMethods.Length; ++i)
                    if (map.InterfaceMethods[i] == definitionInfo) return Close(map.TargetMethods[i]);
            }
            else
            {
                var definition = definitionInfo.GetBaseDefinition();
                foreach (var candidate in receiver.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
                    if (candidate.IsVirtual && candidate.GetBaseDefinition() == definition) return Close(candidate);
            }

            return selected;
        }

        private static Dictionary<string, object> MethodRecord(MethodBase method, object target, object[] arguments,
                                                               string route, int suppliedCount, string phase)
        {
            bool metadata = RuntimeMetadata(method);
            var parameters = metadata ? method.GetParameters() : Array.Empty<ParameterInfo>();
            var values = new List<object>();
            for (int i = 0; i < Math.Min(arguments.Length, 32); ++i)
            {
                var parameter = i < parameters.Length ? parameters[i] : null;
                Type type = parameter?.ParameterType;
                Type element = type != null && type.IsByRef ? type.GetElementType() : type;
                object value = element != null && element.IsByRefLike
                    ? new { capture_status = "byref_like_value_not_captured", type = element.FullName }
                    : Snapshot(arguments[i], 0);
                values.Add(new Dictionary<string, object> {
                    ["position"] = i, ["name"] = parameter?.Name ?? ("arg" + i),
                    ["parameter_type"] = type?.FullName ?? type?.Name,
                    ["by_ref"] = type?.IsByRef ?? false, ["is_out"] = parameter?.IsOut ?? false,
                    ["is_optional"] = parameter?.IsOptional ?? false, ["value"] = value });
            }

            string declaring = metadata ? method.DeclaringType?.FullName ?? "" : "";
            string name = metadata ? method.Name : "<metadata unavailable>";
            var generic = new List<string>();
            if (metadata && method.IsGenericMethod)
                foreach (var type in method.GetGenericArguments()) generic.Add(type.FullName ?? type.Name);
            return new Dictionary<string, object> {
                ["event"] = "powershell_command_invocation", ["timestamp_utc"] = DateTime.UtcNow.ToString("O"),
                ["capture"] = "guest_engine_instrumentation", ["provenance"] = "in_process_data",
                ["phase"] = phase, ["command"] = declaring + "::" + (name == ".ctor" ? "new" : name),
                ["command_type"] = "DotNetMethod", ["bound_parameters"] = new Dictionary<string, object>(),
                ["unbound_arguments"] = Array.Empty<object>(), ["method_name"] = name,
                ["declaring_type"] = declaring, ["target_type"] = target?.GetType().FullName,
                ["method_signature"] = metadata ? Signature(method) : "<metadata unavailable>",
                ["is_static"] = metadata && method.IsStatic, ["is_constructor"] = metadata && method is ConstructorInfo,
                ["dispatch_route"] = route, ["supplied_argument_count"] = suppliedCount,
                ["generic_arguments"] = generic, ["method_arguments"] = values,
                ["arguments_truncated"] = arguments.Length > 32, ["metadata_captured"] = metadata };
        }

        internal static void RecordMethod(MethodBase selected, object target, object[] arguments, string route, int suppliedCount)
        {
            if (s_recording) return;
            s_recording = true;
            try
            {
                arguments ??= Array.Empty<object>();
                MethodBase resolved = RuntimeMetadata(selected) ? ResolveDispatch(selected, target, route) : selected;
                var record = MethodRecord(resolved, target, arguments, route, suppliedCount, "method_arguments_bound");
                if (RuntimeMetadata(selected)) record["selected_signature"] = Signature(selected);
                if (target is Delegate callback && RuntimeMetadata(selected) && selected.Name == "Invoke")
                {
                    var targets = new List<object>();
                    foreach (var member in callback.GetInvocationList())
                    {
                        if (targets.Count == 32) { record["delegate_targets_truncated"] = true; break; }
                        targets.Add(RuntimeMetadata(member.Method) ? (object)Signature(member.Method) : "<metadata unavailable>");
                    }
                    record["delegate_targets"] = targets;
                }

                int parent = Emit(record);
                // Reflection supplies another method as its receiver. Record
                // that target and the supplied array separately, without
                // claiming CLR reflection conversions have already happened.
                if (target is MethodBase reflected && RuntimeMetadata(reflected) && RuntimeMetadata(selected) && selected.Name == "Invoke")
                {
                    object receiver = null;
                    object[] supplied = Array.Empty<object>();
                    var wrapperParameters = selected.GetParameters();
                    for (int i = 0; i < Math.Min(wrapperParameters.Length, arguments.Length); ++i)
                    {
                        if (wrapperParameters[i].Name == "obj") receiver = arguments[i];
                        if (wrapperParameters[i].Name == "parameters" && arguments[i] is object[] array) supplied = array;
                    }
                    var nested = MethodRecord(ResolveDispatch(reflected, receiver, "reflection_target"), receiver, supplied, "reflection_target", supplied.Length,
                                              "reflection_arguments_supplied");
                    nested["selected_signature"] = Signature(reflected);
                    nested["parent_engine_sequence"] = parent;
                    Emit(nested);
                }
            }
            catch (Exception error) { Environment.FailFast("Emumee method capture failed", error); }
            finally { s_recording = false; }
        }

        // Never enumerate arbitrary IEnumerable/IDictionary values or invoke
        // custom getters/ToString methods while observing a command.
        private static object Snapshot(object value, int depth)
        {
            if (value == null) return null;
            if (depth > 6) return new { capture_truncated = true };
            if (value is PSObject wrapper) return Snapshot(wrapper.BaseObject, depth + 1);
            if (value is string text)
                return text.Length <= 4096 ? text : new { capture_truncated = true, prefix = text.Substring(0, 4096) };
            if (value is SwitchParameter toggle) return toggle.IsPresent;
            if (value is bool || value is byte || value is sbyte || value is short || value is ushort ||
                value is int || value is uint || value is long || value is ulong || value is decimal || value is char)
                return value;
            if (value is double real && double.IsFinite(real)) return value;
            if (value is float single && float.IsFinite(single)) return value;
            // Exact framework types only: never dispatch a user override of
            // ToString, an arbitrary dictionary enumerator, or a custom getter.
            Type valueType = value.GetType();
            if (value is Type runtimeType && valueType.Assembly == typeof(object).Assembly && valueType.FullName == "System.RuntimeType")
                return runtimeType.FullName ?? runtimeType.Name;
            if (value is MethodBase method && RuntimeMetadata(method)) return Signature(method);
            if (valueType.IsEnum) return Snapshot(Enum.Format(valueType, value, "G"), depth + 1);
            if (valueType == typeof(Uri)) return Snapshot(((Uri)value).OriginalString, depth + 1);
            if (valueType == typeof(Guid)) return ((Guid)value).ToString("D");
            if (valueType == typeof(Version)) return ((Version)value).ToString();
            if (valueType == typeof(Hashtable) || valueType == typeof(OrderedDictionary) ||
                    valueType == typeof(Dictionary<string, object>))
            {
                var dictionary = (IDictionary)value;
                var entries = new Dictionary<string, object>(StringComparer.Ordinal);
                foreach (DictionaryEntry entry in dictionary)
                {
                    if (entry.Key is not string key)
                        return new { type = valueType.FullName, capture_status = "opaque_non_string_dictionary_keys" };
                    if (entries.Count == 32)
                        return new { type = valueType.FullName, entries, capture_truncated = true };
                    entries[key] = Snapshot(entry.Value, depth + 1);
                }

                return entries;
            }
            if (value.GetType() == typeof(List<object>))
            {
                var list = (List<object>)value;
                var items = new List<object>();
                for (int i = 0; i < Math.Min(list.Count, 32); ++i) items.Add(Snapshot(list[i], depth + 1));
                if (list.Count > 32) items.Add(new { capture_truncated = true });
                return items;
            }

            if (value.GetType() == typeof(List<PSObject>))
            {
                var list = (List<PSObject>)value;
                var items = new List<object>();
                for (int i = 0; i < Math.Min(list.Count, 32); ++i) items.Add(Snapshot(list[i], depth + 1));
                if (list.Count > 32) items.Add(new { capture_truncated = true });
                return items;
            }

            if (value is Array array && array.Rank == 1 && array.GetLowerBound(0) == 0)
            {
                var items = new List<object>();
                for (int i = 0; i < Math.Min(array.Length, 32); ++i) items.Add(Snapshot(array.GetValue(i), depth + 1));
                if (array.Length > 32) items.Add(new { capture_truncated = true });
                return items;
            }

            return new { type = value.GetType().FullName, capture_status = "opaque_value_not_evaluated" };
        }
    }
}
