// Experimental instrumentation injected into a pinned PowerShell source tree.
// Guest-generated data is NOT an independent proof of engine behavior.
using System;
using System.Collections.Generic;
using System.Collections;
using System.Collections.Specialized;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;

namespace System.Management.Automation
{
    internal static unsafe class EmumeeInvocationCapture
    {
        private static int s_sequence;

        [DllImport("libc", EntryPoint = "write", SetLastError = true)]
        private static extern nint Write(int descriptor, byte* buffer, nuint count);

        internal static void Record(InvocationInfo info, string phase)
        {
            try
            {
                int sequence = Interlocked.Increment(ref s_sequence);
                if (sequence > 2000) Environment.FailFast("Emumee invocation budget exceeded");
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
                    ["sequence"] = sequence,
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
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(record);
                if (bytes.Length > 65536) Environment.FailFast("Emumee invocation record exceeds limit");
                fixed (byte* pointer = bytes)
                {
                    if (Write(198, pointer, (nuint)bytes.Length) != bytes.Length)
                        Environment.FailFast("Emumee invocation transport unavailable");
                }
            }
            catch (Exception error)
            {
                Environment.FailFast("Emumee invocation capture failed", error);
            }
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
