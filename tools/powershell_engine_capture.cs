// Experimental instrumentation injected into a pinned PowerShell source tree.
// Guest-generated data is NOT an independent proof of engine behavior.
using System;
using System.Collections.Generic;
using System.Collections;
using System.Collections.Specialized;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Linq.Expressions;
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
            if (record.TryGetValue("access_id", out var accessId) && accessId is int id && id == 0) record["access_id"] = sequence;
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

        private sealed class PropertyAccess
        {
            internal PropertyInfo Property;
            internal object Target;
            internal string Operation, Route, ValueStage;
            internal object Value;
            internal object PassedSnapshot, IndexSnapshot;
            internal object[] Indexes;
            internal int Id;
        }

        private static PropertyAccess BeginProperty(PropertyInfo property, object target, string operation,
                                                    object value, object[] indexes, string route, string valueStage)
        {
            // Only runtime metadata is inspected; no custom PropertyInfo getters.
            if (s_recording || property == null || property.GetType().Assembly != typeof(object).Assembly ||
                    property.GetType().FullName != "System.Reflection.RuntimePropertyInfo") return null;
            var access = new PropertyAccess { Property = property, Target = target, Operation = operation,
                Value = value, Indexes = indexes ?? Array.Empty<object>(), Route = route, ValueStage = valueStage };
            access.Id = RecordProperty(access, "started", null, null);
            return access;
        }

        private static int RecordProperty(PropertyAccess access, string status, object result, Exception error)
        {
            if (access == null || s_recording) return 0;
            s_recording = true;
            try
            {
                var selected = access.Operation == "get" ? access.Property.GetMethod : access.Property.SetMethod;
                var resolved = selected == null ? null : ResolveDispatch(selected, access.Target, access.Route);
                var property = access.Property;
                if (resolved != selected && resolved?.DeclaringType != null)
                    foreach (var candidate in resolved.DeclaringType.GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
                        if ((access.Operation == "get" ? candidate.GetMethod : candidate.SetMethod) == resolved) { property = candidate; break; }
                bool available = access.Operation == "set" || status == "completed";
                if (status == "started")
                {
                    access.PassedSnapshot = access.Operation == "set" ? Snapshot(access.Value, 0) : null;
                    access.IndexSnapshot = Snapshot(access.Indexes, 0);
                }
                var record = new Dictionary<string, object> {
                    ["event"] = "powershell_command_invocation", ["timestamp_utc"] = DateTime.UtcNow.ToString("O"),
                    ["capture"] = "guest_engine_instrumentation", ["provenance"] = "in_process_data",
                    ["phase"] = "property_" + access.Operation + "_" + status, ["command_type"] = "DotNetProperty",
                    ["command"] = (property.DeclaringType?.FullName ?? "") + "::" + property.Name,
                    ["bound_parameters"] = new Dictionary<string, object>(), ["unbound_arguments"] = Array.Empty<object>(),
                    ["property_name"] = property.Name, ["declaring_type"] = property.DeclaringType?.FullName ?? "",
                    ["property_type"] = property.PropertyType.FullName ?? property.PropertyType.Name,
                    ["accessor_signature"] = resolved != null ? Signature(resolved) : "<no accessor>",
                    ["selected_property"] = (access.Property.DeclaringType?.FullName ?? "") + "::" + access.Property.Name,
                    ["is_static"] = selected?.IsStatic ?? false, ["target_type"] = access.Target?.GetType().FullName,
                    ["operation"] = access.Operation, ["access_status"] = status, ["access_id"] = access.Id,
                    ["dispatch_route"] = access.Route, ["value_stage"] = access.Operation == "get" ? "returned" : access.ValueStage,
                    ["value_available"] = available, ["property_value"] = available ? access.Operation == "get" ? Snapshot(result, 0) : access.PassedSnapshot : null,
                    ["index_arguments"] = access.IndexSnapshot, ["error_type"] = error?.GetType().FullName };
                return Emit(record);
            }
            catch (Exception failure) { Environment.FailFast("Emumee property capture failed", failure); return 0; }
            finally { s_recording = false; }
        }

        private static void CompleteProperty(PropertyAccess access, object result) => RecordProperty(access, "completed", result, null);
        private static void FailProperty(PropertyAccess access, Exception error) => RecordProperty(access, "failed", null, error);

        // A write is observed after conversion, immediately before the existing
        // assignment. The original setter and return-value semantics are retained.
        private static T BeginPropertyWrite<T>(ref PropertyAccess access, PropertyInfo property, object target, T value)
        {
            access = BeginProperty(property, target, "set", value, null, "binder", "converted");
            return value;
        }

        private sealed class PropertyAssignmentObserver : ExpressionVisitor
        {
            internal PropertyInfo Property;
            internal Expression Target;
            internal ParameterExpression Access;
            protected override Expression VisitBinary(BinaryExpression node)
            {
                if (node.NodeType == ExpressionType.Assign && node.Left is MemberExpression member && member.Member == Property)
                    return Expression.Assign(node.Left, Expression.Call(
                        typeof(EmumeeInvocationCapture).GetMethod(nameof(BeginPropertyWrite), BindingFlags.NonPublic | BindingFlags.Static).MakeGenericMethod(node.Right.Type),
                        Access, Expression.Constant(Property, typeof(PropertyInfo)), Target, node.Right));
                return base.VisitBinary(node);
            }
        }

        private static Expression PropertyBoundary(Expression body, ParameterExpression access, Expression begin)
        {
            if (body.Type.IsByRef || body.Type.IsByRefLike) return body;
            var result = body.Type == typeof(void) ? null : Expression.Variable(body.Type);
            var error = Expression.Variable(typeof(Exception));
            var complete = typeof(EmumeeInvocationCapture).GetMethod(nameof(CompleteProperty), BindingFlags.NonPublic | BindingFlags.Static);
            var fail = typeof(EmumeeInvocationCapture).GetMethod(nameof(FailProperty), BindingFlags.NonPublic | BindingFlags.Static);
            Expression success = result == null
                ? Expression.Block(body, Expression.Call(complete, access, Expression.Constant(null, typeof(object))))
                : Expression.Block(Expression.Assign(result, body), Expression.Call(complete, access, Expression.Convert(result, typeof(object))), result);
            var guarded = Expression.TryCatch(success, Expression.Catch(error,
                Expression.Block(Expression.Call(fail, access, error), Expression.Rethrow(body.Type))));
            return Expression.Block(result == null ? new[] { access } : new[] { access, result }, begin, guarded);
        }

        internal static Expression ObserveProperty(Expression body, PropertyInfo property, Expression target, string operation)
        {
            if (body.Type.IsByRef || body.Type.IsByRefLike) return body;
            target = target == null ? Expression.Constant(null, typeof(object)) : Expression.Convert(target, typeof(object));
            var access = Expression.Variable(typeof(PropertyAccess));
            Expression begin;
            if (operation == "set")
            {
                body = new PropertyAssignmentObserver { Property = property, Target = target, Access = access }.Visit(body);
                begin = Expression.Assign(access, Expression.Constant(null, typeof(PropertyAccess)));
            }
            else
                begin = Expression.Assign(access, Expression.Call(typeof(EmumeeInvocationCapture).GetMethod(nameof(BeginProperty), BindingFlags.NonPublic | BindingFlags.Static),
                    Expression.Constant(property, typeof(PropertyInfo)), target, Expression.Constant("get"), Expression.Constant(null, typeof(object)),
                    Expression.Constant(null, typeof(object[])), Expression.Constant("binder"), Expression.Constant("returned")));
            return PropertyBoundary(body, access, begin);
        }

        internal static object GetProperty(PropertyInfo property, object target, Func<object> getter)
        {
            var access = BeginProperty(property, target, "get", null, null, "adapter", "returned");
            try { var value = getter(); CompleteProperty(access, value); return value; }
            catch (Exception error) { FailProperty(access, error); throw; }
        }

        internal static void SetProperty(PropertyInfo property, object target, object value, Action setter)
        {
            var access = BeginProperty(property, target, "set", value, null, "adapter", "converted");
            try { setter(); CompleteProperty(access, null); }
            catch (Exception error) { FailProperty(access, error); throw; }
        }

        private static PropertyAccess BeginPropertyInvocation(MethodBase selected, object receiver, object[] args)
        {
            if (receiver is PropertyInfo reflected && selected.Name is "GetValue" or "SetValue")
            {
                object target = null, value = null;
                object[] indexes = null;
                var parameters = selected.GetParameters();
                for (int i = 0; i < Math.Min(args.Length, parameters.Length); ++i)
                {
                    if (parameters[i].Name == "obj") target = args[i];
                    if (parameters[i].Name == "value") value = args[i];
                    if (parameters[i].Name == "index") indexes = args[i] as object[];
                }
                return BeginProperty(reflected, target, selected.Name == "GetValue" ? "get" : "set", value, indexes,
                    "reflection", "supplied_before_clr_conversion");
            }
            var method = (MethodInfo)selected;
            foreach (var property in method.DeclaringType.GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
            {
                bool set = property.SetMethod == method;
                if (!set && property.GetMethod != method) continue;
                var indexes = new object[args.Length - (set ? 1 : 0)];
                Array.Copy(args, indexes, indexes.Length);
                return BeginProperty(property, receiver, set ? "set" : "get", set ? args[^1] : null, indexes, "accessor", "converted");
            }
            return null;
        }

        internal static Expression ObservePropertyInvocation(Expression body, MethodBase selected, Expression receiver, Expression[] args)
        {
            if (!RuntimeMetadata(selected) || selected is not MethodInfo method) return body;
            bool reflection = typeof(PropertyInfo).IsAssignableFrom(method.DeclaringType) && method.Name is "GetValue" or "SetValue";
            bool accessor = method.IsSpecialName && (method.Name.StartsWith("get_", StringComparison.Ordinal) || method.Name.StartsWith("set_", StringComparison.Ordinal));
            if (!reflection && !accessor || body.Type.IsByRef || body.Type.IsByRefLike) return body;
            var access = Expression.Variable(typeof(PropertyAccess));
            receiver = receiver == null ? Expression.Constant(null, typeof(object)) : Expression.Convert(receiver, typeof(object));
            var begin = Expression.Assign(access, Expression.Call(typeof(EmumeeInvocationCapture).GetMethod(nameof(BeginPropertyInvocation), BindingFlags.NonPublic | BindingFlags.Static),
                Expression.Constant(selected, typeof(MethodBase)), receiver, Expression.NewArrayInit(typeof(object), args)));
            return PropertyBoundary(body, access, begin);
        }

        internal static Expression ObserveIndexer(Expression target, MethodInfo accessor, params Expression[] arguments)
        {
            if (accessor.ReturnType.IsByRef || accessor.ReturnType.IsByRefLike) return Expression.Call(target, accessor, arguments);
            foreach (var argument in arguments)
                if (argument.Type.IsByRefLike || argument.Type.IsByRef) return Expression.Call(target, accessor, arguments);
            var variables = new List<ParameterExpression>();
            var statements = new List<Expression>();
            var receiver = Expression.Variable(target.Type);
            variables.Add(receiver);
            statements.Add(Expression.Assign(receiver, target));
            var passed = new Expression[arguments.Length];
            var boxed = new Expression[arguments.Length];
            for (int i = 0; i < arguments.Length; ++i)
            {
                var value = Expression.Variable(arguments[i].Type);
                variables.Add(value);
                statements.Add(Expression.Assign(value, arguments[i]));
                passed[i] = value;
                boxed[i] = Expression.Convert(value, typeof(object));
            }
            statements.Add(ObservePropertyInvocation(Expression.Call(receiver, accessor, passed), accessor, receiver, boxed));
            return Expression.Block(variables, statements);
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
