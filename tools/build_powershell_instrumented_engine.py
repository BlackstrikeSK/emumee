"""Build a pinned experimental engine in Docker, never host PowerShell.

The source must be the clean upstream 7.5.12 commit. NuGet restore is allowed
only in the build stage. This tool does not execute submitted scripts.
"""

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
import zlib
from pathlib import Path


SOURCE_COMMIT = "3ad470239de5c9c52d470917b071831f16b02fc3"
SOURCE_TAG_OBJECT = "f8c5ff6aaeca83dc1e08eeb0b55d8e88d0133ac7"
SDK_IMAGE = "mcr.microsoft.com/dotnet/sdk@sha256:2f5eb32870b4c0074a3d5b5191a03553bcab7b74463a76a7c0a5f3ef65c90fe5"
ENGINE = "src/System.Management.Automation"
PATCHES = {
    ENGINE + "/engine/parser/Compiler.cs": (
        ("        internal static readonly MethodInfo MemberInvocationLoggingOps_LogMemberInvocation =",
         "        internal static readonly MethodInfo Emumee_RecordMethod =\n"
         "            typeof(EmumeeInvocationCapture).GetMethod(nameof(EmumeeInvocationCapture.RecordMethod), StaticFlags);\n\n"
         "        internal static readonly MethodInfo MemberInvocationLoggingOps_LogMemberInvocation ="),),
    ENGINE + "/engine/runtime/Binding/Binders.cs": (
        ("(t, i) => Expression.Call(t, getter, i).Cast(typeof(object))",
         "(t, i) => EmumeeInvocationCapture.ObserveIndexer(t, getter, i).Cast(typeof(object))"),
        ("SafeIndexResult(Expression.Call(target.Expression.Cast(getter.DeclaringType), getter, indexExprs))",
         "SafeIndexResult(EmumeeInvocationCapture.ObserveIndexer(target.Expression.Cast(getter.DeclaringType), getter, indexExprs))"),
        ("(t, i, v) => Expression.Call(t, setter, i, v)",
         "(t, i, v) => EmumeeInvocationCapture.ObserveIndexer(t, setter, i, v)"),
        ("Expression.Call(target.Expression.Cast(setter.DeclaringType), setter, indexExprs)",
         "EmumeeInvocationCapture.ObserveIndexer(target.Expression.Cast(setter.DeclaringType), setter, indexExprs)"),
        ("                                    expr = Expression.Property(targetExpr, propertyAccessor);",
         "                                    expr = EmumeeInvocationCapture.ObserveProperty(Expression.Property(targetExpr, propertyAccessor), propertyAccessor, targetExpr, \"get\");"),
        ("                        var e = Expression.Variable(typeof(Exception));\n                        expr = Expression.TryCatch(expr.Cast(typeof(object)),",
         "                        if (propertyInfo != null) expr = EmumeeInvocationCapture.ObserveProperty(expr, propertyInfo, targetExpr, \"set\");\n\n"
         "                        var e = Expression.Variable(typeof(Exception));\n                        expr = Expression.TryCatch(expr.Cast(typeof(object)),"),
        ("            Expression call;\n            if (constructorInfo != null)",
         """            // Evaluate each converted argument once, then share the value with
            // observation and invocation. Preserve existing ref temporaries so
            // the original copy-out expressions still see method mutations.
            var emumeeArgs = new Expression[argExprs.Length];
            for (int i = 0; i < argExprs.Length; ++i)
            {
                if (argExprs[i].Type.IsByRefLike)
                {
                    emumeeArgs[i] = Expression.Constant(null, typeof(object));
                }
                else if (parameters[i].ParameterType.IsByRef)
                {
                    emumeeArgs[i] = argExprs[i].Cast(typeof(object));
                }
                else
                {
                    var observed = Expression.Variable(argExprs[i].Type);
                    temps.Add(observed);
                    initTemps.Add(Expression.Assign(observed, argExprs[i]));
                    argExprs[i] = observed;
                    emumeeArgs[i] = observed.Cast(typeof(object));
                }
            }

            initTemps.Add(Expression.Call(
                CachedReflectionInfo.Emumee_RecordMethod,
                Expression.Constant(mi, typeof(MethodBase)),
                methodInfo == null || methodInfo.IsStatic ? Expression.Constant(null, typeof(object)) : PSGetMemberBinder.GetTargetExpr(target, methodInfo.DeclaringType).Cast(typeof(object)),
                Expression.NewArrayInit(typeof(object), emumeeArgs),
                Expression.Constant(invocationType.ToString()),
                Expression.Constant(args.Length)));

            Expression call;
            if (constructorInfo != null)"""),
        ("            // We need to add one expression to log the .NET invocation before actually invoking:",
         "            call = EmumeeInvocationCapture.ObservePropertyInvocation(call, mi,\n"
         "                methodInfo == null || methodInfo.IsStatic ? null : PSGetMemberBinder.GetTargetExpr(target, methodInfo.DeclaringType), emumeeArgs);\n\n"
         "            if (temps.Count == 0 && initTemps.Count != 0)\n"
         "            {\n"
         "                call = Expression.Block(call.Type, initTemps.Append(call));\n"
         "                initTemps.Clear();\n"
         "            }\n\n"
         "            // We need to add one expression to log the .NET invocation before actually invoking:")),
    ENGINE + "/engine/CoreAdapter.cs": (
        ("return propertyInfo.GetValue(property.baseObject, null);",
         "return EmumeeInvocationCapture.GetProperty(propertyInfo, property.baseObject, () => propertyInfo.GetValue(property.baseObject, null));"),
        ("                    return adapterData.getterDelegate(property.baseObject);",
         "                    return EmumeeInvocationCapture.GetProperty(propertyInfo, property.baseObject, () => adapterData.getterDelegate(property.baseObject));"),
        ("                    propertyInfo.SetValue(property.baseObject, setValue, null);",
         "                    EmumeeInvocationCapture.SetProperty(propertyInfo, property.baseObject, setValue, () => propertyInfo.SetValue(property.baseObject, setValue, null));"),
        ("                    adapterData.setterDelegate(property.baseObject, setValue);",
         "                    EmumeeInvocationCapture.SetProperty(propertyInfo, property.baseObject, setValue, () => adapterData.setterDelegate(property.baseObject, setValue));"),
        ("                return ctor.Invoke(arguments);",
         "                EmumeeInvocationCapture.RecordMethod(ctor, null, arguments, \"adapter\", -1);\n"
         "                return ctor.Invoke(arguments);"),
        ("            if (!_useReflection)\n            {",
         "            EmumeeInvocationCapture.RecordMethod(method, target, arguments, \"adapter\", -1);\n\n"
         "            if (!_useReflection)\n            {")),
    ENGINE + "/engine/CommandProcessor.cs": (
        ("this.CmdletParameterBinderController.BindCommandLineParameters(arguments);",
         "this.CmdletParameterBinderController.BindCommandLineParameters(arguments);\n"
         "                EmumeeInvocationCapture.Record(this.Command.MyInvocation, \"command_line_bound\");"),
        ("                        Command.DoProcessRecord();",
         "                        EmumeeInvocationCapture.Record(this.Command.MyInvocation, \"process_record_bound\");\n"
         "                        Command.DoProcessRecord();")),
    ENGINE + "/engine/ScriptCommandProcessor.cs": (
        ("this.ScriptParameterBinderController.BindCommandLineParameters(arguments);",
         "this.ScriptParameterBinderController.BindCommandLineParameters(arguments);\n"
         "                    EmumeeInvocationCapture.Record(this.Command.MyInvocation, \"script_arguments_bound\");"),)
}


def context(source: Path) -> tuple[bytes, str]:
    commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    status = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True)
    tag_object = subprocess.check_output(["git", "-C", str(source), "rev-parse", "v7.5.12"], text=True).strip()
    if commit != SOURCE_COMMIT or tag_object != SOURCE_TAG_OBJECT or status:
        raise ValueError("A clean upstream PowerShell 7.5.12 source checkout is required")
    logger = Path(__file__).with_name("powershell_engine_capture.cs").read_bytes()
    archive = io.BytesIO()
    digest = hashlib.sha256(logger + json.dumps(PATCHES, sort_keys=True).encode() + Path(__file__).read_bytes()).hexdigest()
    dockerfile = f"""FROM {SDK_IMAGE} AS build
ENV POWERSHELL_TELEMETRY_OPTOUT=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
WORKDIR /source
COPY source/ /source/
COPY version-git/ /source/.git/
RUN git config --global --add safe.directory /source && git describe --abbrev=60 --long && dotnet restore src/Microsoft.PowerShell.SDK/Microsoft.PowerShell.SDK.csproj
RUN pwsh -NoLogo -NoProfile -NonInteractive -Command "Import-Module ./build.psm1; Start-ResGen; Start-TypeGen"
COPY instrumentation/EmumeeInvocationCapture.cs /source/{ENGINE}/engine/EmumeeInvocationCapture.cs
RUN dotnet build {ENGINE}/System.Management.Automation.csproj -c Release -p:ReleaseTag=7.5.12 -p:RunAnalyzers=false -p:EnableNETAnalyzers=false > /engine-build.log 2>&1 || {{ head -n 20 /engine-build.log; tail -n 30 /engine-build.log; exit 1; }}
FROM scratch
COPY --from=build /source/{ENGINE}/bin/Release/net9.0/System.Management.Automation.dll /System.Management.Automation.dll
LABEL org.emumee.engine.patch={digest} org.emumee.engine.source={SOURCE_COMMIT}
""".encode()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
        add("Dockerfile", dockerfile)
        # Tracked source only: ignored files, local Git configuration, and any
        # unrelated Git objects are never included in the build context.
        tracked = subprocess.check_output(["git", "-C", str(source), "ls-files", "-z"]).decode().split("\0")
        for relative in filter(None, tracked):
            path = source / relative
            data = path.read_bytes()
            if relative == "nuget.config":
                # All pinned packages are public; avoid Azure upstream-cache
                # authorization requirements without importing credentials.
                data = (b'<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear />'
                        b'<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />'
                        b'</packageSources></configuration>')
            if relative in PATCHES:
                text = data.decode("utf-8").replace("\r\n", "\n")
                for old, new in PATCHES[relative]:
                    if text.count(old) != 1:
                        raise ValueError("Pinned engine patch point changed: " + relative)
                    text = text.replace(old, new)
                data = text.encode("utf-8")
            add("source/" + relative, data)
        add("instrumentation/EmumeeInvocationCapture.cs", logger)
        # Only two public upstream Git objects are needed to describe the
        # exact tagged commit. No local config, reflogs, hooks, or history.
        add("version-git/HEAD", (SOURCE_COMMIT + "\n").encode())
        add("version-git/config", b"[core]\nrepositoryformatversion=0\nbare=false\n")
        add("version-git/shallow", (SOURCE_COMMIT + "\n").encode())
        add("version-git/refs/tags/v7.5.12", (SOURCE_TAG_OBJECT + "\n").encode())
        for kind, oid in (("commit", SOURCE_COMMIT), ("tag", SOURCE_TAG_OBJECT)):
            contents = subprocess.check_output(["git", "-C", str(source), "cat-file", kind, oid])
            raw = f"{kind} {len(contents)}\0".encode() + contents
            if hashlib.sha1(raw).hexdigest() != oid:
                raise ValueError("Upstream Git object hash mismatch")
            add("version-git/objects/" + oid[:2] + "/" + oid[2:], zlib.compress(raw))
    return archive.getvalue(), digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data, digest = context(args.source.resolve())
    tag = "emumee-pwsh-engine:" + digest[:32]
    completed = subprocess.run(["docker", "build", "--pull=false", "--progress=plain", "--tag", tag, "-"], input=data)
    if completed.returncode:
        raise SystemExit(completed.returncode)
    container = subprocess.check_output(["docker", "create", tag, "/not-executed"], text=True).strip()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["docker", "cp", container + ":/System.Management.Automation.dll", str(args.output)], check=True)
    finally:
        subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL)
    evidence = {"source_commit": SOURCE_COMMIT, "sdk_image": SDK_IMAGE, "patch_sha256": digest,
                "assembly_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(), "build_image": tag}
    args.output.with_suffix(".build.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence))


if __name__ == "__main__":
    main()
