"""Run only a fixed harmless PowerShell confinement/trace probe in a Linux container.

This is a feasibility tool, not a submitted-script execution mode. It requires
an already pulled official SDK image pinned by repository digest.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
import subprocess
import uuid
from pathlib import Path


PROBE = r"""
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Collections;
public static class EmumeeCommandCapture {
    private static readonly List<object> Events = new List<object>();
    private static readonly List<object> IntegrityEvents = new List<object>();
    private static readonly HashSet<int> MonitoredBreakpoints = new HashSet<int>();
    private static int droppedEvents;
    private static string captureScope;
    public static object[] GetEvents() { return Events.ToArray(); }
    public static object[] GetIntegrityEvents() { return IntegrityEvents.ToArray(); }
    public static int DroppedEvents { get { return droppedEvents; } }
    public static object[] Run(string script, string scope) {
        captureScope = scope;
        using (var runspace = RunspaceFactory.CreateRunspace()) {
            runspace.Open();
            runspace.Debugger.DebuggerStop += OnStop;
            using (var ps = PowerShell.Create()) {
                ps.Runspace = runspace;
                ps.AddScript("Set-PSBreakpoint -Command '*' -Action { break }");
                var setup = ps.Invoke();
                if (ps.HadErrors || setup.Count != 1) throw new Exception("Capture breakpoint setup failed");
                var breakpoint = (Breakpoint)setup[0].BaseObject;
                MonitoredBreakpoints.Add(breakpoint.Id);
                runspace.Debugger.BreakpointUpdated += OnBreakpointUpdated;
                ps.Commands.Clear();
                ps.AddScript(script);
                var values = new List<object>();
                foreach (var value in ps.Invoke()) values.Add(value.BaseObject);
                if (ps.HadErrors) throw new Exception(ps.Streams.Error[0].ToString());
                var remainsEnabled = false;
                foreach (var current in runspace.Debugger.GetBreakpoints()) {
                    if (current.Id == breakpoint.Id && current.Enabled) remainsEnabled = true;
                }
                if (!remainsEnabled) RecordIntegrity(breakpoint.Id, "MissingOrDisabledAtEnd");
                MonitoredBreakpoints.Remove(breakpoint.Id);
                runspace.Debugger.BreakpointUpdated -= OnBreakpointUpdated;
                return values.ToArray();
            }
        }
    }
    private static void OnBreakpointUpdated(object sender, BreakpointUpdatedEventArgs args) {
        if (MonitoredBreakpoints.Contains(args.Breakpoint.Id))
            RecordIntegrity(args.Breakpoint.Id, args.UpdateType.ToString());
    }
    private static void RecordIntegrity(int id, string update) {
        if (IntegrityEvents.Count >= 128) { droppedEvents++; return; }
        IntegrityEvents.Add(new Dictionary<string, object> {
            ["event"] = "powershell_capture_breakpoint_update",
            ["timestamp_utc"] = DateTime.UtcNow.ToString("O"),
            ["scope"] = captureScope,
            ["breakpoint_id"] = id,
            ["update"] = update
        });
    }
    private static object Read(object target, string name) {
        if (target == null) return null;
        for (var type = target.GetType(); type != null; type = type.BaseType) {
            var flags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
            var field = type.GetField(name, flags);
            if (field != null) return field.GetValue(target);
            var property = type.GetProperty(name, flags);
            if (property != null) return property.GetValue(target);
        }
        return null;
    }
    private static void OnStop(object sender, DebuggerStopEventArgs args) {
        var call = args.InvocationInfo;
        var processor = Read(Read(sender, "_context"), "CurrentCommandProcessor");
        var actual = Read(Read(processor, "Command"), "MyInvocation") as InvocationInfo;
        args.ResumeAction = DebuggerResumeAction.Continue;
        if (call.MyCommand == null || actual == null || actual.MyCommand == null ||
            String.IsNullOrEmpty(call.MyCommand.Name) || call.MyCommand.Name != actual.MyCommand.Name) return;
        if (Events.Count >= 2000) { droppedEvents++; return; }
        var native = processor.GetType().Name == "NativeCommandProcessor";
        var binder = native ? Read(processor, "NativeParameterBinderController") : null;
        Events.Add(new Dictionary<string, object> {
            ["event"] = "powershell_command_invocation",
            ["sequence"] = Events.Count + 1,
            ["scope"] = captureScope,
            ["timestamp_utc"] = DateTime.UtcNow.ToString("O"),
            ["phase"] = "before_execution",
            ["capture"] = "engine_debugger_command_processor",
            ["command"] = actual.MyCommand.Name,
            ["invocation_name"] = actual.InvocationName,
            ["command_type"] = actual.MyCommand.CommandType.ToString(),
            ["bound_parameters"] = Snapshot(actual.BoundParameters, 0),
            ["unbound_arguments"] = Snapshot(actual.UnboundArguments, 0),
            ["native_arguments"] = native ? Snapshot(Read(binder, "ArgumentList"), 0) : null,
            ["path"] = native ? Read(processor, "Path") : null,
            ["source_line"] = call.Line,
        });
    }
    private static object Snapshot(object value, int depth) {
        if (value == null) return null;
        if (depth > 8) return new { truncated = true };
        if (value is PSObject ps) return Snapshot(ps.BaseObject, depth + 1);
        if (value is string text) return text.Length <= 16384 ? (object)text : new { truncated = true, prefix = text.Substring(0, 16384) };
        if (value is SwitchParameter toggle) return toggle.IsPresent;
        if (value is bool || value.GetType().IsPrimitive || value is decimal) return value;
        if (value is ScriptBlock script) return new { type = "ScriptBlock", text = script.ToString() };
        if (value is IDictionary dictionary) {
            var copy = new Dictionary<string, object>();
            foreach (DictionaryEntry item in dictionary) {
                if (copy.Count >= 128) { copy["capture_truncated"] = true; break; }
                copy[(string)item.Key] = Snapshot(item.Value, depth + 1);
            }
            return copy;
        }
        if (value is IList list) {
            var copy = new List<object>();
            foreach (var item in list) {
                if (copy.Count >= 128) { copy.Add(new { truncated = true }); break; }
                copy.Add(Snapshot(item, depth + 1));
            }
            return copy.ToArray();
        }
        return new { unsupported_value_type = value.GetType().FullName };
    }
}
'@
$fixtureScript = @'
Trace-Command -Name CommandDiscovery,ParameterBinding -FilePath /work/trace.log -Expression {
    $name = 'Write-' + 'Output'
    & $name ('runtime-' + 'resolved-argument')
    Invoke-Expression ('Write-Output ' + "'nested-resolved-argument'")
    & /bin/echo ('native-' + 'resolved-argument')
    $splat = @{ InputObject = @(('array-' + 'first'), 'array-second'); NoEnumerate = $true }
    & $name @splat | Out-Null
    $alias = 'ec' + 'ho'
    & $alias ('alias-' + 'resolved') | Out-Null
    & /bin/echo 'space value' 'quote"value' '' | Out-Null
}
'@
$values = @([EmumeeCommandCapture]::Run($fixtureScript, 'baseline'))
$tamperScript = @'
Write-Output ('before-' + 'disable')
Get-PSBreakpoint | Disable-PSBreakpoint
Write-Output ('after-' + 'disable')
Get-PSBreakpoint | Remove-PSBreakpoint
Write-Output ('after-' + 'remove')
'@
$tamperValues = @([EmumeeCommandCapture]::Run($tamperScript, 'breakpoint-tamper'))
$client = [System.Net.Sockets.TcpClient]::new()
$connected = $false
try {
    $task = $client.ConnectAsync('198.51.100.1', 80)
    if ($task.Wait(1500)) { $connected = $client.Connected }
} catch {} finally { $client.Dispose() }
$rootWrite = $false
try { [IO.File]::WriteAllText('/emumee-probe-marker', 'harmless'); $rootWrite = $true } catch {}
$status = [IO.File]::ReadAllText('/proc/self/status')
[ordered]@{
    powershell_version = $PSVersionTable.PSVersion.ToString()
    platform = $PSVersionTable.Platform
    values = $values
    command_events = @([EmumeeCommandCapture]::GetEvents())
    capture_integrity_events = @([EmumeeCommandCapture]::GetIntegrityEvents())
    tamper_values = $tamperValues
    dropped_command_events = [EmumeeCommandCapture]::DroppedEvents
    network_connected = $connected
    root_write_succeeded = $rootWrite
    host_drive_visible = [IO.Directory]::Exists('/mnt/c')
    docker_socket_visible = [IO.File]::Exists('/var/run/docker.sock')
    no_new_privileges = [bool]($status -match '(?m)^NoNewPrivs:\s+1$')
    effective_capabilities_zero = [bool]($status -match '(?m)^CapEff:\s+0+$')
    trace = [IO.File]::ReadAllText('/work/trace.log')
} | ConvertTo-Json -Depth 5 -Compress
"""


def docker(*args: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"docker {args[0]} observation timed out; inspect daemon state before retrying") from None
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr[:2000]}")
    return result.stdout


def probe(image: str, resume_container: str | None = None) -> dict:
    if not re.fullmatch(r"mcr\.microsoft\.com/dotnet/sdk@sha256:[0-9a-f]{64}", image):
        raise ValueError("Use an already pulled official SDK repository digest")
    image_info = json.loads(docker("image", "inspect", image))[0]
    if image_info.get("Os") != "linux":
        raise ValueError("The feasibility probe requires a Linux guest image")
    if resume_container and not re.fullmatch(r"emumee-pwsh-probe-[0-9a-f]{32}", resume_container):
        raise ValueError("Invalid probe container name")
    name = resume_container or "emumee-pwsh-probe-" + uuid.uuid4().hex
    print(json.dumps({"probe_container": name}), flush=True)
    encoded = base64.b64encode(PROBE.encode("utf-16le")).decode("ascii")
    created = False
    try:
        if resume_container:
            previous = json.loads(docker("inspect", name))[0]
            expected_command = ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
            if (previous["Image"] != image_info["Id"] or
                    previous["Config"]["Cmd"] != expected_command or
                    previous["State"]["Status"] != "created"):
                raise ValueError("Resume target is not this fixed probe in created state")
        else:
            docker("create", "--name", name, "--pull=never", "--network=none",
               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
               "--user=65534:65534", "--pids-limit=64", "--memory=512m", "--cpus=1",
               "--hostname=emumee-pwsh-probe", "--workdir=/work", "--log-driver=none",
               "--tmpfs=/work:rw,nosuid,nodev,noexec,size=16m,mode=1777",
               "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
               "--env=HOME=/work", "--env=POWERSHELL_TELEMETRY_OPTOUT=1",
               "--env=DOTNET_CLI_TELEMETRY_OPTOUT=1", image,
               "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded,
               timeout=90)
        created = True
        info = json.loads(docker("inspect", name))[0]
        config = info["HostConfig"]
        checks = {
            "network_none": config["NetworkMode"] == "none",
            "read_only_root": config["ReadonlyRootfs"] is True,
            "no_binds": not config.get("Binds"),
            "no_host_mounts": all(mount.get("Type") == "tmpfs"
                                  for mount in info.get("Mounts", [])),
            "no_privileged": config["Privileged"] is False,
            "capabilities_dropped": config["CapDrop"] == ["ALL"],
            "no_new_privileges": "no-new-privileges=true" in config["SecurityOpt"],
            "unprivileged_user": info["Config"]["User"] == "65534:65534",
            "memory_limited": config["Memory"] == 512 * 1024 * 1024,
            "pids_limited": config["PidsLimit"] == 64,
        }
        if not all(checks.values()):
            raise RuntimeError("Container configuration verification failed: " + str(checks))
        started_at = dt.datetime.now(dt.timezone.utc).isoformat()
        raw = docker("start", "--attach", name, timeout=90)
        if len(raw.encode("utf-8")) > 1024 * 1024:
            raise RuntimeError("Fixed probe output exceeded its expected bound")
        final = json.loads(docker("inspect", name))[0]["State"]
        if final["Running"] or final["ExitCode"] != 0 or final.get("OOMKilled"):
            raise RuntimeError("Fixed PowerShell probe did not complete successfully")
        finished_at = dt.datetime.now(dt.timezone.utc).isoformat()
        try:
            result = json.loads(raw)
        except ValueError:
            raise RuntimeError("Fixed probe returned invalid JSON: " + repr(raw[:1000])) from None
        expected = ["runtime-resolved-argument", "nested-resolved-argument", "native-resolved-argument"]
        commands = result["command_events"]
        integrity_events = result["capture_integrity_events"]
        tamper_updates = {event["update"] for event in integrity_events
                         if event["scope"] == "breakpoint-tamper"}
        def bound_input(value: list[str]) -> bool:
            return any(event["command"] == "Write-Output" and
                       event["bound_parameters"].get("InputObject") == value for event in commands)
        observed_checks = {
            "runtime_values": result["values"] == expected,
            "network_denied": result["network_connected"] is False,
            "root_write_denied": result["root_write_succeeded"] is False,
            "host_drive_absent": result["host_drive_visible"] is False,
            "docker_socket_absent": result["docker_socket_visible"] is False,
            "no_new_privileges": result["no_new_privileges"] is True,
            "capabilities_zero": result["effective_capabilities_zero"] is True,
            "expanded_trace_values": all(line in result["trace"] for line in (
                "BIND arg [runtime-resolved-argument] to param [InputObject] SUCCESSFUL",
                "BIND arg [nested-resolved-argument] to param [InputObject] SUCCESSFUL",
                "BIND cmd line arg [native-resolved-argument] to position [0]")),
            "structured_runtime_arguments": bound_input([expected[0]]) and bound_input([expected[1]]),
            "structured_splat_array": bound_input(["array-first", "array-second"]),
            "resolved_alias": bound_input(["alias-resolved"]),
            "native_argument_boundaries": any(event["native_arguments"] == ["space value", 'quote"value', ""]
                                              for event in commands),
            "no_dropped_commands": result["dropped_command_events"] == 0,
            "tamper_fixture_executed": result["tamper_values"] == ["before-disable", "after-disable", "after-remove"],
            "breakpoint_disable_detected": "Disabled" in tamper_updates,
            "breakpoint_remove_detected": "Removed" in tamper_updates,
            "final_breakpoint_loss_detected": "MissingOrDisabledAtEnd" in tamper_updates,
            "baseline_monitor_unchanged": not any(event["scope"] == "baseline" for event in integrity_events),
            "capture_gap_verified": not bound_input(["after-disable"]) and not bound_input(["after-remove"]),
        }
        return {"image": image, "image_id": image_info["Id"],
                "execution_started_at": started_at, "execution_finished_at": finished_at,
                "configuration_checks": checks, "observed_checks": observed_checks,
                "passed": all(observed_checks.values()), "probe": result,
                "limitations": ["Fixed harmless probe only; no submitted scripts are accepted",
                                "Linux PowerShell does not reproduce a Windows persona",
                                "Trace-Command is script-controllable and is not a complete audit boundary",
                                "Debugger capture uses private version-specific engine fields and can be disabled by script code",
                                "DebuggerHidden paths, new runspaces, and native descendants are not completely traced",
                                "Complex values use bounded snapshots; unsupported value types are marked",
                                "Records observe invocations before execution and do not establish successful completion",
                                "The probe does not establish resistance to container escape"]}
    finally:
        if created:
            docker("rm", "--force", name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume-container", help="Resume this fixed probe after a create observation timeout")
    parser.add_argument("--dashboard-root", type=Path, help="Save verified fixed-probe evidence as a partial dashboard run")
    args = parser.parse_args()
    report = probe(args.image, args.resume_container)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.dashboard_root and report["passed"]:
        from emumee.powershell_probe_report import save_probe_run
        run = save_probe_run(report, args.dashboard_root, PROBE)
        print(json.dumps({"dashboard_run": str(run)}))
    print(json.dumps({"passed": report["passed"], "output": str(args.output),
                      "checks": report["observed_checks"]}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
