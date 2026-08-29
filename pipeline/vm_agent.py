"""Helper script executed *on the Windows VM* to drive IDA Pro.

This module is never imported locally — its source is piped to the VM's Python
over SSH (`ssh host python - <subcommand> [args]`).  Keeping it as a real file
(rather than a string blob) means it stays lintable and greppable.

All subcommands accept a leading `--ida-dir <path>`.

Subcommands:
    probe                 -> {"ok": true, "ida": "<path>", "python": "..."}
    instances             -> [{"port":..,"pid":..,"binary":..,"idb_path":..,"alive":..}, ...]
    launch <binary>       -> {"pid": 1234}   (detached; survives the SSH session)
    ensure_dir <path>     -> {"path": "..."}
"""

import json
import os
import subprocess
import sys

IDA_DIR = r"C:\Program Files\IDA Professional 9.3"


def _ida_exe() -> str:
    # The GUI binary is required: the ida-pro-mcp plugin's HTTP server does not
    # start under idat.exe (batch mode).
    return os.path.join(IDA_DIR, "ida.exe")


def _instances_dir() -> str:
    return os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro", "mcp", "instances")


def _pid_alive(pid: int) -> bool:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except Exception:
        return False
    return str(pid) in out


def cmd_probe():
    exe = _ida_exe()
    return {
        "ok": os.path.isfile(exe),
        "ida": exe,
        "python": sys.version.split()[0],
        "instances_dir": _instances_dir(),
    }


def cmd_instances():
    d = _instances_dir()
    out = []
    if not os.path.isdir(d):
        return out
    for name in os.listdir(d):
        if not name.startswith("instance_") or not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(d, name), encoding="utf-8") as fh:
                info = json.load(fh)
        except Exception:
            continue
        pid = int(info.get("pid") or 0)
        info["alive"] = _pid_alive(pid) if pid else False
        out.append(info)
    return out


def cmd_launch(binary):
    exe = _ida_exe()
    if not os.path.isfile(exe):
        raise RuntimeError(f"IDA not found at {exe}")
    if not os.path.isfile(binary):
        raise RuntimeError(f"binary not found on VM: {binary}")
    # A process started normally over SSH dies when the SSH session closes, so
    # spawn it through WMI, which reparents it outside the session's job.
    cmdline = f'"{exe}" -A "{binary}"'
    # Wrap in a PowerShell single-quoted literal (escape any embedded quote by
    # doubling it) so the double quotes around the paths survive intact.
    ps_literal = "'" + cmdline.replace("'", "''") + "'"
    ps = (
        "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
        "-Arguments @{CommandLine=" + ps_literal + "}; "
        'Write-Output "$($r.ReturnValue) $($r.ProcessId)"'
    )
    res = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=120,
    )
    parts = (res.stdout or "").split()
    if len(parts) < 2 or parts[0] != "0":
        raise RuntimeError(f"WMI launch failed: {res.stdout.strip()} {res.stderr.strip()}")
    return {"pid": int(parts[1])}


def cmd_ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return {"path": path}


def main():
    global IDA_DIR
    args = sys.argv[1:]
    # `--ida-dir <path>` overrides the install location (the caller's config
    # is authoritative; the VM has no env var for it).
    if len(args) >= 2 and args[0] == "--ida-dir":
        IDA_DIR = args[1]
        args = args[2:]
    if not args:
        print(json.dumps({"error": "no subcommand"}))
        return 2
    table = {
        "probe": cmd_probe,
        "instances": cmd_instances,
        "launch": cmd_launch,
        "ensure_dir": cmd_ensure_dir,
    }
    fn = table.get(args[0])
    if fn is None:
        print(json.dumps({"error": f"unknown subcommand {args[0]}"}))
        return 2
    try:
        print(json.dumps(fn(*args[1:])))
    except Exception as e:
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
