#!/usr/bin/env python3
"""Export RED evasion JSON events into Windows replay scripts.

The generated files are intended for an isolated Windows lab with Sysmon,
PowerShell Script Block Logging, and Elastic Agent enabled.

Default mode is safe: scripts print the extracted evasion content without
executing it. To generate executable replay scripts, use:

  --mode execute --i-understand-risk

Examples:
  python scripts/export_evasion_scripts.py \
    --evasions-dir ~/data/sigma/evasions/windows \
    --out-dir ~/data/sigma/evasion_scripts/windows \
    --event-type powershell --limit 20

  python scripts/export_evasion_scripts.py \
    --event-type all --mode execute --i-understand-risk --limit-per-rule 2
"""

import argparse
import csv
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


EVENT_TYPES = ("process_creation", "powershell", "registry_event")


def sanitize_name(value: str, max_len: int = 90) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return (value or "evasion")[:max_len]


def short_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:10]


def ps_here_string(name: str, value: str) -> str:
    """Return a single-quoted PowerShell here-string assignment."""
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return f"${name} = @'\n{value}\n'@\n"


def get_path(obj: Dict[str, Any], dotted: str) -> Optional[str]:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    if isinstance(cur, str) and cur.strip():
        return cur
    return None


def first_path(obj: Dict[str, Any], paths: Iterable[str]) -> Tuple[Optional[str], Optional[str]]:
    for path in paths:
        value = get_path(obj, path)
        if value:
            return value, path
    return None, None


def event_type_from_path(path: Path, root: Path) -> Optional[str]:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return None
    if not rel.parts:
        return None
    top = rel.parts[0]
    return top if top in EVENT_TYPES else None


def iter_evasion_files(root: Path, event_type: str) -> Iterable[Tuple[str, Path]]:
    selected = EVENT_TYPES if event_type == "all" else (event_type,)
    for etype in selected:
        base = root / etype
        if not base.is_dir():
            continue
        for fpath in sorted(base.glob("*/*.json")):
            yield etype, fpath


def load_event(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Not a JSON object: {path}")
    return data


def extract_process_command(event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    return first_path(
        event,
        (
            "process.command_line",
            "winlog.event_data.CommandLine",
            "Details.Cmdline",
            "CommandLine",
        ),
    )


def extract_powershell_script(event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    return first_path(
        event,
        (
            "winlog.event_data.ScriptBlockText",
            "Details.ScriptBlockText",
            "Details.ScriptBlock",
            "Details.Cmdline",
            "ExtraFieldInfo.ScriptBlockText",
        ),
    )


def extract_registry_event(event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], str]:
    target, _ = first_path(event, ("winlog.event_data.TargetObject", "Details.RegKey"))
    details, _ = first_path(event, ("winlog.event_data.Details", "Details.Details"))
    return target, details, "winlog.event_data.TargetObject"


def script_header(event: Dict[str, Any], source_json: Path, mode: str) -> str:
    rule = event.get("RuleTitle") or source_json.parent.name
    technique = event.get("_evasion_technique", "")
    evasion_field = event.get("_evasion_field", "")
    return (
        "# RED evasion replay script\n"
        f"# Mode: {mode}\n"
        f"# Rule: {rule}\n"
        f"# Technique: {technique}\n"
        f"# EvasionField: {evasion_field}\n"
        f"# SourceJson: {source_json}\n\n"
    )


def process_script(event: Dict[str, Any], source_json: Path, mode: str) -> Optional[str]:
    command, field = extract_process_command(event)
    if not command:
        return None
    body = script_header(event, source_json, mode)
    body += f"# ExtractedField: {field}\n"
    body += ps_here_string("RedCommand", command)
    if mode == "safe":
        body += (
            'Write-Host "[SAFE] Process command extracted. Not executing."\n'
            'Write-Host $RedCommand\n'
        )
    else:
        body += (
            'Write-Host "[EXECUTE] Running process command via cmd.exe /c"\n'
            'Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", $RedCommand) '
            "-Wait -NoNewWindow\n"
        )
    return body


def powershell_script(event: Dict[str, Any], source_json: Path, mode: str) -> Optional[str]:
    script, field = extract_powershell_script(event)
    if not script:
        return None
    body = script_header(event, source_json, mode)
    body += f"# ExtractedField: {field}\n"
    body += ps_here_string("RedScriptBlockText", script)
    if mode == "safe":
        body += (
            'Write-Host "[SAFE] PowerShell ScriptBlockText extracted. Not executing."\n'
            'Write-Host $RedScriptBlockText\n'
        )
    else:
        body += (
            'Write-Host "[EXECUTE] Invoking PowerShell ScriptBlockText"\n'
            "Invoke-Expression $RedScriptBlockText\n"
        )
    return body


def registry_ps_path(reg_path: str) -> str:
    path = reg_path.strip().replace("/", "\\")
    path = re.sub(r"^HKEY_LOCAL_MACHINE\\", r"HKLM:\\", path, flags=re.IGNORECASE)
    path = re.sub(r"^HKLM\\", r"HKLM:\\", path, flags=re.IGNORECASE)
    path = re.sub(r"^HKEY_CURRENT_USER\\", r"HKCU:\\", path, flags=re.IGNORECASE)
    path = re.sub(r"^HKCU\\", r"HKCU:\\", path, flags=re.IGNORECASE)
    path = re.sub(r"^HKEY_USERS\\", r"HKU:\\", path, flags=re.IGNORECASE)
    path = re.sub(r"^HKU\\", r"HKU:\\", path, flags=re.IGNORECASE)
    path = re.sub(r"^\\REGISTRY\\MACHINE\\", r"HKLM:\\", path, flags=re.IGNORECASE)
    path = re.sub(r"^\\REGISTRY\\USER\\", r"HKU:\\", path, flags=re.IGNORECASE)
    return path


def split_registry_target(target: str) -> Tuple[str, str]:
    target = target.rstrip("\\")
    parts = target.split("\\")
    if len(parts) <= 1:
        return registry_ps_path(target), "(Default)"
    key = "\\".join(parts[:-1])
    value_name = parts[-1] or "(Default)"
    return registry_ps_path(key), value_name


def parse_registry_details(details: Optional[str]) -> Tuple[str, str]:
    if not details or details == "(Empty)":
        return "String", ""
    m = re.match(r"DWORD\s+\(0x([0-9A-Fa-f]+)\)", details)
    if m:
        return "DWord", str(int(m.group(1), 16))
    m = re.match(r"QWORD\s+\(0x([0-9A-Fa-f]+)(?:-0x[0-9A-Fa-f]+)?\)", details)
    if m:
        return "QWord", str(int(m.group(1), 16))
    return "String", details


def registry_script(event: Dict[str, Any], source_json: Path, mode: str) -> Optional[str]:
    target, details, field = extract_registry_event(event)
    if not target:
        return None
    key_path, value_name = split_registry_target(target)
    prop_type, prop_value = parse_registry_details(details)

    body = script_header(event, source_json, mode)
    body += f"# ExtractedField: {field}\n"
    body += ps_here_string("RedRegistryTarget", target)
    body += ps_here_string("RedRegistryDetails", details or "")
    body += ps_here_string("RedRegistryKey", key_path)
    body += ps_here_string("RedRegistryValueName", value_name)
    body += ps_here_string("RedRegistryValueData", prop_value)
    body += f"$RedRegistryPropertyType = '{prop_type}'\n"
    body += "New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null\n"
    if mode == "safe":
        body += (
            'Write-Host "[SAFE] Registry operation extracted. Not modifying registry."\n'
            'Write-Host "Target: $RedRegistryTarget"\n'
            'Write-Host "Details: $RedRegistryDetails"\n'
            'Write-Host "Would set: $RedRegistryKey :: $RedRegistryValueName = $RedRegistryValueData"\n'
        )
    else:
        body += (
            'Write-Host "[EXECUTE] Applying registry operation"\n'
            "New-Item -Path $RedRegistryKey -Force | Out-Null\n"
            "if ($RedRegistryValueName -eq '(Default)') {\n"
            "    Set-Item -Path $RedRegistryKey -Value $RedRegistryValueData\n"
            "} else {\n"
            "    New-ItemProperty -Path $RedRegistryKey -Name $RedRegistryValueName "
            "-Value $RedRegistryValueData -PropertyType $RedRegistryPropertyType -Force | Out-Null\n"
            "}\n"
        )
    return body


def build_script(event_type: str, event: Dict[str, Any], source_json: Path, mode: str) -> Optional[str]:
    if event_type == "process_creation":
        return process_script(event, source_json, mode)
    if event_type == "powershell":
        return powershell_script(event, source_json, mode)
    if event_type == "registry_event":
        return registry_script(event, source_json, mode)
    return None


def write_run_all(out_dir: Path, scripts: Iterable[Path], mode: str) -> None:
    run_all = out_dir / f"run_all_{mode}.ps1"
    lines = [
        "# RED evasion replay runner",
        f"# Mode: {mode}",
        "$ErrorActionPreference = 'Continue'",
        "",
    ]
    for script in scripts:
        rel = script.relative_to(out_dir).as_posix()
        lines.append(f'Write-Host "[RED] Running {rel}"')
        lines.append(f'& "$PSScriptRoot/{rel}"')
        lines.append("")
    run_all.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export evasion JSON files to Windows replay scripts")
    parser.add_argument("--evasions-dir", default="~/data/sigma/evasions/windows")
    parser.add_argument("--out-dir", default="~/data/sigma/evasion_scripts/windows")
    parser.add_argument("--event-type", choices=("all",) + EVENT_TYPES, default="all")
    parser.add_argument("--mode", choices=("safe", "execute"), default="safe")
    parser.add_argument("--i-understand-risk", action="store_true",
                        help="Required with --mode execute")
    parser.add_argument("--limit", type=int, default=None,
                        help="Total maximum scripts to export")
    parser.add_argument("--limit-per-rule", type=int, default=None,
                        help="Maximum scripts to export per rule directory")
    args = parser.parse_args()

    if args.mode == "execute" and not args.i_understand_risk:
        parser.error("--mode execute requires --i-understand-risk")

    root = Path(os.path.expanduser(args.evasions_dir)).resolve()
    out_dir = Path(os.path.expanduser(args.out_dir)).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = out_dir / "manifest.csv"
    scripts_written = []
    per_rule_counts = {}
    total = 0

    with manifest_path.open("w", encoding="utf-8", newline="") as mf:
        writer = csv.DictWriter(
            mf,
            fieldnames=[
                "event_type", "rule", "technique", "mode",
                "source_json", "script_path",
            ],
        )
        writer.writeheader()

        for event_type, source_json in iter_evasion_files(root, args.event_type):
            rule_name = source_json.parent.name
            if args.limit is not None and total >= args.limit:
                break
            if args.limit_per_rule is not None:
                key = (event_type, rule_name)
                if per_rule_counts.get(key, 0) >= args.limit_per_rule:
                    continue

            try:
                event = load_event(source_json)
                content = build_script(event_type, event, source_json, args.mode)
            except Exception as exc:
                print(f"[skip] {source_json}: {exc}")
                continue
            if not content:
                print(f"[skip] {source_json}: no supported replay field")
                continue

            technique = event.get("_evasion_technique") or "unknown"
            unique = short_hash(str(source_json))
            name = sanitize_name(f"{rule_name}_{technique}_{source_json.stem}", max_len=80)
            name = f"{name}_{unique}.ps1"
            script_dir = out_dir / event_type / rule_name
            script_dir.mkdir(parents=True, exist_ok=True)
            script_path = script_dir / name
            script_path.write_text(content, encoding="utf-8")

            scripts_written.append(script_path)
            per_rule_counts[(event_type, rule_name)] = per_rule_counts.get((event_type, rule_name), 0) + 1
            total += 1
            writer.writerow({
                "event_type": event_type,
                "rule": rule_name,
                "technique": technique,
                "mode": args.mode,
                "source_json": str(source_json),
                "script_path": str(script_path),
            })

    write_run_all(out_dir, scripts_written, args.mode)
    print(f"Exported {len(scripts_written)} scripts to {out_dir}")
    print(f"Manifest: {manifest_path}")
    print(f"Runner: {out_dir / ('run_all_' + args.mode + '.ps1')}")


if __name__ == "__main__":
    main()
