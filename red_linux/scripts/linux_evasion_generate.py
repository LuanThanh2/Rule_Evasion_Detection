#!/usr/bin/env python3
"""
Generate candidate evasion variants from the RED-Linux match set, as a Zircolite
input JSONL — to be RE-VERIFIED by Zircolite (the real Sigma engine), not by a
substring heuristic.

Pipeline:
    match events (events/.../<rule>/*_Match_*.json)
        -> apply argv-level transforms to process.command_line
        -> emit Zircolite input (2 rows/candidate: SYSCALL + EXECVE)
        -> [run zircolite]  -> linux_evasion_verify.py keeps only candidates that
                               NO LONGER match their origin rule = true evasion.

Why argv-level transforms (not shell tricks): auditd records argv AFTER the shell
expands it, so `cu''rl`/`c\\url` still log as `curl`. Only transforms that change
the actual argv evade auditd/Sigma:
    - tool swap (curl<->wget, useradd<->adduser, systemctl<->service)
    - long<->short flags (-X <-> --request, -R <-> --recursive, ...)
    - flag reorder, combined short flags
    - chmod octal<->symbolic

Each candidate carries `evid` so the verifier can map detections back.

Usage:
    python3 linux_evasion_generate.py \
        --matches-dir /home/luanthanh/data/red_linux/events/linux/process_creation \
        --out /home/luanthanh/data/red_linux/work/evasion_candidates.jsonl \
        --meta /home/luanthanh/data/red_linux/work/evasion_meta.json
"""

import argparse
import json
import os
import random
import re
import shlex
from pathlib import Path

random.seed(42)


# --------------------------- argv-level transforms ---------------------------

CURL_LONG = {"-X": "--request", "-i": "--include", "-s": "--silent",
             "-k": "--insecure", "-O": "--remote-name", "-d": "--data",
             "-o": "--output", "-H": "--header", "-L": "--location",
             "-u": "--user", "-A": "--user-agent"}
CHMOD_LONG = {"-R": "--recursive", "-f": "--silent", "-v": "--verbose"}


def t_tool_swap(cmd: str) -> str:
    """curl<->wget, useradd<->adduser, systemctl stop<->service ... stop."""
    out = cmd
    if re.match(r"(/\S+/)?curl\b", out):
        out = re.sub(r"\bcurl\b", "wget", out, count=1)
    elif re.match(r"(/\S+/)?wget\b", out):
        out = re.sub(r"\bwget\b", "curl", out, count=1)
    if re.search(r"\buseradd\b", out):
        out = re.sub(r"(/\S+/)?useradd\b", "adduser", out, count=1)
    elif re.search(r"\badduser\b", out):
        out = re.sub(r"(/\S+/)?adduser\b", "useradd", out, count=1)
    return out


def t_long_flags(cmd: str) -> str:
    """Replace short flags with their long equivalents."""
    toks = cmd.split(" ")
    head = toks[0].lower()
    table = CHMOD_LONG if head.endswith("chmod") else CURL_LONG
    return " ".join(table.get(t, t) for t in toks)


def t_flag_reorder(cmd: str) -> str:
    """Shuffle the run of leading single-dash flags (keeps program + tail)."""
    toks = cmd.split(" ")
    if len(toks) < 4:
        return cmd
    flags = [i for i, t in enumerate(toks) if re.fullmatch(r"-[A-Za-z]", t)]
    if len(flags) < 2:
        return cmd
    vals = [toks[i] for i in flags]
    random.shuffle(vals)
    for i, v in zip(flags, vals):
        toks[i] = v
    return " ".join(toks)


def t_combine_short_flags(cmd: str) -> str:
    """`-i -s -k` -> `-isk` (consecutive single-letter flags w/o values)."""
    return re.sub(
        r"((?:-[A-Za-z] ){2,}-[A-Za-z])(?= |$)",
        lambda m: "-" + "".join(t.lstrip("-") for t in m.group(1).split()),
        cmd,
    )


def t_abs_path(cmd: str) -> str:
    """bare program -> absolute path (changes Image/exe but keeps argv[0] basename)."""
    toks = cmd.split(" ", 1)
    prog = toks[0]
    if "/" in prog:
        return cmd
    common = {"curl": "/usr/bin/curl", "wget": "/usr/bin/wget",
              "chmod": "/usr/bin/chmod", "useradd": "/usr/sbin/useradd",
              "systemctl": "/usr/bin/systemctl", "service": "/usr/sbin/service",
              "bash": "/usr/bin/bash", "sh": "/usr/bin/sh"}
    full = common.get(prog, f"/usr/bin/{prog}")
    return full + (" " + toks[1] if len(toks) > 1 else "")


def t_chmod_symbolic(cmd: str) -> str:
    """chmod 777 -> chmod a+rwx, 755 -> u+rwx,go+rx (common modes)."""
    modes = {"777": "a+rwx", "755": "u+rwx,go+rx", "700": "u+rwx",
             "644": "u+rw,go+r", "666": "a+rw", "600": "u+rw", "+x": "u+x"}
    return re.sub(r"\b(777|755|700|644|666|600)\b",
                  lambda m: modes.get(m.group(1), m.group(1)), cmd)


def t_systemctl_service(cmd: str) -> str:
    """`systemctl stop X` <-> `service X stop`."""
    m = re.match(r"(?:/\S+/)?systemctl\s+(stop|disable|start|restart)\s+(\S+)(.*)", cmd)
    if m:
        return f"service {m.group(2)} {m.group(1)}{m.group(3)}"
    m = re.match(r"(?:/\S+/)?service\s+(\S+)\s+(stop|disable|start|restart)(.*)", cmd)
    if m:
        return f"systemctl {m.group(2)} {m.group(1)}{m.group(3)}"
    return cmd


# busybox provides applets via internal dispatch (NO second execve), so the
# kernel records exe=/usr/bin/busybox, argv[0]=busybox -> evades `Image|endswith
# '/<tool>'` rules for real. Only applets busybox actually ships.
_BUSYBOX_APPLETS = {"chmod", "wget", "cat", "cp", "mv", "tar", "nc", "id",
                    "find", "sed", "awk", "chown", "ls", "ps"}


def t_busybox_applet(cmd: str) -> str:
    m = re.match(r"(?:/\S+/)?([A-Za-z][\w-]*)\b(.*)", cmd)
    if not m:
        return cmd
    prog, rest = m.group(1), m.group(2)
    if prog in _BUSYBOX_APPLETS:
        return f"busybox {prog}{rest}"
    return cmd


# Sigma checks CommandLine|contains for absolute suspicious dirs but NOT the
# process cwd. `cd /tmp && chmod 777 x` logs the chmod argv WITHOUT '/tmp/'.
_SUSP_DIRS = r"(?:/tmp|/var/tmp|/dev/shm|/etc|/opt|/\.Library)"


def t_relative_path(cmd: str) -> str:
    """Strip a leading suspicious-dir prefix from path args (cd-then-relative)."""
    return re.sub(rf"{_SUSP_DIRS}/(\S+)", r"\1", cmd)


def t_alt_subcommand(cmd: str) -> str:
    """services rule matches stop/disable; `mask` disables a unit without either."""
    return re.sub(r"\b(?:systemctl|service)\s+(stop|disable)\b",
                  lambda m: m.group(0).replace(m.group(1), "mask"), cmd)


TRANSFORMS = {
    "tool_swap": t_tool_swap,
    "busybox_applet": t_busybox_applet,
    "relative_path": t_relative_path,
    "alt_subcommand": t_alt_subcommand,
    "long_flags": t_long_flags,
    "flag_reorder": t_flag_reorder,
    "combine_short_flags": t_combine_short_flags,
    "abs_path": t_abs_path,
    "chmod_symbolic": t_chmod_symbolic,
    "systemctl_service": t_systemctl_service,
}


# --------------------------- zircolite record build --------------------------

def build_rows(cmd: str, evid: str):
    """Build SYSCALL + EXECVE rows for one candidate command line."""
    try:
        args = shlex.split(cmd)
    except ValueError:
        args = cmd.split(" ")
    if not args:
        return []
    prog = args[0]
    exe = prog if prog.startswith("/") else f"/usr/bin/{os.path.basename(prog)}"
    comm = os.path.basename(prog)
    common = {"Image": exe, "CommandLine": cmd, "exe": exe, "comm": comm,
              "User": "root", "CurrentDirectory": "/tmp", "key": "audit-wazuh-c",
              "evid": evid}
    syscall = {**common, "type": "SYSCALL"}
    execve = {**common, "type": "EXECVE"}
    for i, a in enumerate(args):
        execve[f"a{i}"] = a
    return [syscall, execve]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matches-dir", required=True,
                    help="events/.../process_creation dir (medium+ match set)")
    ap.add_argument("--out", required=True, help="Zircolite input JSONL (candidates)")
    ap.add_argument("--meta", required=True, help="candidate metadata JSON")
    args = ap.parse_args()

    matches_dir = Path(os.path.expanduser(args.matches_dir))
    meta = {}
    n_cand = 0
    seen = set()  # (rule_id, transformed_cmd) -> dedupe identical candidates

    with open(os.path.expanduser(args.out), "w", encoding="utf-8") as out:
        for mf in sorted(matches_dir.rglob("*_Match_*.json")):
            ev = json.load(open(mf, encoding="utf-8"))
            orig_cmd = (ev.get("process", {}) or {}).get("command_line", "")
            rule_id = ev.get("rule_id", "")
            rule_title = ev.get("rule_title", "")
            if not orig_cmd or not rule_id:
                continue

            for tech, fn in TRANSFORMS.items():
                try:
                    new_cmd = fn(orig_cmd)
                except Exception:
                    continue
                if not new_cmd or new_cmd == orig_cmd:
                    continue
                key = (rule_id, new_cmd)
                if key in seen:
                    continue
                seen.add(key)

                evid = f"ev{n_cand:06d}"
                meta[evid] = {
                    "origin_rule_id": rule_id,
                    "origin_rule_title": rule_title,
                    "origin_sigmafile": ev.get("sigmafile", ""),
                    "technique": tech,
                    "original_cmd": orig_cmd,
                    "transformed_cmd": new_cmd,
                    "source_file": str(mf.relative_to(matches_dir)),
                }
                for row in build_rows(new_cmd, evid):
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
                n_cand += 1

    json.dump(meta, open(os.path.expanduser(args.meta), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print(f"generated {n_cand} candidate variants -> {args.out}")
    print(f"metadata -> {args.meta}")


if __name__ == "__main__":
    main()
