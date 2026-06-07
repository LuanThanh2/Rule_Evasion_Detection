#!/usr/bin/env python3
"""
GTFOBins -> malicious command corpus for RED-Linux.

GTFOBins documents legitimate Linux binaries that can be abused for shells,
file read/write, exfiltration, download, library load, and privilege escalation.
The labels come from GTFOBins function metadata and MITRE mappings, not from
Sigma/Wazuh alerts, so this is a second clean malicious source next to ART.

Input:
  <gtfobins>/_gtfobins/* and <gtfobins>/_data/functions.yml

Output JSONL:
  {command_line, technique, techniques, binary, function, context, source}

Run:
  ~/venvs/rule_evasion_env/bin/python red_linux/scripts/gtfobins_to_malicious.py \
    --gtfobins ~/tools/gtfobins \
    --out /home/luanthanh/data/red_linux/benign/process_creation/gtfobins_malicious.jsonl
"""

import argparse
import json
import os
import re
import shlex
from collections import Counter
from pathlib import Path

import yaml

SKIP_LINE = re.compile(
    r"^\s*(#|$|if\b|then\b|else\b|fi\b|for\b|while\b|do\b|done\b|case\b|esac\b|\{|\}|EOF\b)"
)
SEP_TOKENS = {"|", "||", "&", "&&", ";"}
ASSIGN_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def read_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def join_continuations(code):
    """Collapse shell backslash-continuations before line filtering."""
    out, buf = [], ""
    for raw in code.splitlines():
        line = raw.rstrip()
        if not line.strip():
            if buf:
                out.append(buf.strip())
                buf = ""
            continue
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continue
        if buf:
            line = buf + line.strip()
            buf = ""
        out.append(line.strip())
    if buf:
        out.append(buf.strip())
    return out


def shell_tokens(line):
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars="|&;")
        lex.whitespace_split = True
        return list(lex)
    except (TypeError, ValueError):
        try:
            return shlex.split(line)
        except ValueError:
            return re.findall(r"[^\s]+", line)


def token_basename(tok):
    tok = tok.strip("'\"")
    if "=" in tok and not tok.startswith("/"):
        tok = tok.rsplit("=", 1)[-1]
    return os.path.basename(tok)


def command_for_binary(line, binary):
    """Return the process-like command segment that invokes the GTFOBin binary.

    If the line starts with the binary, keep the original text to preserve shell
    syntax. If the binary appears after a pipe/semicolon, return that segment so
    process_creation Image/CommandLine roughly describe the abused binary rather
    than a setup command such as echo/printf.
    """
    stripped = line.strip()
    if SKIP_LINE.match(stripped):
        return None

    tokens = shell_tokens(stripped)
    if not tokens:
        return None

    useful = [t for t in tokens if t not in SEP_TOKENS]
    if useful and useful[0] == "export":
        useful = useful[1:]
    if useful and all(ASSIGN_TOKEN.match(t) for t in useful):
        return None

    # Drop leading VAR=value assignments for first-command detection.
    first = 0
    if first < len(tokens) and tokens[first] == "export":
        first += 1
    while first < len(tokens) and (ASSIGN_TOKEN.match(tokens[first]) or tokens[first] in SEP_TOKENS):
        first += 1
    if first >= len(tokens):
        return None

    if token_basename(tokens[first]) == binary:
        return stripped

    target_idx = None
    for i, tok in enumerate(tokens):
        if token_basename(tok) == binary:
            target_idx = i
            break
    if target_idx is None:
        return None

    start = 0
    for i in range(target_idx - 1, -1, -1):
        if tokens[i] in SEP_TOKENS:
            start = i + 1
            break
    end = len(tokens)
    for i in range(target_idx + 1, len(tokens)):
        if tokens[i] in SEP_TOKENS:
            end = i
            break

    segment = " ".join(tokens[start:end]).strip()
    return segment or stripped


def code_to_commands(code, binary):
    commands = []
    for line in join_continuations(code or ""):
        cmd = command_for_binary(line, binary)
        if cmd:
            commands.append(cmd)
    return commands


def example_codes(example):
    """Yield (context, code) for base and context-specific override code."""
    base = example.get("code")
    if base:
        yield "default", base
    for ctx, cfg in (example.get("contexts") or {}).items():
        if isinstance(cfg, dict) and cfg.get("code"):
            yield ctx, cfg["code"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gtfobins", default="/home/luanthanh/tools/gtfobins")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.gtfobins).expanduser()
    func_meta = read_yaml(root / "_data/functions.yml")
    files = sorted((root / "_gtfobins").glob("*"))

    rows, seen = [], set()
    skipped_no_mitre = 0
    func_counts, tech_counts = Counter(), Counter()

    for fp in files:
        if not fp.is_file():
            continue
        binary = fp.name
        doc = read_yaml(fp)
        for func, examples in (doc.get("functions") or {}).items():
            if not isinstance(examples, list):
                continue
            for n, ex in enumerate(examples):
                if not isinstance(ex, dict):
                    continue
                mitre = ex.get("mitre") or (func_meta.get(func, {}) or {}).get("mitre") or []
                mitre = [str(t) for t in mitre if str(t).startswith("T")]
                if not mitre:
                    skipped_no_mitre += 1
                    continue
                for context, code in example_codes(ex):
                    for cmd in code_to_commands(code, binary):
                        if cmd in seen:
                            continue
                        seen.add(cmd)
                        row = {
                            "command_line": cmd,
                            "technique": mitre[0],
                            "techniques": mitre,
                            "binary": binary,
                            "function": func,
                            "context": context,
                            "source": "GTFOBins",
                            "url": f"https://gtfobins.github.io/gtfobins/{binary}/#{func}",
                        }
                        rows.append(row)
                        func_counts[func] += 1
                        for t in mitre:
                            tech_counts[t] += 1

    outp = Path(args.out).expanduser()
    outp.parent.mkdir(parents=True, exist_ok=True)
    with open(outp, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"GTFOBins files: {len(files)}")
    print(f"unique command lines: {len(rows)}")
    print(f"functions: {len(func_counts)} | MITRE techniques: {len(tech_counts)}")
    print(f"skipped examples without MITRE: {skipped_no_mitre}")
    print(f"top functions: {func_counts.most_common(10)}")
    print(f"techniques: {sorted(tech_counts)}")
    print(f"wrote {outp}")


if __name__ == "__main__":
    main()
