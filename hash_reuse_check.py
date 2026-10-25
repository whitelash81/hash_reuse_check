#!/usr/bin/env python3
"""
hash_reuse_check.py
Compares an NTDS dump (domain accounts) against a folder of local SAM dumps
(one file per host) to find:

  1. Domain <-> Local password reuse - a domain account's NT hash also shows
     up as a local account's hash on one or more hosts.
  2. Local <-> Local password reuse (lateral movement candidates) - the same
     local NT hash shows up on multiple hosts (pass-the-hash across all of them).

Prompts for: NTDS file, SAM dump folder, export file, include blank hash.
Exports a text report (same format as the console) plus two CSVs written
alongside the export file:
    <export>_domain_vs_local.csv
    <export>_lateral_movement.csv

SAM dump folder:
  - Every file in the folder is read as one host's SAM dump, any extension.
  - The host label is the file name minus its extension (WS01.txt -> WS01,
    HOST01_sam.txt -> HOST01_sam), so name dumps after the host.
  - Top level only: subfolders are not searched. Hidden files (".name") are skipped.
  - Keep only SAM dumps in the folder. Any other file (notes, prior output) is
    still counted as a host; its non-hash lines are ignored, but any hash-format
    lines in it will be matched as if they came from a host of that name.
  - Don't write the export into the SAM folder, or a rerun will read the report
    and CSVs as SAM dumps (the script warns if you do).

Expects secretsdump.py-format lines:
    DOMAIN\\username:RID:LMHASH:NTHASH:::
    username:RID:LMHASH:NTHASH:::      (SAM - host taken from the file name)
"""

import csv
import os
import sys
import time
from collections import defaultdict
from datetime import datetime

EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ---------------------------------------------------------------- input helpers

def clean_path(p):
    """Strip whitespace/quotes, expand ~ and env vars."""
    p = p.strip().strip("'\"")
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p))) if p else ""


def enable_tab_completion():
    try:
        import glob
        import readline

        def complete(text, state):
            matches = glob.glob(os.path.expanduser(text) + "*")
            matches = [m + "/" if os.path.isdir(m) else m for m in matches]
            return matches[state] if state < len(matches) else None

        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        readline.set_completer(complete)
    except ImportError:
        pass


def ask_yes_no(prompt, default=False):
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        ans = input(f"{prompt} {suffix}: ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print(f"{RED}Enter y or n.{RESET}")


# ---------------------------------------------------------------- progress

def progress_bar(done, total, current="", width=40):
    pct = done / total if total else 1
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    label = (current[:45] + "…") if len(current) > 46 else current
    sys.stdout.write(f"\r{CYAN}[{bar}]{RESET} {pct:6.1%}  {label:<47}")
    sys.stdout.flush()


def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------- parsing

def parse_dump_line(line):
    """Returns (username, nt_hash) or None if the line can't be parsed."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":")
    if len(parts) < 4:
        return None
    nt_hash = parts[3].lower()
    if len(nt_hash) != 32:
        return None
    return parts[0], nt_hash


def load_ntds(ntds_path):
    """Returns dict: nt_hash -> list of domain usernames."""
    total_bytes = os.path.getsize(ntds_path)
    ntds_hashes = defaultdict(list)
    bytes_read = total_lines = parsed = 0

    print(f"\n{BOLD}[*] Reading NTDS dump ({fmt_size(total_bytes)}){RESET}")
    with open(ntds_path, "rb") as f:
        for raw in f:
            total_lines += 1
            bytes_read += len(raw)
            result = parse_dump_line(raw.decode("utf-8", errors="ignore"))
            if result:
                parsed += 1
                username, nt_hash = result
                ntds_hashes[nt_hash].append(username)
            if total_lines % 2000 == 0:
                progress_bar(bytes_read, total_bytes,
                             f"{fmt_size(bytes_read)} / {fmt_size(total_bytes)}")
    progress_bar(total_bytes, total_bytes, "done")
    print(f"\n[*] Parsed {parsed}/{total_lines} lines, {len(ntds_hashes)} unique hashes")
    return ntds_hashes


def load_sam_folder(sam_files):
    """
    Reads each SAM dump file (one host per file, top-level of the folder only).
    Returns dict: nt_hash -> list of (hostname, username).
    """
    sam_hashes = defaultdict(list)
    total_lines = parsed = 0

    print(f"\n{BOLD}[*] Reading {len(sam_files)} SAM dump file(s){RESET}")
    for i, filepath in enumerate(sam_files):
        # Host label = file name without extension (e.g. HOST01_sam.txt -> HOST01_sam)
        hostname = os.path.splitext(os.path.basename(filepath))[0]
        progress_bar(i, len(sam_files), hostname)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total_lines += 1
                result = parse_dump_line(line)
                if result:
                    parsed += 1
                    username, nt_hash = result
                    sam_hashes[nt_hash].append((hostname, username))
    progress_bar(len(sam_files), len(sam_files), "done")
    print(f"\n[*] Parsed {parsed}/{total_lines} lines, {len(sam_hashes)} unique hashes")
    return sam_hashes


# ---------------------------------------------------------------- comparison

def find_domain_local(ntds_hashes, sam_hashes, include_empty):
    print(f"\n{BOLD}[*] Comparing domain vs local hashes{RESET}")
    keys = list(ntds_hashes.keys())
    shared = set()
    step = max(1, len(keys) // 200)
    for i, h in enumerate(keys):
        if h in sam_hashes and (include_empty or h != EMPTY_NT_HASH):
            shared.add(h)
        if i % step == 0:
            progress_bar(i, len(keys), f"{i}/{len(keys)} hashes")
    progress_bar(len(keys), len(keys), "done")
    print()
    return sorted(shared, key=lambda h: len(sam_hashes[h]), reverse=True)


def find_lateral(sam_hashes, include_empty):
    print(f"\n{BOLD}[*] Checking local hashes reused across hosts{RESET}")
    items = list(sam_hashes.items())
    groups = {}
    step = max(1, len(items) // 200)
    for i, (h, hits) in enumerate(items):
        if (include_empty or h != EMPTY_NT_HASH) and len({host for host, _ in hits}) >= 2:
            groups[h] = hits
        if i % step == 0:
            progress_bar(i, len(items), f"{i}/{len(items)} hashes")
    progress_bar(len(items), len(items), "done")
    print()
    return sorted(groups.items(), key=lambda kv: len({h for h, _ in kv[1]}), reverse=True)


# ---------------------------------------------------------------- reporting

class Tee:
    """Writes to the console (with color) and the export file (without)."""

    def __init__(self, fh):
        self.fh = fh

    def __call__(self, text="", color=""):
        print(f"{color}{text}{RESET}" if color else text)
        self.fh.write(text + "\n")


def write_report(out, ntds_hashes, sam_hashes, shared, lateral):
    blank = lambda h: "  <-- BLANK PASSWORD" if h == EMPTY_NT_HASH else ""

    out()
    out("=== Domain <-> Local Password Reuse ===", BOLD)
    out(f"[*] {len(shared)} hash(es) shared between NTDS and local SAM dumps\n")
    for h in shared:
        hits = sam_hashes[h]
        out(f"NT Hash: {h}{blank(h)}", RED)
        out(f"  Domain account(s): {', '.join(ntds_hashes[h])}")
        out(f"  Found locally on {len(hits)} host(s):")
        for host, user in hits:
            out(f"    - {host}: {user}")
        out()
    if not shared:
        out("[*] No domain/local password reuse found.\n", GREEN)

    out("=== Local <-> Local Password Reuse (Lateral Movement Candidates) ===", BOLD)
    out(f"[*] {len(lateral)} hash(es) reused across multiple hosts locally\n")
    for h, hits in lateral:
        hosts = {host for host, _ in hits}
        out(f"NT Hash: {h}{blank(h)}", MAGENTA)
        out(f"  Shared across {len(hosts)} host(s):")
        for host, user in hits:
            out(f"    - {host}: {user}")
        out()
    if not lateral:
        out("[*] No local-to-local password reuse found across hosts.\n", GREEN)


def write_csvs(base, ntds_hashes, sam_hashes, shared, lateral):
    dvl = f"{base}_domain_vs_local.csv"
    with open(dvl, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["nt_hash", "is_blank_password", "domain_accounts", "host", "local_account"])
        for h in shared:
            domain_users = "; ".join(ntds_hashes[h])
            for host, user in sam_hashes[h]:
                w.writerow([h, h == EMPTY_NT_HASH, domain_users, host, user])

    lat = f"{base}_lateral_movement.csv"
    with open(lat, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["nt_hash", "is_blank_password", "host_count", "host", "local_account"])
        for h, hits in lateral:
            count = len({host for host, _ in hits})
            for host, user in hits:
                w.writerow([h, h == EMPTY_NT_HASH, count, host, user])
    return dvl, lat


# ---------------------------------------------------------------- main

def main():
    enable_tab_completion()
    print(f"{BOLD}NTDS vs SAM Password Reuse Checker{RESET}\n")

    # --- NTDS file (full path) ---
    ntds_file = clean_path(input("NTDS dump file (full path): "))
    while not os.path.isfile(ntds_file):
        ntds_file = clean_path(input(f"{RED}Not found.{RESET} NTDS dump file (full path): "))

    # --- SAM folder (full path) ---
    # Every non-hidden file at the top level = one host's SAM dump; subfolders ignored.
    while True:
        sam_dir = clean_path(input("SAM dump folder (full path): "))
        if not os.path.isdir(sam_dir):
            print(f"{RED}Not found.{RESET}")
            continue
        sam_files = [os.path.join(sam_dir, fn) for fn in sorted(os.listdir(sam_dir))
                     if not fn.startswith(".") and os.path.isfile(os.path.join(sam_dir, fn))]
        if sam_files:
            break
        print(f"{RED}No files in that folder.{RESET}")
    print(f"{CYAN}[*] {len(sam_files)} SAM file(s) found{RESET}")

    # --- export file (full path) ---
    default_out = os.path.join(os.path.dirname(ntds_file),
                               f"hash_reuse_{datetime.now():%Y-%m-%d_%H%M}.txt")
    export_file = clean_path(input(f"Export file (full path) [{default_out}]: ")) or default_out
    if os.path.isdir(export_file):
        export_file = os.path.join(export_file, os.path.basename(default_out))
    out_dir = os.path.dirname(export_file)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        print(f"{YELLOW}[*] Created {out_dir}{RESET}")
    if os.path.samefile(out_dir, sam_dir):
        print(f"{YELLOW}[!] Export is going into the SAM folder - a later run would read "
              f"these output files as SAM dumps.{RESET}")
    base = os.path.splitext(export_file)[0]

    include_empty = ask_yes_no("Include blank-password hash (31d6cfe0...)?", default=False)

    start = time.time()
    ntds_hashes = load_ntds(ntds_file)
    sam_hashes = load_sam_folder(sam_files)
    shared = find_domain_local(ntds_hashes, sam_hashes, include_empty)
    lateral = find_lateral(sam_hashes, include_empty)

    with open(export_file, "w", encoding="utf-8") as fh:
        fh.write(f"NTDS vs SAM Password Reuse - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        fh.write(f"NTDS file: {ntds_file}\n")
        fh.write(f"SAM folder: {sam_dir} ({len(sam_files)} files)\n")
        fh.write(f"Blank hash included: {include_empty}\n")
        fh.write("=" * 80 + "\n")
        write_report(Tee(fh), ntds_hashes, sam_hashes, shared, lateral)

    dvl, lat = write_csvs(base, ntds_hashes, sam_hashes, shared, lateral)

    print("-" * 80)
    print(f"[*] {len(shared)} domain/local reused hash(es), "
          f"{len(lateral)} lateral movement hash(es) ({time.time() - start:.1f}s)")
    print(f"\n[+] Report: {export_file}")
    print(f"[+] CSV:    {dvl}")
    print(f"[+] CSV:    {lat}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted.{RESET}")
        sys.exit(130)
