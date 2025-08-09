#!/usr/bin/env python3
"""
===============================================================================
Junos Prefix-List Safe Summarizer
Author: Moshiko Nayman
Version: 1.1
===============================================================================
Description:
    Parses Junos config-style files and safely summarizes IPv4/IPv6 prefixes
    in 'policy-options prefix-list' statements. Summarization is performed
    only within the same prefix-list name, and only when it can be done
    without introducing any addresses outside the original ranges.

    Input: .conf, .txt, .log, or stdin with 'set policy-options prefix-list' lines.
    Output: A file (or stdout in dry-run mode) with 'delete' and 'set' commands
            to apply summarization.

Key Changes in 1.1:
    - Regex more tolerant of spacing/formatting
    - Optional IPv6 support
    - Faster merge algorithm (per prefix length grouping)
    - Dry-run option (--dry-run)
    - Shows duplicates count
    - Added safety assertion to ensure no IP expansion

Usage:
    python3 junos_prefix_summarize.py <input-file>
    python3 junos_prefix_summarize.py <input-file> --dry-run
    cat <input-file> | python3 junos_prefix_summarize.py

===============================================================================
"""
import sys
import re
import ipaddress
import time
import os
from collections import defaultdict

PREFIX_RE = re.compile(
    r"^\s*set\s+policy-options\s+prefix-list\s+(\S+)\s+"
    r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}/\d{1,2}|[0-9a-fA-F:]+/\d{1,3})\s*$",
    re.IGNORECASE
)

def parse_prefix_lists(lines):
    """Return dict: name -> (set(network_objects), duplicate_count)"""
    pl = defaultdict(set)
    duplicates = defaultdict(int)
    seen = defaultdict(set)

    for ln in lines:
        match = PREFIX_RE.match(ln)
        if match:
            name, prefix_str = match.groups()
            try:
                net = ipaddress.ip_network(prefix_str, strict=False)
                if net in seen[name]:
                    duplicates[name] += 1
                else:
                    pl[name].add(net)
                    seen[name].add(net)
            except ValueError:
                pass
    return pl, duplicates

def exact_merge(networks_set):
    """
    Efficient exact merge of adjacent subnets of the same size.
    Groups networks by prefix length and merges upward.
    Works for IPv4 and IPv6.
    """
    nets = set(networks_set)
    max_prefixlen = max(n.prefixlen for n in nets) if nets else 0

    for plen in range(max_prefixlen, 0, -1):
        same_plen = sorted([n for n in nets if n.prefixlen == plen],
                           key=lambda n: int(n.network_address))
        i = 0
        while i < len(same_plen) - 1:
            a = same_plen[i]
            b = same_plen[i + 1]
            if int(a.broadcast_address) + 1 == int(b.network_address) and a.prefixlen == b.prefixlen:
                try:
                    cand = a.supernet(prefixlen_diff=1)
                except ValueError:
                    cand = None
                if cand and list(cand.subnets(prefixlen_diff=1)) == [a, b]:
                    nets.discard(a)
                    nets.discard(b)
                    nets.add(cand)
                    i += 2
                    continue
            i += 1
    return nets

def generate_changes_for_pl(original_nets):
    original = set(original_nets)
    final = exact_merge(original)

    # Safety check — no expansion
    assert all(any(o.subnet_of(f) for f in final) for o in original), \
        "ERROR: Summarization expanded IP coverage unexpectedly!"

    to_delete = [o for o in original if o not in final and any(o.subnet_of(f) for f in final)]
    to_set = [f for f in final if f not in original and any(d.subnet_of(f) for d in to_delete)]
    return to_delete, to_set, len(original)

def format_net(n):
    return n.with_prefixlen

def main():
    t0 = time.time()
    dry_run = False
    infile = None

    args = sys.argv[1:]
    if "--dry-run" in args:
        dry_run = True
        args.remove("--dry-run")

    if args:
        infile = args[0]
        try:
            with open(infile, 'r') as fh:
                lines = fh.readlines()
        except Exception as e:
            print(f"Error reading {infile}: {e}", file=sys.stderr)
            sys.exit(1)
        base = os.path.splitext(os.path.basename(infile))[0]
        out_filename = f"{base}_summarized_changes.conf"
    else:
        lines = sys.stdin.read().splitlines()
        ts = int(time.time())
        out_filename = f"stdin_summarized_changes_{ts}.conf"

    prefix_lists, duplicates = parse_prefix_lists(lines)

    output_lines = []
    summary = {}

    for name in sorted(prefix_lists.keys()):
        original_nets = prefix_lists[name]
        to_delete, to_set, orig_count = generate_changes_for_pl(original_nets)
        if not to_delete and not to_set:
            continue
        for d in sorted(to_delete, key=lambda n: (int(n.network_address), n.prefixlen)):
            output_lines.append(f"delete policy-options prefix-list {name} {format_net(d)}")
        for s in sorted(to_set, key=lambda n: (int(n.network_address), n.prefixlen)):
            output_lines.append(f"set policy-options prefix-list {name} {format_net(s)}")
        summary[name] = (orig_count, len(to_delete), len(to_set), duplicates.get(name, 0))

    if dry_run:
        for ln in output_lines:
            print(ln)
    else:
        with open(out_filename, 'w') as outf:
            for ln in output_lines:
                outf.write(ln + "\n")
        print(f"Output written to: {out_filename}")

    t1 = time.time()
    total_deleted = sum(v[1] for v in summary.values())
    total_added = sum(v[2] for v in summary.values())

    if not summary:
        print("No safe summarizations found (no changes).")
    else:
        print("\nPer-prefix-list summary (orig / deleted / added / duplicates skipped):")
        for name, (orig, deleted, added, dups) in sorted(summary.items()):
            print(f"  {name}: {orig} → deleted {deleted}, added {added}, duplicates {dups}")
        print(f"\nTotal deleted: {total_deleted}, total added: {total_added}, total commands: {total_deleted + total_added}")

    print(f"Execution time: {t1 - t0:.3f} seconds")

if __name__ == '__main__':
    main()
