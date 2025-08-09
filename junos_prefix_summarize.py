#!/usr/bin/env python3
"""
===============================================================================
Junos Prefix-List Safe Summarizer
Author: Moshiko Nayman
Version: 1.0
===============================================================================
Description:
    This tool parses Junos configuration-style files and safely summarizes
    IPv4 prefixes in 'policy-options prefix-list' statements. Summarization is
    performed *only within the same prefix-list name* and only when it can be
    done without introducing any additional IP addresses outside the original
    ranges.

    Input files can be .conf, .txt, .log, or any text containing Junos
    'set policy-options prefix-list' lines. Any unrelated configuration is
    ignored.

    The script outputs a separate file containing the required 'delete' and
    'set' commands to apply the summarization changes in Junos. The original
    file is never modified.

Key Features:
    - Safe, exact summarization (no unwanted IP expansion)
    - Works on a per-prefix-list basis
    - Generates only necessary delete/set commands
    - Outputs a new file; original remains untouched
    - Shows per-list and total summarization statistics
    - Works with file or stdin input

Usage:
    python3 junos_prefix_summarize.py <input-file>
    cat <input-file> | python3 junos_prefix_summarize.py

Example:
    Input:
        set policy-options prefix-list PL_NEW 10.0.0.0/24
        set policy-options prefix-list PL_NEW 10.0.1.0/24
        set policy-options prefix-list PL_NEW 10.0.2.0/24
        set policy-options prefix-list PL_NEW 10.0.3.0/24
    Output:
        delete policy-options prefix-list PL_NEW 10.0.0.0/24
        delete policy-options prefix-list PL_NEW 10.0.1.0/24
        delete policy-options prefix-list PL_NEW 10.0.2.0/24
        delete policy-options prefix-list PL_NEW 10.0.3.0/24
        set policy-options prefix-list PL_NEW 10.0.0.0/22

Disclaimer:
    This tool is provided "AS IS", without warranty of any kind.
    The author (Moshiko Nayman) assumes no responsibility or liability
    for any errors, issues, or damages arising from the use of this tool.
    Always review generated output before applying to production systems.

===============================================================================
"""
import sys
import re
import ipaddress
import time
import os
from collections import defaultdict

PREFIX_RE = re.compile(
    r"set\s+policy-options\s+prefix-list\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})",
    re.IGNORECASE
)

def parse_prefix_lists(lines):
    """Return dict: name -> set(ipaddress.IPv4Network)"""
    pl = defaultdict(set)
    for ln in lines:
        for match in PREFIX_RE.findall(ln):
            name, prefix_str = match
            try:
                net = ipaddress.IPv4Network(prefix_str, strict=False)
                pl[name].add(net)
            except Exception:
                # skip invalid
                pass
    return pl

def exact_pairwise_merge(networks_set):
    """
    Perform repeated pairwise merges:
    - Only merge two networks if they have the same prefixlen,
      are adjacent, and their supernet is exactly the union (i.e. both subnets present).
    - Repeat until no more merges possible.
    Returns a set of resulting networks.
    """
    nets = set(networks_set)  # copy
    changed = True
    while changed:
        changed = False
        # Sort by network address (ascending) then prefixlen (descending optional)
        sorted_nets = sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen))
        i = 0
        while i < len(sorted_nets) - 1:
            a = sorted_nets[i]
            b = sorted_nets[i + 1]
            # candidate merge: same prefixlen and adjacent
            if a.prefixlen == b.prefixlen and int(a.broadcast_address) + 1 == int(b.network_address):
                # candidate supernet
                try:
                    cand = a.supernet(prefixlen_diff=1)
                except Exception:
                    cand = None
                if cand is not None:
                    # cand.subnets(prefixlen_diff=1) yields two subnets; ensure a and b are them
                    subs = list(cand.subnets(prefixlen_diff=1))
                    if a == subs[0] and b == subs[1]:
                        # Safe to merge a+b -> cand
                        nets.remove(a)
                        nets.remove(b)
                        nets.add(cand)
                        changed = True
                        # break to restart since nets changed
                        break
            i += 1
        # loop repeats until no pairwise merges
    return nets

def generate_changes_for_pl(original_nets):
    """
    Given set(original_nets), compute final_nets by exact_pairwise_merge,
    then determine which original prefixes to delete and which summarized prefixes to set.
    Return (to_delete_list, to_set_list, original_count)
    """
    original = set(original_nets)
    final = exact_pairwise_merge(original)

    # to_delete: original prefixes that are no longer present as-is and are covered by some final prefix
    to_delete = []
    for o in sorted(original, key=lambda n: (int(n.network_address), n.prefixlen)):
        if o in final:
            continue
        # if any final covers o
        if any(o.subnet_of(f) for f in final):
            to_delete.append(o)

    # to_set: final prefixes that are new (not exactly present in original) AND actually replace something
    to_set = []
    for f in sorted(final, key=lambda n: (int(n.network_address), n.prefixlen)):
        if f in original:
            continue
        # only add if f covers at least one deleted original (i.e., it's replacing something)
        if any(deleted.subnet_of(f) for deleted in to_delete):
            to_set.append(f)

    return to_delete, to_set, len(original)

def format_net(n):
    return n.with_prefixlen

def main():
    t0 = time.time()

    # Read input
    if len(sys.argv) > 1:
        infile = sys.argv[1]
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

    prefix_lists = parse_prefix_lists(lines)

    # Prepare output lines and summary
    output_lines = []
    summary = {}  # name -> (orig_count, deleted_count, added_count)

    for name in sorted(prefix_lists.keys()):
        original_nets = prefix_lists[name]
        to_delete, to_set, orig_count = generate_changes_for_pl(original_nets)
        if not to_delete and not to_set:
            continue  # nothing changed for this prefix-list

        # Add delete lines (sorted)
        for d in sorted(to_delete, key=lambda n: (int(n.network_address), n.prefixlen)):
            output_lines.append(f"delete policy-options prefix-list {name} {format_net(d)}")

        # Add set lines for new summarized prefixes (sorted)
        for s in sorted(to_set, key=lambda n: (int(n.network_address), n.prefixlen)):
            output_lines.append(f"set policy-options prefix-list {name} {format_net(s)}")

        summary[name] = (orig_count, len(to_delete), len(to_set))

    # Write output file
    with open(out_filename, 'w') as outf:
        for ln in output_lines:
            outf.write(ln + "\n")

    # Print terminal summary
    t1 = time.time()
    total_deleted = sum(v[1] for v in summary.values())
    total_added = sum(v[2] for v in summary.values())

    print(f"Output written to: {out_filename}")
    if not summary:
        print("No safe summarizations found (no changes).")
    else:
        print("\nPer-prefix-list summary (original_count / deleted / added):")
        for name, (orig, deleted, added) in sorted(summary.items()):
            print(f"  {name}: {orig} → deleted {deleted}, added {added}")
        print(f"\nTotal deleted: {total_deleted}, total added: {total_added}, total commands: {total_deleted + total_added}")

    print(f"Execution time: {t1 - t0:.3f} seconds")

if __name__ == '__main__':
    main()
