# Junos Prefix-List Summarizer

A Python utility that scans Junos configuration or log files, finds `policy-options prefix-list` entries, and **safely summarizes** IP prefixes **only within the same prefix-list name** — without adding new IPs unnecessarily.

Instead of manually cleaning up long, messy prefix-lists, this tool outputs precise `delete` and `set` commands for only the prefixes that can be losslessly compressed.

---

## ✨ Features
- Works with any `.conf`, `.txt`, or log file containing Junos configs.
- Only summarizes prefixes **within the same prefix-list name**.
- Ensures **no extra IP space** is introduced during summarization.
- Outputs a new file with the optimized configuration changes.
- Prints a summary of:
  - How many prefixes were summarized per prefix-list
  - Total changes made
  - Runtime

---

## 🚀 Usage
```bash
python3 junos_prefix_summarize.py input.conf
```

---

⚠ Disclaimer
This tool is provided "AS IS", without warranty of any kind.
Author: Moshiko Nayman
I am not responsible for any damage, misconfiguration, or downtime caused by using this script.
Always review generated changes before applying them to production systems.
