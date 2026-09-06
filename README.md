# N7 — Honeypot Detector

Detect honeypots through network fingerprinting, banner analysis, and behavior probing.

## Overview

This project implements a honeypot detection system that:
- Performs quick port scanning to identify open services
- Grabs and analyzes service banners for known honeypot signatures
- Tests TTL consistency for OS emulation detection
- Probes service behavior for abnormal responses
- Produces a confidence score and verdict

## Features

- **Banner analysis**: Match against known honeypot signatures (Cowrie, Dionaea, Kippo, Conpot, etc.)
- **TTL analysis**: Detect OS emulation inconsistencies
- **Behavior probing**: Test response patterns for emulated services
- **Range scanning**: Scan IP ranges for honeypots
- **Scoring system**: Aggregate indicators into a confidence score

## Installation

No external dependencies — uses only the Python standard library.

## Usage

```bash
# Offline harness (default): spin up fake honeypots on localhost, verify detection
python3 honeypot_detect.py --harness

# Analyze a single target on a lab host (placeholders: RFC 5737 TEST-NET)
python3 honeypot_detect.py 192.0.2.100

# Analyze with custom ports
python3 honeypot_detect.py 192.0.2.100 --ports 22,80,443

# Scan an IP range on a lab network (needs --live for TTL analysis/root)
python3 honeypot_detect.py --scan-range 192.0.2 --range-start 1 --range-end 20
```

The default (no args / `--harness`) runs a fully unprivileged offline harness:
it starts real honeypot-style TCP servers on localhost, scans them, and asserts
the banners and verdicts are flagged. TTL analysis (raw ICMP sockets) and live
scan-range probing are gated: they require `--live` (root).

## Live Lab Test Plan

> Authorized own-lab use only. Use documented placeholders (192.0.2.x, 198.51.100.x).

1. **Prepare a lab host** (VM/container) running a low-interaction honeypot
   (e.g. `cowrie` or `kippo`) bound to a `192.0.2.x` address.
2. Stand up a **clean** service host running a real `sshd`/nginx on the same
   network for comparison.
3. Run `python3 honeypot_detect.py 192.0.2.100` against the honeypot; confirm
   the known-signature banner is flagged and the verdict is
   `LIKELY HONEYPOT` or `SUSPICIOUS`.
4. Run the same command against the clean host; confirm it is rated
   `LIKELY LEGITIMATE`.
5. With root, run `--live` to add TTL/ICMP analysis and confirm no false
   positives on the clean host.

## Metrics

Deterministic, unprivileged, offline/localhost:

- `python3 -m unittest discover -s tests` — 11 unit tests (exit 0)
- Offline harness spins 2 fake honeypot servers, scans them, asserts:
  - both honeypot ports found
  - verdict is `LIKELY HONEYPOT` / `SUSPICIOUS`
  - at least one known honeypot signature detected
- Banner analysis: known SIGs (Cowrie/Kippo/Dionaea) flagged; legitimate
  banner (Apache) cleared
- Closed-port scan yields `CLEAN` — no false positive
- Harness exit code: `0` on success, `1` on failure

## License

MIT

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
