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
# Analyze single target
python3 honeypot_detect.py 192.168.1.100

# Analyze with custom ports
python3 honeypot_detect.py 192.168.1.100 --ports 22,80,443

# Scan IP range
python3 honeypot_detect.py --scan-range 192.168.1 --range-start 1 --range-end 20
```

## Example Output

```
╔═══════════════════════════════════════╗
║     N7 — Honeypot Detector            ║
╚═══════════════════════════════════════╝

==================================================
  Honeypot Analysis: 192.168.1.100
==================================================

[1/4] Port scanning...
  Open ports: [22, 80, 8080]

[2/4] Banner grabbing...
  [!] Port 22: HONEYPOT SIGNATURE (cowrie)
      Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2

[3/4] TTL analysis...
  TTL: 64 (OS: Linux/FreeBSD)

[4/4] Behavior probing...
  Port 22: ['slow_response']

==================================================
  VERDICT: LIKELY HONEYPOT (score: 6)
==================================================
```

## Legal Disclaimer

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
