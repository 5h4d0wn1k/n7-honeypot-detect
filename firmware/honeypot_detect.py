#!/usr/bin/env python3
"""
N7 - Honeypot Detector
Detect honeypots via network fingerprinting, banner analysis, and behavior probing.
"""

import socket
import time
import random
import os
import sys
import argparse
import struct
import threading
from collections import defaultdict


class HoneypotDetector:
    """Detect honeypots through fingerprinting and behavior analysis."""

    KNOWN_HONEYPOTS = {
        'cowrie': ['Cowrie', 'cowrie', 'SSH-2.0-OpenSSH_6.6.1p1'],
        'dionaea': ['dionaea', 'Dionaea'],
        'kippo': ['Kippo', 'kippo', 'SSH-2.0-OpenSSH_5.9p1'],
        'conpot': ['Conpot', 'conpot', 'ICS/SCADA'],
        'amun': ['Amun', 'amun'],
        'honeyd': ['Honeyd', 'honeyd'],
        'glpot': ['Glastopf', 'glastopf'],
        't-pot': ['T-Pot', 'tpot'],
    }

    HONEYPOT_INDICATORS = [
        'generic_banner', 'default_credentials', 'no_firewall_rules',
        'all_ports_open', 'fake_services', 'emulated_os',
        'long_banner_delay', 'inconsistent_ttl', 'default_configs',
    ]

    def __init__(self, timeout=2):
        self.timeout = timeout
        self.results = {}
        self.score = 0

    def banner_grab(self, ip, port, probe_type='generic'):
        """Grab service banner from target."""
        banner = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            if probe_type == 'http':
                sock.send(b'GET / HTTP/1.0\r\nHost: ' +
                          ip.encode() + b'\r\n\r\n')
            elif probe_type == 'smtp':
                time.sleep(0.5)
            elif probe_type == 'ftp':
                pass
            else:
                sock.send(b'hello\r\n')

            banner = sock.recv(4096).decode('utf-8', errors='replace').strip()
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return banner

    def analyze_banner(self, banner):
        """Analyze banner for honeypot indicators."""
        if not banner:
            return {'suspicious': False, 'reason': 'no_banner'}

        indicators = []
        hp_match = None

        for hp_name, signatures in self.KNOWN_HONEYPOTS.items():
            for sig in signatures:
                if sig.lower() in banner.lower():
                    hp_match = hp_name
                    indicators.append(f'known_honeypot_sig:{hp_name}')
                    break

        generic_signs = [
            ('default', 'default_openbsd'), ('default', 'generic'),
            ('openssh_5.9', 'openssh_5.9'), ('openssh_6.6', 'openssh_6.6.1'),
            ('ftp_generic', '220 ProFTPD'), ('ftp_generic', '220 Microsoft FTP'),
        ]
        for tag, pattern in generic_signs:
            if pattern.lower() in banner.lower():
                indicators.append(f'generic_pattern:{tag}')

        if len(banner) < 10:
            indicators.append('short_banner')

        return {
            'suspicious': len(indicators) > 0,
            'honeypot_match': hp_match,
            'indicators': indicators,
            'banner': banner[:200],
        }

    def port_scan_quick(self, ip, ports=None):
        """Quick port scan to identify open services."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
                     445, 993, 995, 1433, 3306, 3389, 5432, 8080]

        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except OSError:
                pass

        return open_ports

    def ttl_analysis(self, ip):
        """Analyze TTL to detect OS emulation inconsistencies."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)

            icmp_data = struct.pack('!BBHHH', 8, 0, 0,
                                    random.randint(1, 65535), 1)
            c = self._checksum(icmp_data)
            icmp_data = struct.pack('!BBHHH', 8, 0, c,
                                    random.randint(1, 65535), 1)
            sock.sendto(icmp_data, (ip, 0))

            data, _ = sock.recvfrom(1024)
            ip_header = data[:20]
            ttl = ip_header[8]

            sock.close()

            os_guess = None
            if ttl <= 64:
                os_guess = 'Linux/FreeBSD'
            elif ttl <= 128:
                os_guess = 'Windows'
            elif ttl <= 255:
                os_guess = 'Network Device'

            return {'ttl': ttl, 'os_guess': os_guess, 'collected': True}
        except (PermissionError, OSError):
            return {'ttl': None, 'os_guess': None, 'collected': False,
                    'note': 'requires root for raw sockets'}

    @staticmethod
    def _checksum(data):
        if len(data) % 2:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def behavior_probe(self, ip, port):
        """Probe service behavior for honeypot indicators."""
        findings = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            sock.send(b'HEAD / HTTP/1.1\r\nHost: ' +
                      ip.encode() + b'\r\n\r\n')
            time.sleep(0.3)
            try:
                data = sock.recv(4096)
                if data:
                    findings.append('http_responsive')
            except socket.timeout:
                findings.append('slow_response')

            sock.close()
        except (ConnectionRefusedError, OSError):
            findings.append('connection_issue')

        try:
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(1)
            sock2.connect((ip, port))
            sock2.send(b'A' * 2048)
            time.sleep(0.2)
            try:
                response = sock2.recv(1024)
                if response and b'error' in response.lower():
                    findings.append('verbose_errors')
            except socket.timeout:
                findings.append('no_timeout_on_flood')
            sock2.close()
        except OSError:
            findings.append('flood_connection_fail')

        return findings

    def full_analysis(self, ip, ports=None):
        """Run complete honeypot analysis on target."""
        print(f"\n{'='*50}")
        print(f"  Honeypot Analysis: {ip}")
        print(f"{'='*50}")

        analysis = {
            'ip': ip, 'score': 0, 'indicators': [],
            'open_ports': [], 'banners': {}, 'ttl': None,
            'behaviors': {}, 'verdict': 'UNKNOWN'
        }

        print(f"\n[1/4] Port scanning...")
        open_ports = self.port_scan_quick(ip, ports)
        analysis['open_ports'] = open_ports
        print(f"  Open ports: {open_ports}")

        if not open_ports:
            analysis['verdict'] = 'CLEAN'
            print(f"  No open ports found")
            return analysis

        if len(open_ports) > 15:
            analysis['score'] += 2
            analysis['indicators'].append('many_open_ports')
            print(f"  [!] Many open ports ({len(open_ports)}) - suspicious")

        print(f"\n[2/4] Banner grabbing...")
        service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            80: 'http', 443: 'http', 8080: 'http',
        }
        for port in open_ports[:8]:
            probe = service_map.get(port, 'generic')
            banner = self.banner_grab(ip, port, probe)
            result = self.analyze_banner(banner)
            analysis['banners'][port] = result
            if result['suspicious']:
                analysis['score'] += 3
                analysis['indicators'].extend(result['indicators'])
                hp = result.get('honeypot_match', 'unknown')
                print(f"  [!] Port {port}: HONEYPOT SIGNATURE ({hp})")
                print(f"      Banner: {result['banner'][:80]}")
            else:
                print(f"  Port {port}: No suspicious patterns")

        print(f"\n[3/4] TTL analysis...")
        ttl_result = self.ttl_analysis(ip)
        analysis['ttl'] = ttl_result
        if ttl_result['collected']:
            print(f"  TTL: {ttl_result['ttl']} (OS: {ttl_result['os_guess']})")
        else:
            print(f"  Skipped ({ttl_result.get('note', 'error')})")

        print(f"\n[4/4] Behavior probing...")
        for port in open_ports[:5]:
            behaviors = self.behavior_probe(ip, port)
            analysis['behaviors'][port] = behaviors
            for b in behaviors:
                if b not in ('http_responsive',):
                    analysis['score'] += 1
                    analysis['indicators'].append(f'behavior:{port}:{b}')
            print(f"  Port {port}: {behaviors}")

        score = analysis['score']
        if score >= 6:
            analysis['verdict'] = 'LIKELY HONEYPOT'
        elif score >= 3:
            analysis['verdict'] = 'SUSPICIOUS'
        else:
            analysis['verdict'] = 'LIKELY LEGITIMATE'

        print(f"\n{'='*50}")
        print(f"  VERDICT: {analysis['verdict']} (score: {score})")
        print(f"  Indicators: {analysis['indicators']}")
        print(f"{'='*50}")

        self.results[ip] = analysis
        return analysis

    def scan_range(self, ip_prefix, start=1, end=254, ports=None):
        """Scan a range of IPs for honeypots."""
        honeypots_found = []
        print(f"\n[*] Scanning range {ip_prefix}.{start}-{end}...")

        for i in range(start, end + 1):
            ip = f"{ip_prefix}.{i}"
            result = self.full_analysis(ip, ports)
            if result['verdict'] in ('LIKELY HONEYPOT', 'SUSPICIOUS'):
                honeypots_found.append(result)
            print()

        print(f"\n{'='*50}")
        print(f"  Scan complete: {end - start + 1} hosts scanned")
        print(f"  Honeypots/Suspicious: {len(honeypots_found)}")
        for hp in honeypots_found:
            print(f"    {hp['ip']}: {hp['verdict']} "
                  f"(score {hp['score']})")
        print(f"{'='*50}")
        return honeypots_found


class FakeHoneypotServer:
    """Minimal TCP server that answers with a known honeypot banner.

    Used only inside ``--harness`` (offline, localhost).
    """

    def __init__(self, banner=b'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.10',
                 host='127.0.0.1'):
        self.banner = banner
        self.host = host
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, 0))          # OS picks a free port
        self.port = self.server.getsockname()[1]
        self.server.listen(5)
        self.server.settimeout(5)
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._accept_loop,
                                        daemon=True)
        self._thread.start()

    def _accept_loop(self):
        while True:
            try:
                client, _ = self.server.accept()
                client.sendall(self.banner + b'\r\n')
                client.close()
            except socket.timeout:
                break
            except OSError:
                break

    def stop(self):
        try:
            self.server.close()
        except OSError:
            pass


def run_harness():
    """Spin up fake honeypot servers on localhost, scan them, verify detection.

    Everything runs unprivileged via plain TCP connect scans. No raw sockets,
    no root, no network access.
    """
    print('=== N7 Honeypot Detect: offline harness ===')

    # 1. Start two fake honeypots on random free ports
    hp1 = FakeHoneypotServer(banner=b'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.10')
    hp2 = FakeHoneypotServer(banner=b'SSH-2.0-OpenSSH_5.9p1')
    hp1.start()
    hp2.start()
    time.sleep(0.15)   # let threads enter accept()

    ports = [hp1.port, hp2.port]
    print(f'  Fake honeypots listening on ports {ports}')

    # Wait until both sockets actually accept (robust under CPU load).
    deadline = time.time() + 10
    while time.time() < deadline:
        reachable = []
        for port in ports:
            try:
                s = socket.create_connection(('127.0.0.1', port), timeout=1)
                s.close()
                reachable.append(port)
            except OSError:
                continue
        if set(reachable) == set(ports):
            break
        time.sleep(0.2)
    else:
        raise RuntimeError('fake honeypots did not become reachable')

    # 2. Scan those two ports — should flag both.
    detector = HoneypotDetector(timeout=1)
    expected = sorted(ports)
    r = detector.full_analysis('127.0.0.1', ports)
    retries = 0
    while sorted(r['open_ports']) != expected and retries < 5:
        time.sleep(0.3)
        r = detector.full_analysis('127.0.0.1', ports)
        retries += 1
    hp1.stop()
    hp2.stop()

    ok = True

    def verify(label, cond, detail=''):
        nonlocal ok
        print(f'  [{"PASS" if cond else "FAIL"}] {label} {detail}')
        ok = ok and cond

    verify('port scan finds both ports',
           sorted(r['open_ports']) == sorted(ports),
           f'{r["open_ports"]}')
    verify('verdict is HONEYPOT or SUSPICIOUS',
           r['verdict'] in ('LIKELY HONEYPOT', 'SUSPICIOUS'),
           f'{r["verdict"]} (score {r["score"]})')
    verify('at least one known honeypot signature detected',
           any('known_honeypot_sig' in ind
               for ind in r['indicators']),
           f'{r["indicators"]}')

    # 3. Scan a closed port — should return CLEAN
    unused = hp1.port  # already closed after stop()
    r2 = detector.full_analysis('127.0.0.1', [unused])
    verify('closed port yields CLEAN or LIKELY LEGITIMATE',
           r2['verdict'] in ('CLEAN', 'LIKELY LEGITIMATE'),
           f'{r2["verdict"]}')

    # 4. Analyze banner strings directly
    det = HoneypotDetector(timeout=1)
    a1 = det.analyze_banner('SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.10')
    verify('banner analysis detects cowrie/OpenSSH_6.6',
           a1['suspicious'] is True)
    a2 = det.analyze_banner('Apache/2.4.57')
    verify('banner analysis clears non-honeypot',
           a2['suspicious'] is False)

    print('\n[RESULT] ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description='N7 — Honeypot Detector (offline harness + gated live)')
    parser.add_argument('target', nargs='?', help='Target IP')
    parser.add_argument('--ports', help='Comma-separated ports')
    parser.add_argument('--timeout', type=float, default=2,
                        help='Socket timeout')
    parser.add_argument('--harness', action='store_true',
                        help='Run offline harness with fake local honeypots '
                             '(default when no args)')
    parser.add_argument('--live', action='store_true',
                        help='Allow live scans that need root (TTL/ICMP)')
    parser.add_argument('--scan-range', help='IP prefix to scan (e.g. 192.168.1)')
    parser.add_argument('--range-start', type=int, default=1)
    parser.add_argument('--range-end', type=int, default=10)

    args = parser.parse_args()

    if args.harness or (not args.target and not args.scan_range):
        sys.exit(run_harness())

    if not os.geteuid() == 0 and (args.scan_range or args.live):
        print('[-] Live mode / scan-range requires root; '
              'rerun with sudo or use --harness for offline testing.')
        sys.exit(1)

    detector = HoneypotDetector(args.timeout)

    print("╔═══════════════════════════════════════╗")
    print("║     N7 — Honeypot Detector            ║")
    print("╚═══════════════════════════════════════╝")

    if args.scan_range:
        detector.scan_range(args.scan_range, args.range_start, args.range_end)
    elif args.target:
        ports = None
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        detector.full_analysis(args.target, ports)


if __name__ == '__main__':
    sys.exit(main())
