import os, sys, subprocess, socket, time, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))
from honeypot_detect import HoneypotDetector, FakeHoneypotServer


class TestBannerAnalysis(unittest.TestCase):
    d = HoneypotDetector(timeout=1)

    def test_cowrie_sig_detected(self):
        r = self.d.analyze_banner(
            'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.10')
        self.assertTrue(r['suspicious'])
        self.assertEqual(r['honeypot_match'], 'cowrie')

    def test_kippo_sig_detected(self):
        r = self.d.analyze_banner('SSH-2.0-OpenSSH_5.9p1')
        self.assertTrue(r['suspicious'])
        self.assertEqual(r['honeypot_match'], 'kippo')

    def test_dionaea_sig_detected(self):
        r = self.d.analyze_banner('dionaea sniffer active')
        self.assertTrue(r['suspicious'])

    def test_legitimate_banner_clears(self):
        r = self.d.analyze_banner('Apache/2.4.57 (Ubuntu)')
        self.assertFalse(r['suspicious'])

    def test_empty_banner_clears(self):
        r = self.d.analyze_banner('')
        self.assertFalse(r['suspicious'])

    def test_short_banner_flagged(self):
        r = self.d.analyze_banner('SSH-2.0')
        self.assertTrue(r['suspicious'])
        self.assertIn('short_banner', r['indicators'])


class TestFakeHoneypotServer(unittest.TestCase):
    def test_starts_and_responds(self):
        srv = FakeHoneypotServer(banner=b'SSH-2.0-OpenSSH_5.9p1')
        srv.start()
        time.sleep(0.1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('127.0.0.1', srv.port))
        data = sock.recv(1024)
        sock.close()
        srv.stop()
        self.assertIn(b'OpenSSH', data)


class TestHarness(unittest.TestCase):
    def test_harness_exit_code_zero(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'honeypot_detect.py'), '--harness'],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(r.returncode, 0)
        self.assertIn('[RESULT] PASS', r.stdout)

    def test_harness_output_structure(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'honeypot_detect.py'), '--harness'],
            capture_output=True, text=True, timeout=15)
        self.assertIn('Fake honeypots listening', r.stdout)
        self.assertIn('port scan finds both', r.stdout)
        self.assertIn('banner analysis detects', r.stdout)


class TestGatekeeping(unittest.TestCase):
    def test_scan_range_no_root_refuses(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'honeypot_detect.py'),
             '--scan-range', '127.0.0'],
            capture_output=True, text=True, timeout=5)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('--harness', r.stdout.lower() + r.stderr.lower())


class TestFullAnalysisLocalhost(unittest.TestCase):
    def test_clean_port_yields_legitimate(self):
        srv = FakeHoneypotServer(banner=b'SSH-2.0-OpenSSH_5.9p1')
        srv.start()
        time.sleep(0.1)
        det = HoneypotDetector(timeout=1)
        # scan only the honeypot port
        r = det.full_analysis('127.0.0.1', [srv.port])
        srv.stop()
        self.assertIn(r['verdict'], ('LIKELY HONEYPOT', 'SUSPICIOUS'))
        self.assertGreater(r['score'], 0)


if __name__ == '__main__':
    unittest.main()
