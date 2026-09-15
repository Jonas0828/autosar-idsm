#!/usr/bin/env python3
"""attack_tests.py — 触发 eth_probe 各检测器的 scapy 脚本.
在 .202 上执行:  sudo python3 attack_tests.py <目标IP> <测试名>
测试名: doip | someip | tls | uds | all
"""
import sys
from scapy.all import IP, TCP, UDP, Raw, send

def syn_then_payload(target, dport, payload, sport=49152):
    """TCP SYN + 带 payload 的 PSH-ACK (模拟已建立连接)."""
    syn = IP(dst=target)/TCP(sport=sport, dport=dport, flags="S", seq=1000)
    psh = IP(dst=target)/TCP(sport=sport, dport=dport, flags="PA", seq=1001)/Raw(load=payload)
    send(syn, verbose=0)
    send(psh, verbose=0)

def test_doip(target):
    """DoIP routing activation (detector 5, aux=0x5)."""
    doip = bytes([0x02, 0xFD]) + (0x0005).to_bytes(2, 'big') + (7).to_bytes(4, 'big') + bytes([0x0E, 0, 0, 0, 0, 0, 0])
    syn_then_payload(target, 13400, doip)
    print(f"[*] DoIP routing activation sent to {target}:13400")

def test_uds(target):
    """UDS SecurityAccess (rule sid=1000001, detector 4)."""
    doip_hdr = bytes([0x02, 0xFD]) + (0x8001).to_bytes(2, 'big') + (7).to_bytes(4, 'big')
    uds = doip_hdr + bytes([0x0E, 0x00, 0x10, 0x01, 0x27, 0x01, 0x00])  # 27 01 = SecurityAccess
    syn_then_payload(target, 13400, uds)
    print(f"[*] UDS SecurityAccess sent to {target}:13400")

def test_someip(target):
    """SOME/IP-SD offer 非白名单服务 (detector 6)."""
    sd = bytes([0x80, 0, 0, 0]) + (16).to_bytes(4, 'big') + bytes([0x01, 0, 0, 0]) + \
         (0x9999).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + bytes([1, 0, 0, 3]) + (0).to_bytes(4, 'big') + (0).to_bytes(4, 'big')
    someip = (0xFFFF).to_bytes(2, 'big') + (0x8100).to_bytes(2, 'big') + (8 + len(sd)).to_bytes(4, 'big') + \
             (1).to_bytes(2, 'big') + (7).to_bytes(2, 'big') + bytes([1, 1, 0x02, 0]) + sd
    pkt = IP(dst=target)/UDP(sport=30490, dport=30490)/Raw(load=someip)
    send(pkt, verbose=0)
    print(f"[*] SOME/IP-SD rogue offer sent to {target}:30490")

def test_tls(target):
    """TLS 1.0 ClientHello (detector 9, aux=0x9002 版本<1.2)."""
    # TLS record: handshake(0x16) ver 03 01 (TLS 1.0) + ClientHello
    ch = bytes([0x01, 0x00, 0x00, 0x2A]) + bytes([0x03, 0x01]) + b'\xAA'*32 + \
         bytes([0]) + (2).to_bytes(2, 'big') + (0x002F).to_bytes(2, 'big') + bytes([1, 0])
    tls = bytes([0x16, 0x03, 0x01]) + (len(ch)).to_bytes(2, 'big') + ch
    syn_then_payload(target, 443, tls)
    print(f"[*] TLS 1.0 ClientHello sent to {target}:443")

def test_http(target):
    """HTTP /admin (rule sid=3000001, detector 4)."""
    http = b"GET /admin/config HTTP/1.1\r\nHost: ecu\r\n\r\n"
    syn_then_payload(target, 80, http)
    print(f"[*] HTTP /admin sent to {target}:80")

TESTS = {"doip": test_doip, "uds": test_uds, "someip": test_someip,
         "tls": test_tls, "http": test_http}

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    target, name = sys.argv[1], sys.argv[2]
    if name == "all":
        for t in TESTS.values():
            t(target)
    elif name in TESTS:
        TESTS[name](target)
    else:
        print(f"unknown test: {name} (choose from {list(TESTS) + ['all']})")
