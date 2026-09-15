#!/usr/bin/env python3
"""
Minimal HTTP server simulating a SOC endpoint for IDSRM testing.

Usage:
    python3 tests/mock_soc_server.py [port]   (default port: 8080)

Listens on:
    POST http://localhost:<port>/api/idsm-violations

Expected JSON payload (QSEv forwarded by IDSRM, R24-11 data model):
    {"ids_message": "<hex>", "protocol_version": 2,
     "has_context_data": <bool>, "has_timestamp": <bool>,
     "idsm_instance_id": <uint>, "sensor_instance_id": <uint>,
     "event_id": <uint>, "count": <uint>, "severity": "LOW|MEDIUM|HIGH|CRITICAL",
     "timestamp_s": <uint>, "timestamp_ns": <uint>,
     "context_data_version": <uint>,
     "payload": "<hex>", "payload_len": <uint>}

Returns:
    200 {"status":"ok"}   on valid event
    400                   on malformed payload
    404                   on wrong path
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import struct
import sys

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ENDPOINT = "/api/idsm-violations"

# detector_type → human-readable name (apps/eth_probe/alert.h)
DETECTOR_NAMES = {
    1: "PORT_SCAN", 2: "RATE_FLOOD", 3: "FLAG_ANOMALY", 4: "RULE_HIT",
    5: "DOIP", 6: "SOME_IP", 7: "REASSEMBLY", 8: "CROSS_BORDER",
    9: "TLS", 10: "HTTP", 11: "DNS", 12: "ARP_SPOOF", 100: "SURICATA",
}
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def decode_context(payload_hex: str) -> str:
    """Decode the 46-byte eth_probe/eve_bridge context layout v1 into a
    human-readable summary. Returns empty string for other layouts."""
    try:
        raw = bytes.fromhex(payload_hex)
    except ValueError:
        return ""
    if len(raw) != 46:
        return ""
    (det_type, proto, sport, dport) = struct.unpack(">BBHH", raw[:6])
    src = raw[6:22]
    dst = raw[22:38]
    count, aux = struct.unpack(">II", raw[38:46])

    def ip_str(b: bytes) -> str:
        if b[4:] == b"\x00" * 12:  # IPv4 in first 4 bytes
            return ".".join(str(x) for x in b[:4])
        return ":".join(f"{b[i]:02x}{b[i+1]:02x}" for i in range(0, 16, 2)).lstrip("0")

    det = DETECTOR_NAMES.get(det_type, f"TYPE_{det_type}")
    proto_s = PROTO_NAMES.get(proto, str(proto))
    return (f"{det} {proto_s} {ip_str(src)}:{sport} -> {ip_str(dst)}:{dport}"
            f" aux=0x{aux:08X} x{count}")


class SocHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != ENDPOINT:
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        try:
            event = json.loads(body)
            assert "ids_message"          in event, "missing ids_message"
            assert "event_id"             in event, "missing event_id"
            assert "count"                in event, "missing count"
            assert "severity"             in event, "missing severity"
            assert "payload"              in event, "missing payload"
            assert "context_data_version" in event, "missing context_data_version"
            assert event["severity"] in VALID_SEVERITIES, \
                f"invalid severity: {event['severity']}"

            decoded = decode_context(event["payload"])
            print(
                f"[SOC] event=0x{event['event_id']:04X}"
                f"  idsm={event.get('idsm_instance_id', '?')}"
                f"  sensor={event.get('sensor_instance_id', '?')}"
                f"  count={event['count']}"
                f"  severity={event['severity']:<8}"
                + (f"\n      >> {decoded}" if decoded else "")
                + f"\n      payload={event['payload']}"
                f"  len={event.get('payload_len', '?')}"
                f"\n      msg={event['ids_message']}",
                flush=True
            )

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        except (AssertionError, json.JSONDecodeError, KeyError) as exc:
            print(f"[SOC ERR] {exc}", flush=True)
            self.send_response(400)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress default access log noise


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"[SOC] Listening on http://localhost:{port}{ENDPOINT}")
    print("[SOC] Press Ctrl+C to stop\n", flush=True)
    try:
        HTTPServer(("localhost", port), SocHandler).serve_forever()
    except KeyboardInterrupt:
        print("\n[SOC] Stopped.")
