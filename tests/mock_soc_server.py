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
import sys

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ENDPOINT = "/api/idsm-violations"


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

            print(
                f"[SOC] event=0x{event['event_id']:04X}"
                f"  idsm={event.get('idsm_instance_id', '?')}"
                f"  sensor={event.get('sensor_instance_id', '?')}"
                f"  count={event['count']}"
                f"  severity={event['severity']:<8}"
                f"  payload={event['payload']}"
                f"  len={event.get('payload_len', '?')}"
                f"  msg={event['ids_message']}",
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
