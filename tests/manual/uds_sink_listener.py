#!/usr/bin/env python3
"""Manual live test for the IdsRm UDS sink (--sink).

Listens on an AF_UNIX socket, prints every NDJSON line received, and
exits after --expect lines or --timeout seconds.

Usage (on the build host):
  python3 tests/manual/uds_sink_listener.py /tmp/idsm_live.sock --expect 12
"""
import argparse
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--expect", type=int, default=0, help="exit after N lines (0 = never)")
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        import os
        os.unlink(args.path)
    except FileNotFoundError:
        pass
    srv.bind(args.path)
    srv.listen(1)
    srv.settimeout(1.0)

    print(f"[listener] waiting on {args.path}", flush=True)
    conn = None
    deadline = time.time() + args.timeout
    lines = 0
    while time.time() < deadline:
        if conn is None:
            try:
                conn, _ = srv.accept()
                conn.settimeout(1.0)
                print("[listener] probe connected", flush=True)
            except socket.timeout:
                continue
        try:
            data = conn.recv(65536)
            if not data:
                print("[listener] probe disconnected", flush=True)
                conn = None
                continue
            for line in data.decode("utf-8", "replace").splitlines():
                lines += 1
                print(f"[{lines:02d}] {line}", flush=True)
            if args.expect and lines >= args.expect:
                break
        except socket.timeout:
            continue
    print(f"[listener] total {lines} line(s)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
