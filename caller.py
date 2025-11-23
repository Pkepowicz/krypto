#!/usr/bin/env python3
"""Caller (signer) client with simple timing and psutil memory measurements.

This script signs a file, sends it to the verifier, and prints:
 - sign time and psutil PSS (or RSS) memory delta
 - network roundtrip time
 - verifier response (as received)

Usage example:
  python3 caller.py --host 127.0.0.1 --port 9000 --file example.txt
"""
from __future__ import annotations
import argparse
import base64
import json
import socket
import struct
import sys
import time
import psutil

try:
    import oqs
except Exception:
    print("Missing dependency: python-oqs. Install with: pip install python-oqs", file=sys.stderr)
    raise


def send_message(conn: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    header = struct.pack("!Q", len(data))
    conn.sendall(header + data)


def read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_message(conn: socket.socket) -> dict:
    raw = read_exact(conn, 8)
    (length,) = struct.unpack("!Q", raw)
    payload = read_exact(conn, length)
    return json.loads(payload.decode("utf-8"))


def sign_bytes(data: bytes, scheme: str):
    with oqs.Signature(scheme) as signer:
        pub = signer.generate_keypair()
        sig = signer.sign(data)
    return pub, sig


def format_bytes(n: int) -> str:
    # Human-friendly bytes
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024.0:
            return f"{n:.0f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TiB"


def main():
    parser = argparse.ArgumentParser(description="OQS signer client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--file", default="example.txt", help="File to sign and send")
    parser.add_argument("--scheme", default="Dilithium2", help="Signature scheme (default: %(default)s)")
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()

    # Measure PSS (preferred) via psutil; fallback to RSS if PSS unavailable
    proc = psutil.Process()

    def get_pss() -> int:
        try:
            mi = proc.memory_full_info()
            pss = getattr(mi, "pss", None)
            if pss is not None:
                return pss
        except Exception:
            pass
        return proc.memory_info().rss

    mem_before = get_pss()
    t0 = time.perf_counter()
    pub, sig = sign_bytes(data, args.scheme)
    t1 = time.perf_counter()
    mem_after = get_pss()

    sign_time = t1 - t0
    sign_mem_delta = mem_after - mem_before

    payload = {
        "scheme": args.scheme,
        "data": base64.b64encode(data).decode("ascii"),
        "signature": base64.b64encode(sig).decode("ascii"),
        "public_key": base64.b64encode(pub).decode("ascii"),
    }

    # Send and wait for response
    t_net0 = time.perf_counter()
    with socket.create_connection((args.host, args.port), timeout=10) as conn:
        send_message(conn, payload)
        resp = recv_message(conn)
    t_net1 = time.perf_counter()

    net_time = t_net1 - t_net0

    # Print measurements
    print("== Caller measurements ==")
    print(f"Sign time: {sign_time:.6f} s")
    print(f"Sign memory delta (pss or rss): {format_bytes(sign_mem_delta)}")
    print(f"Network roundtrip time (send+recv): {net_time:.6f} s")
    print("")
    print("Verifier response:")
    print(json.dumps(resp, indent=2))


if __name__ == "__main__":
    main()
