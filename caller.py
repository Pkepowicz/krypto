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
from perf_counter import PerfCounter

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
    parser.add_argument("--arch", default=None, help="Override architecture for perf counter (x86_64, armv7, armv8)")
    parser.add_argument("--csv", default="metrics.csv", help="CSV file to append metrics to")
    parser.add_argument("--run", type=int, default=1, help="Run number to record in CSV")
    parser.add_argument("--rounds", type=int, default=1, help="Number of rounds to perform (default: 1)")
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

    pc = PerfCounter(arch=args.arch)

    # Run the requested number of rounds, appending CSV rows per run.
    import os, csv

    csv_path = args.csv
    start_run = int(args.run)

    for i in range(int(args.rounds)):
        runnum = start_run + i

        # Create a fresh signer for each round to ensure independent key generation
        with oqs.Signature(args.scheme) as signer:
            # Key generation cycles + elapsed
            gen_cycles, pub, gen_time = pc.measure_callable(signer.generate_keypair)

            # Signing cycles + elapsed (use the freshly created signer)
            sign_cycles, sig, sign_time = pc.measure_callable(signer.sign, data)

        payload = {
            "scheme": args.scheme,
            "data": base64.b64encode(data).decode("ascii"),
            "signature": base64.b64encode(sig).decode("ascii"),
            "public_key": base64.b64encode(pub).decode("ascii"),
        }

        # Send and wait for response; measure cycles and elapsed for send+recv
        def send_and_recv():
            with socket.create_connection((args.host, args.port), timeout=10) as conn:
                send_message(conn, payload)
                return recv_message(conn)

        net_cycles, resp, net_time = pc.measure_callable(send_and_recv)

        # Print measurements for this round
        print(f"== Caller measurements (run {runnum}) ==")
        print(f"Keygen time: {gen_time:.6f} s")
        print(f"Keygen cycles: {gen_cycles}")
        print(f"Sign time: {sign_time:.6f} s")
        print(f"Sign cycles: {sign_cycles}")
        print(f"Network cycles (send+recv): {net_cycles}")
        print(f"Network roundtrip time (send+recv): {net_time:.6f} s")
        print("")
        print("Verifier response:")
        print(json.dumps(resp, indent=2))

        # Prepare CSV row: run number, keygen time, keygen cycles, sign time, sign cycles, verify time, verify cycles, verified
        try:
            verify_cycles = int(resp.get("verify_cycles", 0))
        except Exception:
            verify_cycles = 0
        try:
            verify_time = float(resp.get("verify_time_s", 0.0))
        except Exception:
            verify_time = 0.0
        verified = bool(resp.get("verified", False))

        # Append to CSV, write header if file does not exist
        write_header = not os.path.exists(csv_path)
        with open(csv_path, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            if write_header:
                writer.writerow(["run", "keygen_time_s", "keygen_cycles", "sign_time_s", "sign_cycles", "verify_time_s", "verify_cycles", "verified"])
            writer.writerow([runnum, f"{gen_time:.6f}", gen_cycles, f"{sign_time:.6f}", sign_cycles, f"{verify_time:.6f}", verify_cycles, str(verified)])


if __name__ == "__main__":
    main()
