#!/usr/bin/env python3
"""RSA Caller (signer) client with timing, cycles, and memory measurements.

This script signs a file with RSA-PSS, sends it to the verifier, and prints:
 - keygen time and cycles
 - sign time and cycles
 - verifier response (as received)

Usage example:
  python3 rsa_caller.py --host 127.0.0.1 --port 9000 --file example.txt
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
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("Missing dependency: cryptography. Install with: pip install cryptography", file=sys.stderr)
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


def main():
    parser = argparse.ArgumentParser(description="RSA signer client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--file", default="example.txt", help="File to sign and send")
    parser.add_argument("--key-size", type=int, default=2048, help="RSA key size in bits (default: 2048)")
    parser.add_argument("--arch", default=None, help="Override architecture for perf counter (x86_64, armv7, armv8)")
    parser.add_argument("--csv", default="rsa_metrics.csv", help="CSV file to append metrics to")
    parser.add_argument("--run", type=int, default=1, help="Run number to record in CSV")
    parser.add_argument("--rounds", type=int, default=1, help="Number of rounds to perform (default: 1)")
    parser.add_argument("--net-timeout", type=float, default=10.0, help="Connection timeout seconds for establishing TCP connection")
    args = parser.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()

    pc = PerfCounter(arch=args.arch)

    # Run the requested number of rounds, appending CSV rows per run.
    import os, csv

    csv_path = args.csv
    start_run = int(args.run)

    for i in range(int(args.rounds)):
        runnum = start_run + i

        # Generate RSA keypair
        gen_cycles, private_key, gen_time = pc.measure_callable(
            rsa.generate_private_key, public_exponent=65537, key_size=args.key_size
        )
        public_key = private_key.public_key()

        # Serialize keys for sending
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

        # Sign the data
        sign_cycles, signature, sign_time = pc.measure_callable(
            private_key.sign, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
        )

        payload = {
            "key_size": args.key_size,
            "data": base64.b64encode(data).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
            "public_key": base64.b64encode(public_key_pem.encode("ascii")).decode("ascii"),
        }

        # Send and wait for response (do not measure send/recv time)
        def send_and_recv():
            conn = socket.create_connection((args.host, args.port), timeout=args.net_timeout)
            try:
                conn.settimeout(None)
                send_message(conn, payload)
                return recv_message(conn)
            finally:
                conn.close()

        resp = send_and_recv()

        # Print measurements for this round
        print(f"== RSA Caller measurements (run {runnum}) ==")
        print(f"Keygen time: {gen_time:.6f} s")
        print(f"Keygen cycles: {gen_cycles}")
        print(f"Sign time: {sign_time:.6f} s")
        print(f"Sign cycles: {sign_cycles}")
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