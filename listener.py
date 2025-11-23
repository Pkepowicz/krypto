#!/usr/bin/env python3
"""Listener (verifier) server with simple timing and psutil measurements.

Receives a signed payload and prints verification time and PSS (or RSS) memory deltas.
Replies with JSON including verification result and timing/memory fields.
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


def read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def get_pss_for_proc() -> int:
    proc = psutil.Process()
    try:
        mi = proc.memory_full_info()
        pss = getattr(mi, "pss", None)
        if pss is not None:
            return pss
    except Exception:
        pass
    return proc.memory_info().rss


def recv_message(conn: socket.socket) -> dict:
    raw = read_exact(conn, 8)
    (length,) = struct.unpack("!Q", raw)
    payload = read_exact(conn, length)
    return json.loads(payload.decode("utf-8"))


def send_message(conn: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    header = struct.pack("!Q", len(data))
    conn.sendall(header + data)


def handle_connection(conn: socket.socket, addr) -> None:
    try:
        msg = recv_message(conn)
    except Exception as e:
        send_message(conn, {"verified": False, "message": f"receive error: {e}"})
        return

    scheme = msg.get("scheme")
    data_b64 = msg.get("data")
    sig_b64 = msg.get("signature")
    pub_b64 = msg.get("public_key")

    if not all([scheme, data_b64, sig_b64, pub_b64]):
        send_message(conn, {"verified": False, "message": "missing fields"})
        return

    try:
        data = base64.b64decode(data_b64)
        signature = base64.b64decode(sig_b64)
        public_key = base64.b64decode(pub_b64)
    except Exception as e:
        send_message(conn, {"verified": False, "message": f"base64 decode error: {e}"})
        return

    try:
        with oqs.Signature(scheme) as verifier:
            mem_before = get_pss_for_proc()
            t0 = time.perf_counter()
            try:
                verifier.verify(data, signature, public_key)
                verified = True
                message = "signature valid"
            except Exception:
                verified = False
                message = "signature invalid"
            t1 = time.perf_counter()
            mem_after = get_pss_for_proc()

            verify_time = t1 - t0
            verify_mem_delta = mem_after - mem_before

            # Print server-side metrics and return them to caller
            print(f"Verified={verified} addr={addr} time={verify_time:.6f}s pss_delta={verify_mem_delta}")
            send_message(conn, {
                "verified": verified,
                "message": message,
                "verify_time_s": verify_time,
                "verify_pss_delta": verify_mem_delta,
            })
    except Exception as e:
        send_message(conn, {"verified": False, "message": f"verifier error: {e}"})


def run_server(host: str, port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        print(f"Listening on {host}:{port}...")
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connection from {addr}")
                try:
                    handle_connection(conn, addr)
                except Exception as e:
                    print(f"Error handling connection {addr}: {e}")


def main():
    parser = argparse.ArgumentParser(description="OQS signature listener/verifier")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    run_server(args.host, args.port)


if __name__ == "__main__":
    main()
