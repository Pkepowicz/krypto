#!/usr/bin/env python3
"""RSA Listener (verifier) server with timing, cycles, and memory measurements.

Receives a signed payload with RSA-PSS and prints verification time and PSS memory deltas.
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
import typing
import psutil
from perf_counter import PerfCounter

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("Missing dependency: cryptography. Install with: pip install cryptography", file=sys.stderr)
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


def handle_connection(conn: socket.socket, addr, arch: typing.Optional[str] = None) -> None:
    try:
        msg = recv_message(conn)
    except Exception as e:
        send_message(conn, {"verified": False, "message": f"receive error: {e}"})
        return

    key_size = msg.get("key_size")
    data_b64 = msg.get("data")
    sig_b64 = msg.get("signature")
    pub_b64 = msg.get("public_key")

    if not all([key_size, data_b64, sig_b64, pub_b64]):
        send_message(conn, {"verified": False, "message": "missing fields"})
        return

    try:
        data = base64.b64decode(data_b64)
        signature = base64.b64decode(sig_b64)
        public_key_pem = base64.b64decode(pub_b64).decode("ascii")
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except Exception as e:
        send_message(conn, {"verified": False, "message": f"decode error: {e}"})
        return

    pc = PerfCounter(arch=arch)
    mem_before = get_pss_for_proc()
    try:
        verify_cycles, _ret, verify_time = pc.measure_callable(
            public_key.verify, signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
        )
        verified = True
        message = "signature valid"
    except Exception:
        verified = False
        message = "signature invalid"
        verify_cycles = 0
        verify_time = 0.0
    mem_after = get_pss_for_proc()

    verify_mem_delta = mem_after - mem_before

    # Print server-side metrics and return them to caller
    print(f"Verified={verified} addr={addr} time={verify_time:.6f}s pss_delta={verify_mem_delta} cycles={verify_cycles}")
    send_message(conn, {
        "verified": verified,
        "message": message,
        "verify_time_s": verify_time,
        "verify_pss_delta": verify_mem_delta,
        "verify_cycles": verify_cycles,
    })


def run_server(host: str, port: int, arch: typing.Optional[str] = None):
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
                    handle_connection(conn, addr, arch=arch)
                except Exception as e:
                    print(f"Error handling connection {addr}: {e}")


def main():
    parser = argparse.ArgumentParser(description="RSA signature listener/verifier")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--arch", default=None, help="Override architecture for perf counter (x86_64, armv7, armv8)")
    args = parser.parse_args()

    run_server(args.host, args.port, arch=args.arch)


if __name__ == "__main__":
    main()