"""Simple demo: sign and verify a file using Open Quantum Safe (python-oqs).

Requires: `python-oqs` (install with `pip install python-oqs`).
This script creates `example.txt`, signs it with Dilithium2, writes
`example.sig` and `example.pub` and verifies the signature.
"""
from pathlib import Path
import base64
import sys
import argparse
import time
import statistics
import json
import os
try:
    import psutil
except Exception:
    psutil = None

try:
    import oqs
except Exception:
    print(
        "Missing dependency: python-oqs.",
        file=sys.stderr,
    )
    raise


DEFAULT_SCHEME = "Dilithium2"


def sign_bytes_once(data: bytes, scheme: str = DEFAULT_SCHEME):
    """Sign once: return (public_key_bytes, signature_bytes)."""
    with oqs.Signature(scheme) as signer:
        pub = signer.generate_keypair()
        sig = signer.sign(data)
    return pub, sig


def verify_bytes_once(data: bytes, signature: bytes, public_key: bytes, scheme: str = DEFAULT_SCHEME) -> bool:
    """Return True if signature verifies, False otherwise."""
    with oqs.Signature(scheme) as verifier:
        try:
            verifier.verify(data, signature, public_key)
            return True
        except Exception:
            return False


def benchmark_scheme(scheme: str, data: bytes, rounds: int = 10, batch: int = 1, warmup: int = 5):
    """Benchmark key generation, signing and verification times.

    Returns a dict with timing lists and summary statistics.
    Uses `psutil` when available and falls back to /proc parsing for RSS and PSS.
    Supports warmup iterations and batching; recorded memory values are per-op averages
    when batching is used.
    """
    keygen_times = []
    sign_times = []
    verify_times = []
    # PSS deltas (bytes)
    keygen_pss = []
    sign_pss = []
    verify_pss = []

    def get_pss_bytes() -> int:
        """Return current PSS (proportional set size) in bytes when available.

        Uses psutil.memory_full_info().pss if available, otherwise parses
        `/proc/self/smaps_rollup` for the `Pss:` value. Returns 0 if unavailable.
        """
        if psutil:
            try:
                mfi = psutil.Process().memory_full_info()
                pss = getattr(mfi, 'pss', None)
                if pss is not None:
                    return int(pss)
            except Exception:
                pass
        try:
            with open('/proc/self/smaps_rollup', 'r') as f:
                for line in f:
                    if line.startswith('Pss:'):
                        parts = line.split()
                        return int(parts[1]) * 1024
        except Exception:
            pass
        return 0

    # Use separate contexts for signer and verifier to avoid conflicts
    with oqs.Signature(scheme) as signer, oqs.Signature(scheme) as verifier:
        # Warm-up phase: run a few iterations to allow libraries to initialize
        for _ in range(max(0, warmup)):
            try:
                pub_w = signer.generate_keypair()
                sig_w = signer.sign(data)
                verifier.verify(data, sig_w, pub_w)
            except Exception:
                pass

        for i in range(rounds):
            # Key generation batch: generate `batch` keypairs and measure PSS
            pss0 = get_pss_bytes()
            t0 = time.perf_counter()
            pubs = [signer.generate_keypair() for _ in range(batch)]
            t1 = time.perf_counter()
            pss1 = get_pss_bytes()
            total_keygen = t1 - t0
            keygen_times.append(total_keygen / batch)
            keygen_pss.append((pss1 - pss0) / batch)

            # Signing batch: sign `batch` times using current keypair
            pss0 = get_pss_bytes()
            t0 = time.perf_counter()
            sigs = [signer.sign(data) for _ in range(batch)]
            t1 = time.perf_counter()
            pss1 = get_pss_bytes()
            total_sign = t1 - t0
            sign_times.append(total_sign / batch)
            sign_pss.append((pss1 - pss0) / batch)

            # Verification batch: verify each signature using the last public key
            pub = pubs[-1]
            pss0 = get_pss_bytes()
            t0 = time.perf_counter()
            for s in sigs:
                verifier.verify(data, s, pub)
            t1 = time.perf_counter()
            pss1 = get_pss_bytes()
            total_verify = t1 - t0
            verify_times.append(total_verify / batch)
            verify_pss.append((pss1 - pss0) / batch)

    def summary(lst):
        return {
            "count": len(lst),
            "mean_s": statistics.mean(lst) if lst else 0.0,
            "median_s": statistics.median(lst) if lst else 0.0,
            "stdev_s": statistics.stdev(lst) if len(lst) > 1 else 0.0,
            "min_s": min(lst) if lst else 0.0,
            "max_s": max(lst) if lst else 0.0,
        }

    result = {
        "scheme": scheme,
        "rounds": rounds,
        "keygen_times_s": keygen_times,
        "sign_times_s": sign_times,
        "verify_times_s": verify_times,
        "keygen_pss_bytes": keygen_pss,
        "sign_pss_bytes": sign_pss,
        "verify_pss_bytes": verify_pss,
        "keygen_summary": summary(keygen_times),
        "sign_summary": summary(sign_times),
        "verify_summary": summary(verify_times),
        "keygen_pss_summary": summary(keygen_pss),
        "sign_pss_summary": summary(sign_pss),
        "verify_pss_summary": summary(verify_pss),
    }

    return result


def print_summary(res: dict, json_out: bool = False):
    if json_out:
        print(json.dumps(res, indent=2))
        return

    print(f"Benchmark results for scheme: {res['scheme']}")
    print(f"Rounds: {res['rounds']}")
    for name in ("keygen", "sign", "verify"):
        s = res[f"{name}_summary"]
        print(
            f"- {name.capitalize():7}: mean={s['mean_s']*1000:.3f} ms, median={s['median_s']*1000:.3f} ms, stdev={s['stdev_s']*1000:.3f} ms, min={s['min_s']*1000:.3f} ms, max={s['max_s']*1000:.3f} ms"
        )
    # Print PSS memory summaries (in KB)
    for name in ("keygen", "sign", "verify"):
        s_pss = res.get(f"{name}_pss_summary")
        if s_pss:
            print(
                f"  {name.capitalize():7} pss: mean={s_pss['mean_s']/1024:.3f} KB, median={s_pss['median_s']/1024:.3f} KB, stdev={s_pss['stdev_s']/1024:.3f} KB, min={s_pss['min_s']/1024:.3f} KB, max={s_pss['max_s']/1024:.3f} KB"
            )


def main():
    parser = argparse.ArgumentParser(description="OQS signature demo and benchmark")
    parser.add_argument("--scheme", default=DEFAULT_SCHEME, help="Signature scheme (default: %(default)s)")
    parser.add_argument("--file", default="example.txt", help="File to sign/benchmark (default: %(default)s)")
    parser.add_argument("--rounds", type=int, default=10, help="Rounds for benchmark (default: %(default)s)")
    parser.add_argument("--benchmark", action="store_true", help="Run benchmark instead of single sign/verify demo")
    parser.add_argument("--output-json", action="store_true", help="Output benchmark results as JSON")
    parser.add_argument("--batch", type=int, default=1, help="Batch size for each measured round (default: %(default)s)")
    parser.add_argument("--warmup", type=int, default=5, help="Warmup iterations before measuring (default: %(default)s)")
    args = parser.parse_args()

    base = Path(__file__).parent
    example = base / args.file

    # Create example file if missing
    if not example.exists():
        example.write_text("This is a test message for OQS signature.\n")

    data = example.read_bytes()

    if args.benchmark:
        print(f"Running benchmark: scheme={args.scheme}, rounds={args.rounds}, batch={args.batch}, warmup={args.warmup}")
        res = benchmark_scheme(args.scheme, data, rounds=args.rounds, batch=args.batch, warmup=args.warmup)
        print_summary(res, json_out=args.output_json)
        return

    # Default demo: single sign and verify (same behavior as before)
    print(f"Using scheme: {args.scheme}")
    print("Signing file...")
    pub, sig = sign_bytes_once(data, scheme=args.scheme)

    # Verify
    print("Verifying signature...")
    ok = verify_bytes_once(data, sig, pub, scheme=args.scheme)
    if ok:
        print("Verification succeeded: signature is valid.")
    else:
        print("Verification FAILED: signature is invalid.")


if __name__ == "__main__":
    main()
