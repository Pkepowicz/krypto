# Krypto

Repository for experimenting with python-oqs signing/verification and benchmarking.

## Quick Run

Install dependencies:

```zsh
python3 -m pip install -r requirements.txt
```

Start the verifier (listener) on the host that should verify incoming signatures:

```zsh
python3 listener.py --host 0.0.0.0 --port 9000
```

Sign and send a file from the caller (signer) to the verifier:

```zsh
python3 caller.py --host 127.0.0.1 --port 9000 --file example.txt
```

Run the local benchmark/demo in `main.py` (measures keygen/sign/verify times):

```zsh
python3 main.py --benchmark --scheme Dilithium2 --file example.txt --rounds 20 --batch 10 --warmup 5 --output-json
```

Notes:
- Replace `Dilithium2` with any supported scheme listed by your installed `python-oqs`.
- The network transport is plain TCP (no TLS/auth). Use an SSH tunnel or add TLS for production.

