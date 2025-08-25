# BTC_Generate_Compare - the best BTC adress generating and comparing scrypt

Summary of btc_pattern_scanner.py

Purpose:
Generates Bitcoin private keys following specified patterns (from patterns.txt), derives multiple address types (P2PKH, P2SH, SegWit, Taproot), and checks if they exist in a large address database (Parquet → LMDB).
If a match is found, the script records it with the private key and WIF formats.

Pattern Types Supported (from patterns.txt):

octal → 8 hex characters, each repeated 8×

sequence_4x16 → 4-symbol sequence repeated 16×

Modes:

Pattern Mode: Generate private keys from user-defined patterns.

Sequential Mode: Start from a specific/random/last-saved key and iterate sequentially.

Performance Features:

Uses multiprocessing with configurable workers (workers_gen, workers_db).

LMDB used as fast key-value database for address lookups (loaded from Parquet).

Chunked processing of patterns to avoid memory issues.

Resume/Checkpoint files (processed_patterns.txt, last_state.json, last_sequential_key.txt) for crash recovery.

Monitoring thread displays throughput, memory, CPU usage, and matches in real-time.

Writes results incrementally to matches.csv and a final summary.
