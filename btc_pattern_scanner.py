#!/usr/bin/env python3
# btc_pattern_scanner.py

import os
import sys
import json
import csv
import signal
import time
import secrets
import hashlib
import lmdb
import pandas as pd
import coincurve
import psutil
import gc
from multiprocessing import Pool, Manager, cpu_count
from threading import Thread

# -----------------------------------------------------------------------------
# CONFIG and GLOBALS
# -----------------------------------------------------------------------------
# Use absolute paths relative to the script location to avoid CWD issues
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PATTERN_FILE       = os.path.join(SCRIPT_DIR, 'patterns.txt')
ADDRESS_DB_PARQUET = os.path.join(SCRIPT_DIR, 'Bitcoin_addresses_LATEST.parquet')
LMDB_DIR           = os.path.join(SCRIPT_DIR, 'address_db')
MATCHES_FILE       = os.path.join(SCRIPT_DIR, 'matches.csv')
RESUME_FILE        = os.path.join(SCRIPT_DIR, 'processed_patterns.txt')
LAST_STATE_FILE    = os.path.join(SCRIPT_DIR, 'last_state.json')
LAST_SEQ_FILE      = os.path.join(SCRIPT_DIR, 'last_sequential_key.txt')


# secp256k1 private key range (1 ≤ k < N)
SECP256K1_MIN = 1

# Get the curve order from the library's internal constant
# This is a more robust way to get N across different coincurve versions
SECP256K1_N = coincurve.utils.GROUP_ORDER_INT
SECP256K1_MAX = SECP256K1_N - 1


# Will be filled at runtime
workers_gen    = cpu_count()
workers_db     = 1
generated_cnt  = None
compared_cnt   = None

# Global flag for graceful shutdown
shutdown_requested = False

def signal_handler(signum, frame):
    """Handle Ctrl+C signal for graceful shutdown."""
    global shutdown_requested
    print(f"\n\nReceived signal {signum}. Initiating graceful shutdown...")
    print("Please wait while the current chunk finishes processing...")
    shutdown_requested = True

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # Termination signal

# -----------------------------------------------------------------------------
# Base58 / Bech32 Helpers
# -----------------------------------------------------------------------------
B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58encode(b: bytes) -> str:
    """Encode bytes to Base58."""
    n = int.from_bytes(b, 'big')
    s = bytearray()
    while n:
        n, r = divmod(n, 58)
        s.insert(0, B58_ALPHABET[r])
    # leading zero bytes
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return (B58_ALPHABET[0:1] * pad + s).decode()

def base58_check(payload: bytes) -> str:
    """Base58 with 4-byte double-SHA256 checksum."""
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)

def hash160(b: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

# Bech32 / Bech32m (BIP-0173 & BIP-0350)
CHARSET      = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_REV  = {c:i for i,c in enumerate(CHARSET)}

def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data, spec='bech32'):
    """Compute checksum for Bech32 or Bech32m."""
    const = 1 if spec == 'bech32' else 0x2bc830a3
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0]*6) ^ const
    return [(polymod >> 5*(5-i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec='bech32'):
    chk = bech32_create_checksum(hrp, data, spec)
    combined = data + chk
    return hrp + '1' + ''.join(CHARSET[d] for d in combined)

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for x in data:
        acc = (acc << frombits) | x
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def segwit_addr_encode(hrp, witver, witprog):
    data = [witver] + convertbits(witprog, 8, 5)
    spec = 'bech32' if witver == 0 else 'bech32m'
    return bech32_encode(hrp, data, spec)

def private_key_to_wif(private_key_int, compressed=True):
    """Convert a private key integer to WIF format."""
    # Convert to 32-byte big-endian
    private_key_bytes = private_key_int.to_bytes(32, 'big')
    
    # Mainnet prefix is 0x80
    payload = b'\x80' + private_key_bytes
    
    # Add compression flag if compressed
    if compressed:
        payload += b'\x01'
    
    return base58_check(payload)


def derive_all_addresses_for_priv_int(priv_int):
    """Derive all supported Bitcoin addresses for a given private key integer.
    Returns list of 7 addresses in order:
    [P2PKH_uncompressed, P2PKH_compressed, P2SH_legacy, P2SH_P2WPKH, Bech32_P2WPKH, Bech32_P2WSH, Bech32m_P2TR]
    """
    pk = coincurve.PrivateKey.from_int(priv_int)
    pub_un = pk.public_key.format(compressed=False)
    pub_c  = pk.public_key.format(compressed=True)

    # 1) P2PKH
    h160_un = hash160(pub_un)
    h160_c  = hash160(pub_c)
    p2pkh_un = base58_check(b'\x00' + h160_un)
    p2pkh_c  = base58_check(b'\x00' + h160_c)

    # 2) P2SH-legacy (classic P2PKH script hashed)
    script = b'\x76\xa9\x14' + h160_c + b'\x88\xac'
    script_hash = hash160(script)
    p2sh_legacy = base58_check(b'\x05' + script_hash)

    # 3) Nested P2WPKH
    inner = b'\x00\x14' + h160_c
    nested_hash = hash160(inner)
    p2sh_wpkh = base58_check(b'\x05' + nested_hash)

    # 4) Native segwit P2WPKH
    bech32_p2wpkh = segwit_addr_encode('bc', 0, h160_c)

    # 5) P2WSH (v0)
    prog = hashlib.sha256(script).digest()
    bech32_p2wsh = segwit_addr_encode('bc', 0, prog)

    # 6) Taproot (v1) over x-only pubkey
    xonly = pub_c[1:33]
    bech32_p2tr = segwit_addr_encode('bc', 1, xonly)

    return [
        p2pkh_un, p2pkh_c,
        p2sh_legacy, p2sh_wpkh,
        bech32_p2wpkh, bech32_p2wsh,
        bech32_p2tr
    ]


def make_resume_line(pattern: str) -> str:
    """Create a resume file line: pattern + tab + comma-separated addresses.
    Falls back to pattern only if pattern is invalid or out of range.
    """
    try:
        priv_int = int(pattern, 16)
        if not (SECP256K1_MIN <= priv_int <= SECP256K1_MAX):
            return pattern + "\n"
        addrs = derive_all_addresses_for_priv_int(priv_int)
        return pattern + "\t" + ",".join(addrs) + "\n"
    except Exception:
        return pattern + "\n"


# -----------------------------------------------------------------------------
# LOAD CONFIG & PATTERNS - GENERATOR-BASED APPROACH
# -----------------------------------------------------------------------------
def pattern_generator(config_lines):
    """Generator that yields patterns one by one to avoid memory issues.
    Supported types: octal, sequence_4x16
    """
    blocks = []
    cur = {}
    for L in config_lines:
        L = L.strip()
        if not L or L.startswith('#'):
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        if '=' not in L:
            continue
        k, v = L.split('=', 1)
        k, v = k.strip(), v.strip()
        cur[k] = v
    if cur:
        blocks.append(cur)

    for blk in blocks:
        t = blk.get('pattern_type')
        chars = blk.get('chars', '')

        if t == 'octal':
            # eight chars: each repeated 8× - CHUNKED PROCESSING
            for a in chars:
                for b in chars:
                    for c in chars:
                        for d in chars:
                            for e in chars:
                                for f in chars:
                                    for g in chars:
                                        for h in chars:
                                            yield (
                                                a * 8 + b * 8 + c * 8 + d * 8 +
                                                e * 8 + f * 8 + g * 8 + h * 8
                                            )

        elif t == 'sequence_4x16':
            # 4-symbol sequence repeated 16 times
            for a in chars:
                for b in chars:
                    for c in chars:
                        for d in chars:
                            sequence = a + b + c + d
                            yield sequence * 16
        else:
            raise ValueError(f"Unknown pattern_type {t!r}")

def count_total_patterns(config_lines):
    """Count total patterns without generating them all (supported: octal, sequence_4x16)."""
    blocks = []
    cur = {}
    for L in config_lines:
        L = L.strip()
        if not L or L.startswith('#'):
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        if '=' not in L:
            continue
        k, v = L.split('=', 1)
        k, v = k.strip(), v.strip()
        cur[k] = v
    if cur:
        blocks.append(cur)

    total = 0
    for blk in blocks:
        t = blk.get('pattern_type')
        chars = blk.get('chars', '')
        char_count = len(chars)

        if t == 'octal':
            total += char_count ** 8
        elif t == 'sequence_4x16':
            total += char_count ** 4
        else:
            raise ValueError(f"Unknown pattern_type {t!r}")

    return total

def expand_patterns(config_lines):
    """Legacy function - now returns a generator for memory efficiency."""
    return list(pattern_generator(config_lines))

def load_patterns_and_config():
    """Load config and return pattern generator, total count, and filtered config."""
    global workers_gen, workers_db
    lines = open(PATTERN_FILE).read().splitlines()

    # first pick off workers_*
    filtered = []
    for L in lines:
        if L.startswith('workers_gen='):
            workers_gen = int(L.split('=',1)[1])
        elif L.startswith('workers_db='):
            workers_db = int(L.split('=',1)[1])
        else:
            filtered.append(L)

    # Return generator, total count, and filtered config for memory efficiency
    return pattern_generator(filtered), count_total_patterns(filtered), filtered

# -----------------------------------------------------------------------------
# LMDB SETUP
# -----------------------------------------------------------------------------
def init_lmdb():
    """If LMDB dir empty or missing, load the Parquet into it."""
    if not os.path.isdir(LMDB_DIR) or not os.listdir(LMDB_DIR):
        print("Initializing LMDB from parquet... this may take a while")
        env = lmdb.open(
            LMDB_DIR, 
            map_size=50 * 1024**3,  # Increase map size to 50GB
            writemap=True,          # Use writemap for better write performance
            map_async=True,         # Asynchronous writes
            max_readers=workers_gen * 2
        )
        df = pd.read_parquet(ADDRESS_DB_PARQUET)
        
        # Batch write for better performance
        WRITE_BATCH_SIZE = 10000
        addresses = df.iloc[:,0].tolist()
        
        with env.begin(write=True) as txn:
            for i, addr in enumerate(addresses):
                txn.put(addr.encode(), b'1')
                
                # Commit in batches for better performance
                if i % WRITE_BATCH_SIZE == 0 and i > 0:
                    txn.commit()
                    txn = env.begin(write=True)
                    print(f"Processed {i:,} addresses...")
        
        env.sync()
        env.close()
        print(f"LMDB initialization complete. Loaded {len(addresses):,} addresses.")

# -----------------------------------------------------------------------------
# WORKER: process batch of patterns → derive all addrs → check LMDB → record
# -----------------------------------------------------------------------------

# Global LMDB environment per worker (thread-local)
import threading
_thread_local = threading.local()

def get_lmdb_env():
    """Get thread-local LMDB environment optimized for maximum performance."""
    if not hasattr(_thread_local, 'lmdb_env'):
        _thread_local.lmdb_env = lmdb.open(
            LMDB_DIR, 
            readonly=True, 
            lock=False, 
            max_readers=workers_gen * 4,  # More readers for better concurrency
            readahead=True,   # Enable readahead for better sequential access
            meminit=False,    # Don't initialize memory for better performance
            map_size=100 * 1024**3,  # Large map size for better performance
            max_dbs=1         # Single database for simplicity
        )
    return _thread_local.lmdb_env

def process_pattern_chunk(pattern_chunk):
    """Process a chunk of patterns with memory-efficient approach."""
    global generated_cnt, compared_cnt
    
    results = []
    matches = []
    env = get_lmdb_env()
    
    with env.begin() as txn:
        for pattern in pattern_chunk:
            # Must be 64-hex chars
            try:
                priv_int = int(pattern, 16)
            except ValueError:
                # Skip invalid patterns but still count them as processed
                results.append((pattern, 'INVALID'))
                continue

            # In secp256k1 range?
            if not (SECP256K1_MIN <= priv_int <= SECP256K1_MAX):
                # Skip out-of-range patterns but still count them as processed
                results.append((pattern, 'OUT_OF_RANGE'))
                continue

            pk = coincurve.PrivateKey.from_int(priv_int)
            pub_un = pk.public_key.format(compressed=False)
            pub_c  = pk.public_key.format(compressed=True)

            # Generate Bitcoin addresses (not private keys)
            # 1) P2PKH (Pay-to-Public-Key-Hash) - most common address type
            h160_un = hash160(pub_un)
            h160_c  = hash160(pub_c)
            p2pkh_un = base58_check(b'\x00' + h160_un)  # Uncompressed P2PKH
            p2pkh_c  = base58_check(b'\x00' + h160_c)   # Compressed P2PKH

            # 2) P2SH-legacy (simple OP_HASH160 <PKH> OP_EQUAL)
            script = b'\x76\xa9\x14' + h160_c + b'\x88\xac'
            script_hash = hash160(script)
            p2sh_legacy = base58_check(b'\x05' + script_hash)

            # 3) Nested P2WPKH = P2SH( OP_0 <20-byte-PKH> )
            inner = b'\x00\x14' + h160_c
            nested_hash = hash160(inner)
            p2sh_wpkh = base58_check(b'\x05' + nested_hash)

            # 4) Native segwit P2WPKH
            bech32_p2wpkh = segwit_addr_encode('bc', 0, h160_c)

            # 5) P2WSH = native v0 over SHA256(redeemScript)
            #    redeemScript = same P2PKH script but for witness
            #    SHA256(redeemScript) ⇒ 32b program
            prog = hashlib.sha256(script).digest()
            bech32_p2wsh = segwit_addr_encode('bc', 0, prog)

            # 6) Taproot P2TR v1 = Bech32m over x-only pubkey
            #    x-only is first 32 bytes of compressed pubkey without parity byte
            xonly = pub_c[1:33]
            bech32_p2tr = segwit_addr_encode('bc', 1, xonly)

            # Only include actual Bitcoin addresses (not private keys like WIF)
            all_addrs = [
                p2pkh_un, p2pkh_c,        # P2PKH addresses
                p2sh_legacy, p2sh_wpkh,   # P2SH addresses  
                bech32_p2wpkh, bech32_p2wsh,  # Segwit addresses
                bech32_p2tr               # Taproot address
            ]

            # Count generated addresses (7 addresses per valid pattern)
            generated_cnt.value += len(all_addrs)

            # LMDB lookup - check all addresses against the parquet database
            found_addr = None
            addr_bytes = [addr.encode() for addr in all_addrs]
            
            # Count compared addresses (each address is checked against database)
            compared_cnt.value += len(all_addrs)
            
            for i, addr_b in enumerate(addr_bytes):
                if txn.get(addr_b):
                    found_addr = all_addrs[i]
                    # Generate WIF for the matched address (useful for wallet import)
                    wif_compressed = private_key_to_wif(priv_int, compressed=True)
                    wif_uncompressed = private_key_to_wif(priv_int, compressed=False)
                    matches.append((pattern, found_addr, priv_int, wif_compressed, wif_uncompressed))
                    break

            # Always add to results for consistent processing
            results.append((pattern, 'PROCESSED'))
    
    return results, matches

def process_pattern_batch(patterns):
    """Process a batch of patterns - wrapper for backward compatibility."""
    return process_pattern_chunk(patterns)

def process_pattern(pattern):
    """Single pattern wrapper for backward compatibility."""
    results, matches = process_pattern_chunk([pattern])
    
    # Write matches immediately for single pattern processing
    if matches:
        with open(MATCHES_FILE, 'a', newline='') as mf:
            writer = csv.writer(mf)
            for pattern_key, addr, priv_int, wif_c, wif_un in matches:
                writer.writerow([pattern_key, addr, hex(priv_int), wif_c, wif_un])
    
    return results[0] if results else (pattern, 'ERROR')

def chunk_generator(generator, chunk_size):
    """Convert a generator into chunks of specified size."""
    chunk = []
    for item in generator:
        chunk.append(item)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:  # yield remaining items
        yield chunk


# -----------------------------------------------------------------------------
# SEQUENTIAL KEY GENERATOR + PROGRESS MONITOR (single-line status)
# -----------------------------------------------------------------------------

def sequential_generator(start_int: int):
    """Yield 64-hex private keys sequentially starting from start_int."""
    i = start_int
    while not shutdown_requested and i <= SECP256K1_MAX:
        yield f"{i:064x}"
        i += 1


def monitor(start_t):
    last_len = 0
    while True:
        time.sleep(5)
        g = generated_cnt.value
        c = compared_cnt.value
        rate = g / (time.time() - start_t) if g else 0

        # Show matches count from a cached counter instead of reading file
        matches = getattr(monitor, 'matches_count', 0)

        # Build status line and render in-place
        try:
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            memory_percent = process.memory_percent()
            cpu_percent = process.cpu_percent()
            status = (
                f"[{time.strftime('%H:%M:%S')}] "
                f"Gen={g:,}  Cmp={c:,}  Rate={rate:.1f}/s  Matches={matches}  "
                f"Mem={memory_mb:.1f}MB ({memory_percent:.1f}%)  CPU={cpu_percent:.1f}%"
            )
        except:
            status = (
                f"[{time.strftime('%H:%M:%S')}] Gen={g:,}  Cmp={c:,}  Rate={rate:.1f}/s  Matches={matches}"
            )

        pad = max(0, last_len - len(status))
        sys.stdout.write("\r" + status + (" " * pad))
        sys.stdout.flush()
        last_len = len(status)


# -----------------------------------------------------------------------------
# MAIN - MEMORY-EFFICIENT CHUNKED PROCESSING
# -----------------------------------------------------------------------------
def run_pattern_mode():
    # Load pattern generator, total count, and filtered config
    pattern_gen, total_patterns, filtered_config = load_patterns_and_config()
    
    print(f"Total patterns to process: {total_patterns:,}")
    
    # Check if this is a huge number that might cause issues
    if total_patterns > 1_000_000:
        print(f"WARNING: Processing {total_patterns:,} patterns. This may take a very long time!")
        print("Consider reducing the pattern complexity or using smaller character sets.")
        response = input("Continue? (y/N): ").strip().lower()
        if response != 'y':
            print("Aborted by user.")
            return

    # Resume: load last processed pattern and skip up to that point
    last_processed_pattern = None
    if os.path.exists(RESUME_FILE):
        with open(RESUME_FILE) as f:
            content = f.read().strip()
            if content:
                # Allow formats:
                #  - "<pattern>" (legacy)
                #  - "<pattern>\t<addr1,addr2,...>" (new)
                lines = [l.strip() for l in content.splitlines() if l.strip()]
                last_line = lines[-1] if lines else ''
                last_processed_pattern = last_line.split()[0] if last_line else None
        print(f"Resuming from last processed pattern: {last_processed_pattern}")

    # Filter out already processed patterns using generator
    def filtered_pattern_gen():
        found_resume_point = last_processed_pattern is None  # If no resume file, start from beginning
        for pattern in pattern_gen:
            if not found_resume_point:
                if pattern == last_processed_pattern:
                    found_resume_point = True
                continue  # Skip patterns until we find the resume point
            yield pattern
    
    # Prepare LMDB
    init_lmdb()
    
    # Initialize matches file with header if it doesn't exist
    if not os.path.exists(MATCHES_FILE):
        with open(MATCHES_FILE, 'w', newline='') as mf:
            writer = csv.writer(mf)
            writer.writerow(['Pattern', 'Address', 'Private_Key_Hex', 'WIF_Compressed', 'WIF_Uncompressed'])

    mgr = Manager()
    global generated_cnt, compared_cnt
    generated_cnt = mgr.Value('L', 0)
    compared_cnt  = mgr.Value('L', 0)
    
    # Initialize matches counter for monitor
    monitor.matches_count = 0

    start = time.time()
    # Spawn monitor thread
    thr = Thread(target=monitor, args=(start,), daemon=True)
    thr.start()

    # Chunked processing to avoid memory issues
    # Much larger chunk sizes for better performance
    available_memory_gb = psutil.virtual_memory().available / (1024**3)
    if available_memory_gb < 2:
        CHUNK_SIZE = 100  # Minimum chunk size
        print(f"Low memory detected ({available_memory_gb:.1f}GB available). Using smaller chunk size.")
    elif available_memory_gb < 4:
        CHUNK_SIZE = 500  # Medium chunk size
    elif available_memory_gb < 8:
        CHUNK_SIZE = 1000  # Large chunk size
    else:
        CHUNK_SIZE = 2000  # Very large chunk size for maximum performance
    
    # Calculate how many patterns we've already processed
    patterns_processed = 0
    if last_processed_pattern:
        # Count patterns up to the last processed one
        temp_count = 0
        for pattern in pattern_generator(filtered_config):
            temp_count += 1
            if pattern == last_processed_pattern:
                patterns_processed = temp_count
                break
    
    remaining_patterns = total_patterns - patterns_processed
    
    if remaining_patterns <= 0:
        print("Nothing new to do – all patterns already processed.")
        return
    
    print(f"Processing {remaining_patterns:,} remaining patterns in chunks of {CHUNK_SIZE}...")
    print(f"Available memory: {available_memory_gb:.1f}GB")
    
    # Optimize pool for maximum performance
    pool = Pool(
        processes=workers_gen,
        maxtasksperchild=1000  # Restart workers periodically to prevent memory leaks
    )
    processed_patterns = []
    all_matches = []
    
    # Optimized processing with reduced disk I/O
    chunk_count = 0
    last_resume_write = 0
    last_state_write = 0
    last_pattern_in_chunk = None
    
    # Use imap for parallel processing instead of apply
    chunk_iter = chunk_generator(filtered_pattern_gen(), CHUNK_SIZE)
    
    try:
        # Process patterns in chunks using parallel imap
        for batch_results, batch_matches in pool.imap(process_pattern_chunk, chunk_iter):
            # Check for shutdown signal
            if shutdown_requested:
                print("Shutdown requested. Stopping pattern processing...")
                break
                
            chunk_count += 1
            
            # Process all patterns in chunk (including invalid ones)
            chunk_last_pattern = None
            for pattern, status in batch_results:
                patterns_processed += 1
                chunk_last_pattern = pattern  # Keep track of the last pattern in this chunk
            
            # Update the global last pattern
            if chunk_last_pattern:
                last_pattern_in_chunk = chunk_last_pattern
            
            # Write resume file only every 1000 patterns (not every chunk!)
            current_time = time.time()
            if last_pattern_in_chunk and (patterns_processed - last_resume_write >= 100000):
                with open(RESUME_FILE, 'w') as rf:
                    rf.write(make_resume_line(last_pattern_in_chunk))
                last_resume_write = patterns_processed
            
            # Update state file only every 5000 patterns (not every 100!)
            if patterns_processed - last_state_write >= 5000:
                with open(LAST_STATE_FILE, 'w') as ls:
                    json.dump({
                        'last_pattern': last_pattern_in_chunk, 
                        'status': 'PROCESSING',
                        'progress': f"{patterns_processed}/{total_patterns}",
                        'timestamp': current_time
                    }, ls)
                last_state_write = patterns_processed
            
            # Collect matches and update counter
            if batch_matches:
                all_matches.extend(batch_matches)
                monitor.matches_count += len(batch_matches)
            
            # Write matches immediately to ensure durability (higher I/O)
            if len(all_matches) >= 1:
                with open(MATCHES_FILE, 'a', newline='') as mf:
                    writer = csv.writer(mf)
                    for pattern_key, addr, priv_int, wif_c, wif_un in all_matches:
                        writer.writerow([pattern_key, addr, hex(priv_int), wif_c, wif_un])
                all_matches.clear()
            
            # Reduced garbage collection frequency (every 1000 chunks)
            if chunk_count % 1000 == 0:
                gc.collect()
        
        pool.close()
        pool.join()
        
        # Write any remaining data
        if last_pattern_in_chunk:
            with open(RESUME_FILE, 'w') as rf:
                rf.write(make_resume_line(last_pattern_in_chunk))
        
        if all_matches:
            with open(MATCHES_FILE, 'a', newline='') as mf:
                writer = csv.writer(mf)
                for pattern_key, addr, priv_int, wif_c, wif_un in all_matches:
                    writer.writerow([pattern_key, addr, hex(priv_int), wif_c, wif_un])
        
        # Final state update
        with open(LAST_STATE_FILE, 'w') as ls:
            json.dump({
                'last_pattern': last_pattern_in_chunk, 
                'status': 'COMPLETED' if not shutdown_requested else 'STOPPED',
                'progress': f"{patterns_processed}/{total_patterns}",
                'timestamp': time.time()
            }, ls)
        
        if shutdown_requested:
            print(f"\nProcessing stopped by user request.")
            print(f"Total patterns processed: {patterns_processed:,}")
        else:
            print(f"\nProcessing completed successfully!")
            print(f"Total patterns processed: {patterns_processed:,}")
        
    except Exception as e:
        print(f"\n\nUnexpected error occurred: {e}")
        print("Shutting down gracefully...")
        pool.terminate()
        pool.join()
        
        # Save any remaining matches
        if all_matches:
            with open(MATCHES_FILE, 'a', newline='') as mf:
                writer = csv.writer(mf)
                for pattern_key, addr, priv_int, wif_c, wif_un in all_matches:
                    writer.writerow([pattern_key, addr, hex(priv_int), wif_c, wif_un])
        
        print(f"Saved progress: {patterns_processed:,} patterns processed before error")
        raise

    elapsed = time.time() - start
    
    # Create final matches summary
    create_final_matches_summary()
    
    print("\n=== Final Report ===")
    print(f"Total patterns processed: {patterns_processed:,}")
    print(f"Total BTC addresses generated: {generated_cnt.value:,}")
    print(f"Total BTC addresses compared: {compared_cnt.value:,}")
    print(f"Elapsed time: {elapsed:.1f}s")
    print(f"Avg rate: {generated_cnt.value/elapsed:.1f} addresses/sec")
    
    # Count matches
    match_count = 0
    if os.path.exists(MATCHES_FILE):
        with open(MATCHES_FILE, 'r') as f:
            lines = [line for line in f if line.strip()]
            match_count = max(0, len(lines) - 1)  # Subtract 1 for header
    
    print(f"Total matches found: {match_count}")
    if match_count > 0:
        print(f"Matches saved in: {MATCHES_FILE}")

def create_final_matches_summary():
    """Create a final summary of all matches found."""
    if not os.path.exists(MATCHES_FILE):
        return
    
    matches = []
    try:
        with open(MATCHES_FILE, 'r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader, None)  # Skip header row
            for row in reader:
                if len(row) >= 3:
                    matches.append(row)
    except:
        return
    
    if not matches:
        return
    
    # Create final summary file
    summary_file = 'final_matches_summary.txt'
    with open(summary_file, 'w') as f:
        f.write("=== BITCOIN PATTERN SCANNER - FINAL MATCHES SUMMARY ===\n")
        f.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total matches found: {len(matches)}\n\n")
        
        for i, (pattern, address, private_key_hex) in enumerate(matches, 1):
            f.write(f"Match #{i}:\n")
            f.write(f"  Pattern: {pattern}\n")
            f.write(f"  Address: {address}\n")
            f.write(f"  Private Key: {private_key_hex}\n")
            try:
                f.write(f"  Private Key (decimal): {int(private_key_hex, 16)}\n")
            except ValueError:
                f.write(f"  Private Key (decimal): [Invalid hex format]\n")
            f.write("\n")
    
    print(f"Final matches summary saved to: {summary_file}")


def run_sequential_mode(start_hex: str | None = None):
    """Sequential generation mode: derive and check keys consecutively."""
    # Prepare LMDB
    init_lmdb()

    # Initialize matches file with header if it doesn't exist
    if not os.path.exists(MATCHES_FILE):
        with open(MATCHES_FILE, 'w', newline='') as mf:
            writer = csv.writer(mf)
            writer.writerow(['Pattern', 'Address', 'Private_Key_Hex', 'WIF_Compressed', 'WIF_Uncompressed'])

    # Determine starting key
    start_int = None
    chosen = None
    if start_hex:
        try:
            start_int = int(start_hex, 16)
            chosen = 'INPUT'
        except ValueError:
            print('Invalid starting key provided. It must be 64-hex. Falling back...')
    if start_int is None and os.path.exists(LAST_SEQ_FILE):
        try:
            with open(LAST_SEQ_FILE, 'r') as f:
                last_hex = f.read().strip().split()[0]
                start_int = int(last_hex, 16)
                chosen = 'LAST_SAVED'
        except Exception:
            start_int = None
    if start_int is None:
        # Random in [1, N-1]
        start_int = secrets.randbelow(SECP256K1_MAX) + 1
        chosen = 'RANDOM'

    if not (SECP256K1_MIN <= start_int <= SECP256K1_MAX):
        print('Starting key out of secp256k1 range. Aborting.')
        return

    print(f"Sequential mode: starting from {start_int:064x} ({chosen})")

    mgr = Manager()
    global generated_cnt, compared_cnt
    generated_cnt = mgr.Value('L', 0)
    compared_cnt = mgr.Value('L', 0)

    monitor.matches_count = 0
    start = time.time()
    thr = Thread(target=monitor, args=(start,), daemon=True)
    thr.start()

    available_memory_gb = psutil.virtual_memory().available / (1024**3)
    if available_memory_gb < 2:
        CHUNK_SIZE = 100
    elif available_memory_gb < 4:
        CHUNK_SIZE = 500
    elif available_memory_gb < 8:
        CHUNK_SIZE = 1000
    else:
        CHUNK_SIZE = 2000

    pool = Pool(processes=workers_gen, maxtasksperchild=1000)

    patterns_processed = 0
    chunk_count = 0
    last_state_write = 0
    last_key_in_chunk = None

    gen = sequential_generator(start_int)
    chunk_iter = chunk_generator(gen, CHUNK_SIZE)

    all_matches = []

    try:
        for batch_results, batch_matches in pool.imap(process_pattern_chunk, chunk_iter):
            if shutdown_requested:
                print("Shutdown requested. Stopping sequential processing...")
                break

            chunk_count += 1
            for pattern, status in batch_results:
                patterns_processed += 1
                last_key_in_chunk = pattern

            # Persist last key every 1000 processed
            if last_key_in_chunk and (patterns_processed - last_state_write >= 1000):
                with open(LAST_SEQ_FILE, 'w') as f:
                    f.write(last_key_in_chunk + "\n")
                with open(LAST_STATE_FILE, 'w') as ls:
                    json.dump({
                        'mode': 'SEQUENTIAL',
                        'last_key': last_key_in_chunk,
                        'status': 'PROCESSING',
                        'processed': patterns_processed,
                        'timestamp': time.time()
                    }, ls)
                last_state_write = patterns_processed

            if batch_matches:
                all_matches.extend(batch_matches)
                monitor.matches_count += len(batch_matches)

            if len(all_matches) >= 1:
                with open(MATCHES_FILE, 'a', newline='') as mf:
                    writer = csv.writer(mf)
                    for pattern_key, addr, priv_int, wif_c, wif_un in all_matches:
                        writer.writerow([pattern_key, addr, hex(priv_int), wif_c, wif_un])
                all_matches.clear()

            if chunk_count % 1000 == 0:
                gc.collect()

        pool.close()
        pool.join()

        if last_key_in_chunk:
            with open(LAST_SEQ_FILE, 'w') as f:
                f.write(last_key_in_chunk + "\n")
        
        if all_matches:
            with open(MATCHES_FILE, 'a', newline='') as mf:
                writer = csv.writer(mf)
                for pattern_key, addr, priv_int, wif_c, wif_un in all_matches:
                    writer.writerow([pattern_key, addr, hex(priv_int), wif_c, wif_un])

        with open(LAST_STATE_FILE, 'w') as ls:
            json.dump({
                'mode': 'SEQUENTIAL',
                'last_key': last_key_in_chunk,
                'status': 'COMPLETED' if not shutdown_requested else 'STOPPED',
                'processed': patterns_processed,
                'timestamp': time.time()
            }, ls)

        if shutdown_requested:
            print(f"\nProcessing stopped by user request.")
        else:
            print(f"\nSequential processing finished (pool drained).")

    except Exception as e:
        print(f"\n\nUnexpected error occurred: {e}")
        print("Shutting down gracefully...")
        pool.terminate()
        pool.join()
        if all_matches:
            with open(MATCHES_FILE, 'a', newline='') as mf:
                writer = csv.writer(mf)
                for pattern_key, addr, priv_int, wif_c, wif_un in all_matches:
                    writer.writerow([pattern_key, addr, hex(priv_int), wif_c, wif_un])
        print(f"Saved progress: {patterns_processed:,} keys processed before error")
        raise

    elapsed = time.time() - start
    print("\n=== Final Report (Sequential) ===")
    print(f"Total BTC addresses generated: {generated_cnt.value:,}")
    print(f"Total BTC addresses compared: {compared_cnt.value:,}")
    print(f"Elapsed time: {elapsed:.1f}s")
    if elapsed > 0:
        print(f"Avg rate: {generated_cnt.value/elapsed:.1f} addresses/sec")


def main():
    print("Select generation mode:")
    print("  1) Pattern-based (from patterns.txt)")
    print("  2) Sequential keys (start from input/last-saved/random)")
    choice = input("Enter choice [1/2] (default 1): ").strip()

    if choice == '2':
        print("Sequential mode selected.")
        user_start = input("Enter starting private key (64-hex) or press Enter: ").strip()
        if user_start == '':
            user_start = None
        run_sequential_mode(user_start)
    else:
        print("Pattern mode selected.")
        print("Pattern mode: generates keys from patterns.txt blocks. Supported:")
        print("- octal: eight hex chars, each repeated 8× in sequence")
        print("- sequence_4x16: 4-symbol sequence repeated 16×")
        run_pattern_mode()


if __name__ == "__main__":
    main()
