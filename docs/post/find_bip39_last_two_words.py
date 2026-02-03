#!/usr/bin/env python3
"""
find_bip39_last_two_words.py

Usage:
  1) Quick: python3 find_bip39_last_two_words.py "word1 word2 ... word10"
  2) Interactive: python3 find_bip39_last_two_words.py
     (you'll be prompted to paste the 10 words)

This script uses the python-mnemonic library to validate BIP-39 checksums and derive Tron addresses.
It brute-forces valid word11+word12 pairs for fixed first 10 words, generating ~262k full mnemonics
and their first addresses (path m/44'/195'/0'/0/0). Expect 30-90 min runtime for derivations.

SECURITY: Run offline on a trusted machine. Do NOT paste your full 12-word seed anywhere public.
"""

import sys
import hashlib
import hmac
from ecdsa import SigningKey, SECP256k1
import base58

def require_mnemonic():
    try:
        from mnemonic import Mnemonic
        return Mnemonic
    except Exception as e:
        print("ERROR: python-mnemonic not found.")
        print("Install with: sudo apt install python3-mnemonic")
        sys.exit(1)

def load_wordlist():
    Mnemonic = require_mnemonic()
    mnemo = Mnemonic("english")
    return mnemo, mnemo.wordlist

def validate_words_in_wordlist(words, wordlist):
    invalid = [w for w in words if w not in wordlist]
    if invalid:
        print(f"WARNING: These words are not in the BIP-39 English wordlist: {invalid}")
        print("Correct them before proceeding.")
        return False
    return True

def get_input_words_from_args_or_prompt():
    if len(sys.argv) >= 2:
        candidate = " ".join(sys.argv[1:])
        words = candidate.strip().split()
    else:
        print("Enter your first 10 BIP-39 words (separated by spaces).")
        s = input("10 words: ").strip()
        # Normalize multiple spaces
        s = ' '.join(s.split())
        words = s.split()
    if len(words) != 10:
        print(f"Expected 10 words, got {len(words)}. Words: {words}")
        sys.exit(1)
    return words

def find_valid_last_words(first_11_words, wordlist, mnemo):
    first_11_joined = " ".join(first_11_words)
    candidates = []
    for w in wordlist:
        full = f"{first_11_joined} {w}"
        if mnemo.check(full):
            candidates.append(w)
    return candidates

def derive_hardened(priv_bytes, chain_bytes, index):
    hardened_index = index | 0x80000000
    data = b'\x00' + priv_bytes + hardened_index.to_bytes(4, 'big')
    I = hmac.new(chain_bytes, data, hashlib.sha512).digest()
    il_int = int.from_bytes(I[:32], 'big')
    priv_int = int.from_bytes(priv_bytes, 'big')
    order = SECP256k1.order
    new_priv_int = (il_int + priv_int) % order
    new_priv = new_priv_int.to_bytes(32, 'big')
    new_chain = I[32:]
    return new_priv, new_chain

def derive_nonhard(priv_bytes, chain_bytes, index):
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    pub_comp = vk.to_string("compressed")
    data = pub_comp + index.to_bytes(4, 'big')
    I = hmac.new(chain_bytes, data, hashlib.sha512).digest()
    il_int = int.from_bytes(I[:32], 'big')
    priv_int = int.from_bytes(priv_bytes, 'big')
    order = SECP256k1.order
    new_priv_int = (il_int + priv_int) % order
    new_priv = new_priv_int.to_bytes(32, 'big')
    new_chain = I[32:]
    return new_priv, new_chain

def derive_path(seed):
    # Master key
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    priv = I[:32]
    chain = I[32:]
    # Path: m/44'/195'/0'/0/0
    path = [(44, True), (195, True), (0, True), (0, False), (0, False)]
    for idx, is_hardened in path:
        if is_hardened:
            priv, chain = derive_hardened(priv, chain, idx)
        else:
            priv, chain = derive_nonhard(priv, chain, idx)
    return priv

def private_key_to_tron_address(priv_bytes):
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    pub_bytes = vk.to_string("uncompressed")[1:]
    keccak = hashlib.sha3_256(pub_bytes).digest()
    addr_hash = keccak[-20:]
    payload = b"\x41" + addr_hash
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

def main():
    first_10 = get_input_words_from_args_or_prompt()
    
    # Load wordlist and validate input words
    mnemo, wordlist = load_wordlist()
    if not validate_words_in_wordlist(first_10, wordlist):
        sys.exit(1)
    
    print("\n[!] Running checksum-validation for last two words... (this runs locally)\n")
    print("This will take ~30-60s to find all ~262k candidates, then ~30-90min to derive addresses.\n")
    
    candidates = []  # List of (w11, w12) tuples
    for i, w11 in enumerate(wordlist):
        prefix_11 = first_10 + [w11]
        temp_candidates = find_valid_last_words(prefix_11, wordlist, mnemo)
        for w12 in temp_candidates:
            candidates.append((w11, w12))
        if (i + 1) % 256 == 0 or i == len(wordlist) - 1:
            print(f"Processed {i+1}/2048 possible word11... Found {len(candidates)} valid pairs so far.")
    
    print(f"\nFound {len(candidates)} valid (word11, word12) pairs.\n")
    
    if len(candidates) == 0:
        print("No checksum-valid candidates found. Possible causes:")
        print(" - The mnemonic uses a different language/wordlist")
        print(" - There is a checksum mismatch in the 10 words")
        sys.exit(0)

    # Write full mnemonics and addresses to files
    output_file = "full_mnemonics.txt"
    addresses_file = "addresses.txt"
    first_10_joined = " ".join(first_10)
    with open(output_file, 'w') as f, open(addresses_file, 'w') as af:
        for j, (w11, w12) in enumerate(candidates):
            full_mnemonic = f"{first_10_joined} {w11} {w12}"
            seed = mnemo.to_seed(full_mnemonic)
            priv_key = derive_path(seed)
            address = private_key_to_tron_address(priv_key)
            f.write(full_mnemonic + "\n")
            f.write(address + "\n\n")
            af.write(address + "\n")
            
            if (j + 1) % 1024 == 0 or j == len(candidates) - 1:
                print(f"Derived {j+1}/{len(candidates)} addresses...")
    
    print(f"\nWrote {len(candidates)} full 12-word mnemonics with Tron addresses to {output_file}.")
    print(f"Wrote {len(candidates)} Tron addresses to {addresses_file}.")
    print("\n-- Files created --")
    print("Next steps (recommended):")
    print(" - Scan addresses.txt for your known address.")
    print(" - Cross-reference with full_mnemonics.txt to get the matching seed.")
    print(" - Import the matching mnemonic into TronLink to recover.")
    print("\nSecurity reminder: keep these files private and delete after use.")

if __name__ == "__main__":
    main()
