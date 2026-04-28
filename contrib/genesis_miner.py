#!/usr/bin/env python3
"""
Genesis block nonce miner for Soqucoin.
Uses scrypt hash to find valid nonce for genesis blocks after
CTxOut serialization format change (nVisibility + nAssetType fields).

Usage: Run on VPS with soqucoind compiled for nonce discovery.
"""
import subprocess
import sys
import json

# We'll use soqucoind -regtest -version to get regtest genesis (trivial)
# For harder networks, we need to let soqucoind mine them

print("This script assists genesis mining by using soqucoind's built-in miner.")
print("Run: soqucoind -stagenet -printtoconsole 2>&1 | grep 'mined!'")
print("The nonces will be printed to stdout.")
