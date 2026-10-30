# -*- coding: utf-8 -*-
"""
OpenClaw GenPark Receipt Ledger - Merkle Mountain Range & RFC 6962 Proof-of-Execution Ledger
Standard Library only: hashlib, hmac, json, time, math, typing.
Generates canonical cryptographically signed execution receipts, builds RFC 6962 binary
Merkle trees, and produces compact logarithmic audit proofs for non-repudiation.
"""

import hashlib
import hmac
import json
import time
from typing import Dict, List, Any

class OpenClawGenParkReceiptLedger:
    def __init__(self, hmac_key: str = "openclaw_default_receipt_key"):
        self.hmac_key = hmac_key.encode("utf-8")

    def append_receipt_entry(self, entry_data: Dict[str, Any],
                             secret_key: str = None) -> Dict[str, Any]:
        """
        Creates a canonical JSON receipt entry with timestamp, HMAC-SHA256 signature,
        and RFC 6962 leaf hash: SHA256(0x00 || canonical_json).
        """
        key = secret_key.encode("utf-8") if secret_key else self.hmac_key
        canonical_str = json.dumps(entry_data, sort_keys=True, separators=(',', ':'))
        
        # HMAC-SHA256 Signature
        sig = hmac.new(key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

        # RFC 6962 Leaf Hash: prefix with 0x00
        leaf_input = b"\x00" + canonical_str.encode("utf-8")
        leaf_hash = hashlib.sha256(leaf_input).hexdigest()

        return {
            "receipt_id": entry_data.get("receipt_id", f"rcpt_{int(time.time()*1000)}"),
            "canonical_payload": canonical_str,
            "hmac_signature": sig,
            "rfc6962_leaf_hash": leaf_hash,
            "created_at": time.time()
        }

    def compute_merkle_root(self, leaf_hashes: List[str]) -> Dict[str, Any]:
        """
        Computes the binary Merkle tree root using RFC 6962 interior node hashing:
        Node = SHA256(0x01 || left_child || right_child)
        """
        if not leaf_hashes:
            return {"merkle_root": None, "tree_depth": 0, "total_leaves": 0}

        current_level = [bytes.fromhex(h) for h in leaf_hashes]
        depth = 0

        while len(current_level) > 1:
            depth += 1
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Carry forward odd leaf to maintain balance
                    right = left
                interior = hashlib.sha256(b"\x01" + left + right).digest()
                next_level.append(interior)
            current_level = next_level

        return {
            "merkle_root": current_level[0].hex(),
            "tree_depth": depth,
            "total_leaves": len(leaf_hashes)
        }

    def generate_and_verify_audit_path(self, leaf_index: int,
                                       leaf_hashes: List[str],
                                       expected_root: str) -> Dict[str, Any]:
        """
        Generates logarithmic inclusion audit path for leaf at leaf_index and verifies it.
        """
        if leaf_index < 0 or leaf_index >= len(leaf_hashes):
            return {"error": "Index out of range"}

        current_level = [bytes.fromhex(h) for h in leaf_hashes]
        target_idx = leaf_index
        audit_path = []

        while len(current_level) > 1:
            is_right_sibling = (target_idx % 2 == 0)
            sibling_idx = target_idx + 1 if is_right_sibling else target_idx - 1
            if sibling_idx >= len(current_level):
                sibling_idx = target_idx # duplicated leaf

            sibling_hash = current_level[sibling_idx].hex()
            direction = "RIGHT" if is_right_sibling else "LEFT"
            audit_path.append({"sibling_hash": sibling_hash, "direction": direction})

            # Move to parent level
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(hashlib.sha256(b"\x01" + left + right).digest())
            
            target_idx = target_idx // 2
            current_level = next_level

        # Local verification of audit path
        curr = bytes.fromhex(leaf_hashes[leaf_index])
        for step in audit_path:
            sib = bytes.fromhex(step["sibling_hash"])
            if step["direction"] == "RIGHT":
                curr = hashlib.sha256(b"\x01" + curr + sib).digest()
            else:
                curr = hashlib.sha256(b"\x01" + sib + curr).digest()

        is_valid = (curr.hex() == expected_root)

        return {
            "leaf_index": leaf_index,
            "target_leaf_hash": leaf_hashes[leaf_index],
            "audit_path_length": len(audit_path),
            "audit_path": audit_path,
            "computed_root": curr.hex(),
            "expected_root": expected_root,
            "is_cryptographically_valid": is_valid
        }
