# -*- coding: utf-8 -*-
from client import OpenClawGenParkReceiptLedger

ledger = OpenClawGenParkReceiptLedger()

# 1. Create Receipts
leaves = []
for i in range(4):
    entry = {"receipt_id": f"tx_00{i+1}", "agent": "openclaw_agent", "action": "TOOL_INVOCATION", "result": "SUCCESS"}
    res = ledger.append_receipt_entry(entry)
    leaves.append(res["rfc6962_leaf_hash"])
    print(f"Leaf {i+1}: {res['rfc6962_leaf_hash'][:16]}... (HMAC: {res['hmac_signature'][:12]}...)")

# 2. Merkle Root
root_res = ledger.compute_merkle_root(leaves)
print(f"\nMerkle Root: {root_res['merkle_root']} (Depth: {root_res['tree_depth']})")

# 3. Audit Path Verification
proof = ledger.generate_and_verify_audit_path(leaf_index=2, leaf_hashes=leaves, expected_root=root_res["merkle_root"])
print(f"\nAudit Proof for Leaf #2:")
print(f"  Valid: {proof['is_cryptographically_valid']} (Path Length: {proof['audit_path_length']})")
