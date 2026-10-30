# -*- coding: utf-8 -*-
import sys, json
from client import OpenClawGenParkReceiptLedger

client = OpenClawGenParkReceiptLedger()

TOOLS = [
    {
        "name": "append_receipt_entry",
        "description": "Generates HMAC-SHA256 signed canonical execution receipt and RFC 6962 leaf hash.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entry_data": {"type": "object"},
                "secret_key": {"type": "string"}
            },
            "required": ["entry_data"]
        }
    },
    {
        "name": "compute_merkle_root",
        "description": "Computes RFC 6962 binary Merkle tree root from a list of leaf hashes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "leaf_hashes": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["leaf_hashes"]
        }
    },
    {
        "name": "generate_and_verify_audit_path",
        "description": "Constructs and cryptographically verifies logarithmic inclusion proof for a given leaf.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "leaf_index": {"type": "integer"},
                "leaf_hashes": {"type": "array", "items": {"type": "string"}},
                "expected_root": {"type": "string"}
            },
            "required": ["leaf_index", "leaf_hashes", "expected_root"]
        }
    }
]

def handle_request(req):
    method = req.get("method")
    rid = req.get("id")
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    elif method == "tools/call":
        params = req.get("params", {})
        tname = params.get("name")
        args = params.get("arguments", {})
        if tname == "append_receipt_entry":
            res = client.append_receipt_entry(args["entry_data"], args.get("secret_key"))
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}}
        elif tname == "compute_merkle_root":
            res = client.compute_merkle_root(args["leaf_hashes"])
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}}
        elif tname == "generate_and_verify_audit_path":
            res = client.generate_and_verify_audit_path(args["leaf_index"], args["leaf_hashes"], args["expected_root"])
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": "Invalid Request"}}

def main():
    for line in sys.stdin:
        if not line.strip(): continue
        try:
            req = json.loads(line)
            resp = handle_request(req)
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
