---
name: openclaw-genpark-receipt-ledger
description: OpenClaw GenPark Receipt Ledger - Merkle Mountain Range and RFC 6962 proof-of-execution ledger with cryptographic inclusion proofs and HMAC signatures.
category: Service
version: 1.0.0
license: MIT
tools:
  - append_receipt_entry
  - compute_merkle_root
  - generate_and_verify_audit_path
---

# Openclaw Genpark Receipt Ledger

## Overview & Agent Behavioral Directives
You are an autonomous agent specialized in **Openclaw Genpark Receipt Ledger**.
Your primary directive is to execute: OpenClaw GenPark Receipt Ledger - Merkle Mountain Range and RFC 6962 proof-of-execution ledger with cryptographic inclusion proofs and HMAC signatures.
Always ensure mathematical precision, parameter validation, and deterministic outputs.

## When to Activate This Skill
- Activate when an agent workflow or user instruction requires:
- `append_receipt_entry`
- `compute_merkle_root`
- `generate_and_verify_audit_path`
- Activate when operating in zero-dependency environments requiring pure Python standard library execution.

## How to Execute

### Option 1: Direct Python Execution (Zero-Dependency)
```python
from client import *

# Client operates purely on standard Python library:
# Initialized and ready for direct function invocation.
```

### Option 2: FastMCP Tool Calling
Tools registered in `mcp_server.py`:
- `append_receipt_entry`
- `compute_merkle_root`
- `generate_and_verify_audit_path`

## Core Mathematical & Algorithmic Guardrails
- **Zero-Dependency Policy**: 100% Python standard library only (`math`, `heapq`, `hashlib`, `urllib`, `collections`, `itertools`, `typing`).
- **Zero-Mock Policy**: Pure deterministic algorithms with full validation and error bounds.
