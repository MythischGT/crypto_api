# 🔐 Crypto API

A unified, high-performance REST API built over two pure-Python cryptography libraries. 

This API serves as the backend engine for cryptographic operations, exposing endpoints for Prime Field arithmetic, Elliptic Curve validation, Number Theory utilities, and secure Key Exchanges.

## 🗂️ Repository Layout

The project relies on two core cryptographic libraries managed as Git submodules, wrapped by a modern FastAPI application.

```text
crypto_api/
├── galoiscore/          # Git submodule: Core Galois field & ECC primitives
├── crypto_systems/      # Git submodule: High-level cryptographic protocols
├── api/                 # FastAPI Application
│   └── routers/
│       ├── field.py     # /api/field        → GF(p) arithmetic
│       ├── ecc.py       # /api/ecc          → Elliptic Curve operations
│       ├── utils.py     # /api/utils        → Number theory (Primes, GCD)
│       └── dhke.py      # /api/crypto/dhke  → Diffie-Hellman Key Exchange
└── requirements.txt
└── main.py          # Application entry point