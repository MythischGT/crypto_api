# crypto_api

Unified REST API over two pure-Python cryptography libraries.

## Repository layout

```
crypto_api/
├── galoiscore/          # git submodule — galois_core primitives
├── crypto_systems/      # git submodule — cryptographic protocols
├── api/
│   ├── main.py
│   └── routers/
│       ├── field.py     # /api/field   — GF(p) arithmetic
│       ├── ecc.py       # /api/ecc     — elliptic curves
│       ├── utils.py     # /api/utils   — number theory
│       └── dhke.py      # /api/crypto/dhke — Diffie-Hellman
└── requirements.txt
```

## Setup

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/youruser/crypto_api

pip install -r requirements.txt
uvicorn api.main:app --reload
```

Interactive docs → http://localhost:8000/docs

## DHKE flow

```
POST /api/crypto/dhke/keypair        {"bits": 2048}  → Alice keypair
POST /api/crypto/dhke/keypair        {"bits": 2048}  → Bob keypair
POST /api/crypto/dhke/shared_secret  {Alice priv + Bob pub}  → secret
POST /api/crypto/dhke/derive_key     {"secret": "...", "length": 32} → AES key
```