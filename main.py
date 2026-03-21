"""
crypto_api  —  main.py  (lives at the repo root)

    crypto_api/
    ├── main.py              ← this file
    ├── api/
    │   └── routers/
    ├── galoiscore/
    │   └── src/
    ├── crypto_systems/
    │   ├── common/
    │   └── src/
    └── requirements.txt

Run from crypto_api/:
    pip install fastapi uvicorn
    uvicorn main:app --reload

Docs → http://localhost:8000/docs
"""
import os
import sys

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))   # crypto_api/  (repo root)

# galois_core: from core.prime import PrimeField
_GALOIS_SRC = os.path.join(_HERE, "galoiscore", "src")

# crypto_systems has two import perspectives that must both work:
#
#   1. Our router does:  from crypto_systems.src.dhke import ...
#      → needs _HERE (repo root) on sys.path so `crypto_systems` is a top-level package
#
#   2. Inside crypto_systems/src/dhke.py the code does:  from common.types import ...
#      → needs crypto_systems/ itself on sys.path so `common` resolves as top-level
#        (this is the internal convention of that submodule)
_CS_PARENT  = _HERE                                    # for perspective 1
_CS_PACKAGE = os.path.join(_HERE, "crypto_systems")    # for perspective 2

for p in (_GALOIS_SRC, _CS_PARENT, _CS_PACKAGE):
    if p not in sys.path:
        sys.path.insert(0, p)

# ---------------------------------------------------------------------------
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import field, ecc, utils, dhke

app = FastAPI(
    title="crypto_api",
    description=(
        "Unified REST API over **galois_core** (prime-field arithmetic, ECC, "
        "number theory) and **crypto_systems** (DHKE, ECDH, ECDSA, RSA)."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(field.router, prefix="/api/field",       tags=["Prime Field"])
app.include_router(ecc.router,   prefix="/api/ecc",         tags=["ECC"])
app.include_router(utils.router, prefix="/api/utils",       tags=["Utilities"])
app.include_router(dhke.router,  prefix="/api/crypto/dhke", tags=["DHKE"])


@app.get("/", tags=["Meta"])
def root():
    return {
        "name": "crypto_api",
        "version": "0.1.0",
        "docs": "/docs",
        "galois_core":    ["/api/field", "/api/ecc", "/api/utils"],
        "crypto_systems": ["/api/crypto/dhke"],
    }