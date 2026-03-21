"""
/api/crypto/dhke  —  Diffie-Hellman Key Exchange endpoints.

Wraps crypto_systems.src.dhke — layout on disk:

    crypto_api/
    ├── crypto_systems/
    │   ├── common/
    │   │   └── types.py     ← DHKEPrivateKey(x, p, g, group), etc.
    │   └── src/
    │       └── dhke.py      ← generate_key_pair / compute_shared_secret / derive_key

DHKE interactive flow
---------------------
1. POST /keypair          → Alice keypair
2. POST /keypair          → Bob   keypair
3. POST /shared_secret    → Alice: private_key fields + Bob's public y
4. POST /shared_secret    → Bob:   private_key fields + Alice's public y
5. POST /derive_key       → both derive identical AES key bytes
"""
import base64
import os
import sys

_HERE      = os.path.dirname(os.path.abspath(__file__))        # api/routers/
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, "..", "..")) # crypto_api/

if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Literal

# crypto_systems.src.dhke — functions use snake_case with underscore
from crypto_systems.src.dhke import (
    generate_key_pair,
    compute_shared_secret,
    derive_key,
)
# types: x / y / group / secret  (NOT value / bits)
from common.types import (
    DHKEPrivateKey,
    DHKEPublicKey,
    DHKESharedSecret,
)
from common.exceptions import (
    InvalidParameterError,
    InvalidKeyError,
    KeyGenerationError,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

VALID_GROUPS = ("modp2048", "modp3072", "modp4096")

class KeypairRequest(BaseModel):
    group: Literal["modp2048", "modp3072", "modp4096"] = "modp2048"

class PrivateKeyOut(BaseModel):
    x: str          # decimal string — keep secret
    p: str
    g: str
    group: str

class PublicKeyOut(BaseModel):
    y: str          # decimal string — share with peer
    y_hex: str      # same value in hex — easier to read
    p: str
    g: str
    group: str

class KeypairResponse(BaseModel):
    group: str
    private_key: PrivateKeyOut
    public_key: PublicKeyOut

class SharedSecretRequest(BaseModel):
    # Your private key (from /keypair)
    private_x:     str
    private_p:     str
    private_g:     str = "2"
    private_group: Literal["modp2048", "modp3072", "modp4096"] = "modp2048"
    # Peer's public value (public_key.y from their /keypair)
    peer_y: str

class SharedSecretResponse(BaseModel):
    group: str
    secret: str         # decimal
    secret_hex: str     # hex (truncated for display)
    secret_bits: int

class DeriveKeyRequest(BaseModel):
    secret:       str           # decimal or 0x hex — from /shared_secret
    secret_group: Literal["modp2048", "modp3072", "modp4096"] = "modp2048"
    length:       int = 32      # bytes; 1–64

class DeriveKeyResponse(BaseModel):
    length:  int
    key_hex: str
    key_b64: str

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _int(s: str, name: str) -> int:
    try:
        return int(s, 0)
    except (ValueError, TypeError):
        raise HTTPException(400, f"'{name}' is not a valid integer: {s!r}")

def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (InvalidParameterError, InvalidKeyError) as e:
        raise HTTPException(400, str(e))
    except KeyGenerationError as e:
        raise HTTPException(500, str(e))

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/keypair", response_model=KeypairResponse,
             summary="Generate a DHKE key pair (RFC 3526 MODP group)")
def keypair(body: KeypairRequest):
    """
    Generate a fresh key pair.  Run **twice** — once for Alice, once for Bob.

    Keep `private_key.x` secret.  Share `public_key.y` with your peer.
    """
    kp   = _call(generate_key_pair, body.group)
    priv = kp.private_key
    pub  = kp.public_key
    return KeypairResponse(
        group=body.group,
        private_key=PrivateKeyOut(
            x=str(priv.x), p=str(priv.p), g=str(priv.g), group=priv.group,
        ),
        public_key=PublicKeyOut(
            y=str(pub.y), y_hex=hex(pub.y),
            p=str(pub.p), g=str(pub.g), group=pub.group,
        ),
    )


@router.post("/shared_secret", response_model=SharedSecretResponse,
             summary="Compute shared secret: g^(xy) mod p")
def shared_secret(body: SharedSecretRequest):
    """
    Both parties compute the same value independently.

    Pass **your** private key fields and **the peer's** `public_key.y`.
    """
    priv = DHKEPrivateKey(
        x     = _int(body.private_x, "private_x"),
        p     = _int(body.private_p, "private_p"),
        g     = _int(body.private_g, "private_g"),
        group = body.private_group,
    )
    peer = DHKEPublicKey(
        y     = _int(body.peer_y, "peer_y"),
        p     = priv.p,
        g     = priv.g,
        group = body.private_group,
    )
    ss = _call(compute_shared_secret, priv, peer)
    return SharedSecretResponse(
        group       = ss.group,
        secret      = str(ss.secret),
        secret_hex  = hex(ss.secret),
        secret_bits = ss.secret.bit_length(),
    )


@router.post("/derive_key", response_model=DeriveKeyResponse,
             summary="Derive symmetric key bytes from the shared secret")
def derive(body: DeriveKeyRequest):
    """
    SHA-256 KDF over the shared secret integer.
    Default 32 bytes = AES-256 key.  Both sides get identical output.
    """
    if not (1 <= body.length <= 64):
        raise HTTPException(400, "length must be between 1 and 64 bytes")

    ss  = DHKESharedSecret(
        secret = _int(body.secret, "secret"),
        group  = body.secret_group,
    )
    key = _call(derive_key, ss, body.length)
    return DeriveKeyResponse(
        length  = body.length,
        key_hex = key.hex(),
        key_b64 = base64.b64encode(key).decode(),
    )