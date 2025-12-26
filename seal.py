#!/usr/bin/env python3

import os
import sys
import argparse
import base64
import hashlib
import secrets
import redis
from pathlib import Path
from getpass import getpass
from cryptography.fernet import Fernet

# Redis connection
REDIS_HOST = os.getenv("SOFT_SEAL_REDIS_HOST", "redis_db")
REDIS_PORT = int(os.getenv("SOFT_SEAL_REDIS_PORT", "6379"))

# Redis keys
REDIS_SALT_KEY = "soft_seal:salt"
REDIS_TOKEN_KEY = "soft_seal:token"

# PBKDF2 parameters
PBKDF2_ITERATIONS = 200_000
PBKDF2_KEYLEN = 32  # bytes


# ---------- Machine ID handling ----------

FALLBACK_PATH = Path("/var/lib/myapp/app-machine-id")

def read_machine_id() -> bytes:

    candidates = [
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
    ]

    # Try OS-provided machine IDs
    for path in candidates:
        try:
            if os.path.exists(path):
                raw = open(path, "r", encoding="utf-8").read().strip()
                if raw and not all(c == "0" for c in raw) and len(raw) >= 8:
                    return raw.encode("utf-8")
        except OSError:
            continue

    # FALLBACK: persistent random ID
    FALLBACK_PATH.parent.mkdir(parents=True, exist_ok=True)

    if FALLBACK_PATH.exists():
        return FALLBACK_PATH.read_bytes()

    rnd = secrets.token_bytes(32)
    FALLBACK_PATH.write_bytes(rnd)
    os.chmod(FALLBACK_PATH, 0o600)

    return rnd


# ---------- Key derivation & crypto ----------

def derive_key(machine_id: bytes, salt: bytes) -> bytes:

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        machine_id,
        salt,
        PBKDF2_ITERATIONS,
        dklen=PBKDF2_KEYLEN,
    )

    return base64.urlsafe_b64encode(dk)


def encrypt_secret(secret: bytes, machine_id: bytes, salt: bytes) -> str:

    key = derive_key(machine_id, salt)

    f = Fernet(key)
    token = f.encrypt(secret)  # returns a byte object

    return token.decode("utf-8")


def decrypt_secret(token: str, machine_id: bytes, salt: bytes) -> bytes:

    key = derive_key(machine_id, salt)
    f = Fernet(key)
    return f.decrypt(token.encode("utf-8"))


# ---------- Redis helpers ----------

def get_redis_client() -> redis.Redis:

    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=False,
    )


def redis_has_secret(r: redis.Redis):

    return r.exists(REDIS_SALT_KEY) and r.exists(REDIS_TOKEN_KEY)


def save_secret(r: redis.Redis, salt: bytes, token: str) -> None:

    salt_b64 = base64.b64encode(salt)

    pipe = r.pipeline()
    pipe.set(REDIS_SALT_KEY, salt_b64)
    pipe.set(REDIS_TOKEN_KEY, token.encode("utf-8"))
    pipe.execute()


def load_secret(r: redis.Redis):

    salt_b64 = r.get(REDIS_SALT_KEY)
    token_bytes = r.get(REDIS_TOKEN_KEY)

    if salt_b64 is None or token_bytes is None:
        raise RuntimeError("No secret stored in Redis for soft_seal.")

    salt = base64.b64decode(salt_b64)
    token = token_bytes.decode("utf-8")
    return salt, token


# ---------- Commands ----------

def cmd_init(args):
    """
    Initialize the sealed secret:
    - Prompt user for a secret (hidden input)
    - Generate salt
    - Encrypt with host-bound derived key
    - Save to Redis
    """

    r = get_redis_client()

    if redis_has_secret(r) and not args.force:
        print(
            "A secret is already stored in Redis. Use --force to overwrite.",
            file=sys.stderr,
        )
        sys.exit(1)

    s1 = getpass("Enter secret to seal: ")
    s2 = getpass("Confirm secret: ")

    if s1 != s2:
        print("Secrets do not match. Aborting.", file=sys.stderr)
        sys.exit(1)

    if not s1:
        print("Empty secret is not allowed. Aborting.", file=sys.stderr)
        sys.exit(1)

    secret_bytes = s1.encode("utf-8")
    salt = os.urandom(16)  # 128-bit salt

    try:
        machine_id = read_machine_id()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    token = encrypt_secret(secret_bytes, machine_id, salt)
    save_secret(r, salt, token)

    print("Secret sealed and stored successfully.")


def cmd_show(args):
    """
    Decrypt and show the stored secret.
    """

    r = get_redis_client()

    try:
        salt, token = load_secret(r)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        machine_id = read_machine_id()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        secret = decrypt_secret(token, machine_id, salt)
    except Exception as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(2)

    print("Restored secret:")
    print(secret.decode("utf-8"))


# ---------- Library ----------

def get_unsealed_secret() -> str:
    """
    Fetch and decrypt the stored secret using the host-bound key.

    This is the function your application code should call at startup.

    Raises:
        RuntimeError: if there is no stored secret, or machine-id is invalid.
        Exception: if decryption fails for any reason (e.g., moved to new host).
    """

    r = get_redis_client()

    # Load salt + token from Redis
    salt, token = load_secret(r)

    # Rebuild derived key from local machine-id + salt
    machine_id = read_machine_id()

    # Decrypt
    secret_bytes = decrypt_secret(token, machine_id, salt)
    return secret_bytes.decode("utf-8")


# ---------- CLI ----------

def build_arg_parser():

    parser = argparse.ArgumentParser(
        description="Soft Seal: host-bound secret sealing demo using Redis."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ----------------

    p_init = sub.add_parser(
        "init",
        help="Seal and store a new secret (interactive prompt).",
    )
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing secret if present.",
    )
    p_init.set_defaults(func=cmd_init)

    # ----------------

    p_show = sub.add_parser(
        "show",
        help="Decrypt and print the stored secret.",
    )
    p_show.set_defaults(func=cmd_show)

    return parser


def main():

    parser = build_arg_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":

    main()
