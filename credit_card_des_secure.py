
DES-CBC demo with PBKDF2-derived DES key + HMAC-SHA256 integrity,
JSON storage (records.json), and synthetic PAN generator.

Educational/demo use only. Do NOT use DES in production.
"""

import os
import json
import base64
import argparse
import getpass
import hmac
import hashlib
from Crypto.Cipher import DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256   # <-- use Crypto.Hash.SHA256 for PBKDF2

# ---------- Config ----------
KDF_ITER = 200_000
SALT_LEN = 16
DES_KEY_LEN = 8         # DES key bytes
HMAC_KEY_LEN = 32       # 256-bit HMAC key
IV_LEN = 8
STORAGE_FILE = "records.json"
# ----------------------------

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

# ---------- Luhn / synthetic PAN ----------
def luhn_checksum(number: str) -> int:
    digits = [int(d) for d in number]
    odd_sum = sum(digits[-1::-2])
    even_sum = 0
    for d in digits[-2::-2]:
        d2 = d*2
        even_sum += d2 if d2 < 10 else d2 - 9
    return (odd_sum + even_sum) % 10

def luhn_make(prefix="400000", length=16) -> str:
    body_len = length - len(prefix) - 1
    body = ''.join(str(int.from_bytes(get_random_bytes(1), 'big') % 10) for _ in range(body_len))
    partial = prefix + body
    check = (10 - luhn_checksum(partial + "0")) % 10
    return partial + str(check)

def luhn_validate(number: str) -> bool:
    try:
        return luhn_checksum(number) == 0
    except Exception:
        return False

# ---------- Key derivation ----------
def derive_keys(passphrase: str, salt: bytes = None):
    """
    Derive DES key (8 bytes) and HMAC key (32 bytes) from passphrase.
    If salt is None, a new random salt is generated and returned.
    """
    if salt is None:
        salt = get_random_bytes(SALT_LEN)
    # derive DES_KEY_LEN + HMAC_KEY_LEN bytes
    # Use Crypto.Hash.SHA256 as the hmac_hash_module (correct type)
    key_material = PBKDF2(passphrase.encode('utf-8'), salt, dkLen=DES_KEY_LEN + HMAC_KEY_LEN, count=KDF_ITER, hmac_hash_module=SHA256)
    des_key = key_material[:DES_KEY_LEN]
    hmac_key = key_material[DES_KEY_LEN:]
    return des_key, hmac_key, salt

# ---------- Encrypt / Decrypt ----------
def encrypt_pan(pan: str, passphrase: str):
    des_key, hmac_key, salt = derive_keys(passphrase, None)
    iv = get_random_bytes(IV_LEN)
    cipher = DES.new(des_key, DES.MODE_CBC, iv=iv)
    padded = pad(pan.encode('utf-8'), DES.block_size)
    ct = cipher.encrypt(padded)
    # Compute HMAC over salt||iv||ct
    mac = hmac.new(hmac_key, salt + iv + ct, hashlib.sha256).digest()
    payload = {
        "salt": b64(salt),
        "iv": b64(iv),
        "ct": b64(ct),
        "mac": b64(mac),
        "kdf_iter": KDF_ITER
    }
    return payload

def decrypt_pan(payload: dict, passphrase: str):
    salt = ub64(payload["salt"])
    iv = ub64(payload["iv"])
    ct = ub64(payload["ct"])
    mac = ub64(payload["mac"])
    des_key, hmac_key, _ = derive_keys(passphrase, salt)
    # verify HMAC
    expected = hmac.new(hmac_key, salt + iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError("HMAC verification failed — data tampered or wrong passphrase")
    cipher = DES.new(des_key, DES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ct)
    try:
        plain = unpad(padded, DES.block_size).decode('utf-8')
    except ValueError as e:
        raise ValueError("Decryption failed or wrong key") from e
    return plain

# ---------- Storage helpers ----------
def load_records(filename=STORAGE_FILE):
    if not os.path.exists(filename):
        return []
    with open(filename, "r") as f:
        return json.load(f)

def save_records(records, filename=STORAGE_FILE):
    with open(filename, "w") as f:
        json.dump(records, f, indent=2)

def append_record(payload, filename=STORAGE_FILE):
    records = load_records(filename)
    records.append(payload)
    save_records(records, filename)

# ---------- Masking ----------
def mask_pan(pan: str) -> str:
    if len(pan) <= 10:
        return "*" * len(pan)
    return pan[:6] + "*"*(len(pan)-10) + pan[-4:]

# ---------- CLI ----------
def cmd_genpan(args):
    pan = luhn_make()
    print("Synthetic PAN (Luhn valid):", pan)

def cmd_encrypt(args):
    if args.pan:
        pan = args.pan.strip()
    else:
        pan = input("Enter synthetic PAN (digits only): ").strip()
    if not pan.isdigit() or not luhn_validate(pan):
        print("Warning: PAN does not pass Luhn validation. Use synthetic or correct PAN.")
    passphrase = getpass.getpass("Enter passphrase to derive key: ")
    payload = encrypt_pan(pan, passphrase)
    if args.file:
        append_record(payload, args.file)
        print(f"Encrypted record appended to {args.file}")
    else:
        print(json.dumps(payload, indent=2))

def cmd_list(args):
    records = load_records(args.file if args.file else STORAGE_FILE)
    if not records:
        print("No records found.")
        return
    print(f"Found {len(records)} record(s). Showing masked PAN placeholders:")
    for i, rec in enumerate(records, start=1):
        # We cannot show real PAN without passphrase, but can show salt/iv sizes
        print(f"[{i}] salt_len={len(ub64(rec['salt']))} iv_len={len(ub64(rec['iv']))} ct_len={len(ub64(rec['ct']))} mac_len={len(ub64(rec['mac']))}")

def cmd_decrypt(args):
    idx = args.index
    filename = args.file if args.file else STORAGE_FILE
    records = load_records(filename)
    if not records:
        print("No records found.")
        return
    if idx < 1 or idx > len(records):
        print("Index out of range.")
        return
    payload = records[idx-1]
    passphrase = getpass.getpass("Enter passphrase to decrypt: ")
    try:
        pan = decrypt_pan(payload, passphrase)
        print("Decrypted PAN:", pan)
        print("Masked PAN:", mask_pan(pan))
    except Exception as e:
        print("Decryption failed:", e)

def main():
    parser = argparse.ArgumentParser(description="DES-CBC encrypt/decrypt demo with PBKDF2+HMAC (educational)")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("genpan", help="Generate a synthetic (Luhn-valid) PAN")
    p.set_defaults(func=cmd_genpan)

    p = sub.add_parser("encrypt", help="Encrypt a PAN and append to storage (or print payload)")
    p.add_argument("--pan", help="PAN to encrypt (digits only). If omitted, you'll be prompted.")
    p.add_argument("--file", help="File to append record to (defaults to records.json)")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("list", help="List records metadata")
    p.add_argument("--file", help="File to read records from (defaults to records.json)")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("decrypt", help="Decrypt a record by index from storage")
    p.add_argument("index", type=int, help="Record index (1-based)")
    p.add_argument("--file", help="File to read records from (defaults to records.json)")
    p.set_defaults(func=cmd_decrypt)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return
    args.func(args)

if __name__ == "__main__":
    main()


