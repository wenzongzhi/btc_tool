"""
Copyright 2026 温中志 (Wen Zhongzhi)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import hashlib
from ecdsa import SigningKey, SECP256k1
from bech32 import bech32_encode, convertbits

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def base58_encode(b: bytes) -> str:
    num = int.from_bytes(b, "big")
    res = ""
    while num > 0:
        num, rem = divmod(num, 58)
        res = BASE58_ALPHABET[rem] + res
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + res

def base58check(version: bytes, payload: bytes) -> str:
    data = version + payload
    checksum = sha256(sha256(data))[:4]
    return base58_encode(data + checksum)

def privkey_to_compressed_pubkey(privkey32: bytes) -> bytes:
    sk = SigningKey.from_string(privkey32, curve=SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    x_bytes = x.to_bytes(32, "big")
    prefix = b"\x02" if (y % 2 == 0) else b"\x03"
    return prefix + x_bytes

def p2wpkh_bech32_address(pubkey_compressed: bytes) -> str:
    h160 = hash160(pubkey_compressed)  # 20 bytes
    # witness version 0, program=20 bytes
    data = [0] + list(convertbits(h160, 8, 5, True))
    return bech32_encode("bc", data)

def p2sh_p2wpkh_address(pubkey_compressed: bytes) -> str:
    h160 = hash160(pubkey_compressed)
    redeem_script = b"\x00\x14" + h160  # 0 <20-byte>
    script_hash = hash160(redeem_script)
    return base58check(b"\x05", script_hash)  # mainnet P2SH

def pubkey_to_p2pkh(pubkey: bytes) -> str:
    h160 = hash160(pubkey)
    payload = b"\x00" + h160  # mainnet P2PKH version byte
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

""" the following code just for your test  
# your private key
#pi64 = "3141592653589793238462643383279502884197169399375105820974944592"
pi64 = "1415926535897932384626433832795028841971693993751058209749445923"

priv = bytes.fromhex(pi64)

pub_c = privkey_to_compressed_pubkey(priv)
print("compressed pubkey:", pub_c.hex())

print("P2PKH (1...):", pubkey_to_p2pkh(pub_c))
print("P2WPKH (bc1q):", p2wpkh_bech32_address(pub_c))
print("P2SH-P2WPKH (3...):", p2sh_p2wpkh_address(pub_c))
"""