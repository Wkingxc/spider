import rsa
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time

aes_key = get_random_bytes(24)  # AES-192 requires a 24-byte key
nonce = get_random_bytes(16)

# 使用RSA公钥加密AES密钥和nonce
key_and_nonce = {
    "aes_key": aes_key.hex(),
    "nonce": nonce.hex()
}
RSU_PUBLIC_KEY_FILE = "rsu_public_key.pem"
RSU_PRRIVATE_KEY_FILE = "rsu_private_key.pem"

with open(RSU_PUBLIC_KEY_FILE, mode='rb') as pub_file:
    rsu_pubkey = rsa.PublicKey.load_pkcs1(pub_file.read())
with open(RSU_PRRIVATE_KEY_FILE, mode='rb') as priv_file:
    rsu_privkey = rsa.PrivateKey.load_pkcs1(priv_file.read())

begin = time.time()
for i in range(0,10):
    encrypted_key_and_nonce = rsa.encrypt(json.dumps(key_and_nonce).encode(), rsu_pubkey)
end = time.time()
print(end-begin)

begin = time.time()
for i in range(0,1):
    key_and_nonce = rsa.decrypt(encrypted_key_and_nonce, rsu_privkey)
end = time.time()
print(end-begin)