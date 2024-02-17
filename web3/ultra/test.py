from tools.utils import encrypt_data, decrypt_data
import rsa

RSU_PUBLIC_KEY_FILE = "rsu_public_key.pem"
RSU_PRRIVATE_KEY_FILE = "rsu_private_key.pem"

with open(RSU_PUBLIC_KEY_FILE, mode='rb') as pub_file:
    rsu_pubkey = rsa.PublicKey.load_pkcs1(pub_file.read())
with open(RSU_PRRIVATE_KEY_FILE, mode='rb') as priv_file:
    rsu_privkey = rsa.PrivateKey.load_pkcs1(priv_file.read())

data = {"a":111, "b":222}
encrypted_data, key_and_nonce = encrypt_data(data, rsu_pubkey, rsu_privkey)
t = decrypt_data(encrypted_data, key_and_nonce, rsu_pubkey, rsu_privkey)
print(t)