import rsa

def rsu_gen():
    # 生成RSU的公私钥对，并保存到文件，仅首次运行时需要
    (rsu_pubkey, rsu_privkey) = rsa.newkeys(1024)
    with open('rsu_public_key.pem', 'wb') as pub_file:
        pub_file.write(rsu_pubkey.save_pkcs1('PEM'))
    with open('rsu_private_key.pem', 'wb') as priv_file:
        priv_file.write(rsu_privkey.save_pkcs1('PEM'))

def v_gen():
    # 生成V的公私钥对，并保存到文件，仅首次运行时需要
    (v_pubkey, v_privkey) = rsa.newkeys(1024)
    with open('v_public_key.pem', 'wb') as pub_file:
        pub_file.write(v_pubkey.save_pkcs1('PEM'))
    with open('v_private_key.pem', 'wb') as priv_file:
        priv_file.write(v_privkey.save_pkcs1('PEM'))

def rsu_load():
    RSU_PUBLIC_KEY_FILE = "rsu_public_key.pem"
    RSU_PRRIVATE_KEY_FILE = "rsu_private_key.pem"
    with open(RSU_PUBLIC_KEY_FILE, mode='rb') as pub_file:
        rsu_pubkey = rsa.PublicKey.load_pkcs1(pub_file.read())
    with open(RSU_PRRIVATE_KEY_FILE, mode='rb') as priv_file:
        rsu_privkey = rsa.PrivateKey.load_pkcs1(priv_file.read())
    return rsu_pubkey, rsu_privkey

def v_load():
    V_PUBLIC_KEY_FILE = "v_public_key.pem"
    V_PRIVATE_KEY_FILE = "v_private_key.pem"
    with open(V_PUBLIC_KEY_FILE, mode='rb') as pub_file:
        v_pubkey = rsa.PublicKey.load_pkcs1(pub_file.read())
    with open(V_PRIVATE_KEY_FILE, mode='rb') as priv_file:
        v_privkey = rsa.PrivateKey.load_pkcs1(priv_file.read())
    return v_pubkey, v_privkey