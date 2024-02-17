import rsa

def check_pri_pub_key(v_pubkey, v_privkey):
    test_data = b'This is some test data'
    encrypted_data = rsa.encrypt(test_data, v_pubkey)
    decrypted_data = rsa.decrypt(encrypted_data, v_privkey)
    if decrypted_data == test_data:
        return True
    else:
        return False