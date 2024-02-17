import rsa

def f1():
    # 生成公私钥对
    (public_key, private_key) = rsa.newkeys(2048)
    print(public_key)
    # print(private_key)
    # 使用私钥签名
    message = b'A message I want to sign'
    signature = rsa.sign(message, private_key, 'SHA-256')
    # 使用公钥验证签名
    print(rsa.verify(message, signature, public_key))

def f2():
    # 生成公私钥对
    (public_key, private_key) = rsa.newkeys(2048)

    # 使用公钥加密
    message = b'Hello 123!'
    encrypted_message = rsa.encrypt(message, public_key)

    # 使用私钥解密
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    print(decrypted_message)

f2()