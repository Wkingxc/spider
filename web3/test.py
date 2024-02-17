import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import rsa
import hashlib


data = {
    "aaa":"111",
    "bbb":"222",
    "ccc":"333"
}
# 对json数据进行私钥签名
def sign_data(data, privkey):
    # 将数据转换为字符串并编码
    data_str = json.dumps(data).encode()
    # 使用私钥签名数据
    signature = rsa.sign(data_str, privkey, 'SHA-256')
    return signature

# 对json数据进行签名验证
def verify_signature(data, signature, pubkey):
    # 计算数据的哈希值
    data_str = json.dumps(data).encode()
    try:
        # 验证签名
        rsa.verify(data_str, signature, pubkey)
        print("Signature is valid")
        return True
    except rsa.VerificationError:
        return False

(pubkey,privkey) = rsa.newkeys(2048)
signatures = sign_data(data, privkey)
print(verify_signature(data, signatures, pubkey))