import base64
import codecs
import binascii
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import lz4.frame


def AES_CBC_encrypt(data, key, iv):
    """AES CBC加密函数
    :param data:需要加密的数据块 Union[bytes, bytearray, memoryview]
    :param key:AES加密所用的key Union[bytes, bytearray, memoryview]
    :param iv:AES加密所用的IV Union[bytes, bytearray, memoryview]
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypt_data = cipher.encrypt(data)
    encrypt_data = codecs.encode(encrypt_data, 'hex')
    # print(encrypt_data)
    return encrypt_data


def AES_CBC_decrypt(data, key, iv):
    """AES CBC解密函数
    :param data:需要解密的数据块 Union[bytes, bytearray, memoryview]
    :param key:AES解密所用的key Union[bytes, bytearray, memoryview]
    :param iv:AES解密所用的IV Union[bytes, bytearray, memoryview]
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypt_data = cipher.decrypt(data)
    decrypt_data = codecs.encode(decrypt_data, 'hex')
    return decrypt_data
    # print(decrypt_data)
    # decompress_data(decrypt_data)


def AES_GCM_decrypt(nonce, ciphertext, associated_data, key):
    """AES GCM解密函数
    :param nonce: Base64编码后的密文
    :param ciphertext: 加密使用的随机串初始化向量
    :param associated_data: 附加数据包（可能为空）
    :param key: AES解密所用的key
    :return: 解密数据
    """
    key_bytes = str.encode(key)
    nonce_bytes = str.encode(nonce)
    ad_bytes = str.encode(associated_data)
    data = base64.b64decode(ciphertext)
    aesgcm = AESGCM(key_bytes)
    return aesgcm.decrypt(nonce_bytes, data, ad_bytes)


def AES_CFB_decrypt(data, key, iv):
    """AES CBC加密函数
        :param data:需要加密的数据块 Union[bytes, bytearray, memoryview]
        :param key:AES加密所用的key Union[bytes, bytearray, memoryview]
        :param iv:AES加密所用的IV Union[bytes, bytearray, memoryview]
        """
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypt_data = cipher.decrypt(data)
    encrypt_data = codecs.encode(encrypt_data, 'hex')
    print(encrypt_data)


# def decompress_data(cm_data):
#     de_data = lz4.frame.decompress(cm_data)
#     print(de_data)

# import base64
#
# from Crypto.Cipher import AES


# class AESUtil(object):
#     def __init__(self, key, model, iv, encode_='utf-8'):
#         self.encode_ = encode_
#         self.model = model
#         self.iv = iv.encode()
#         self.key = self.add_16(key)
#         self.aes = 'PCKS7'
#         # 这里的密钥长度必须是16、24或32，目前16位的就够用了
#
#     def init_aes(self):
#         model_func = {'ECB': AES.MODE_ECB, 'CBC': AES.MODE_CBC}[self.model]
#         if self.model == 'ECB':
#             self.aes = AES.new(self.key, model_func)  # 创建一个aes对象
#         elif self.model == 'CBC':
#             self.aes = AES.new(self.key, model_func, self.iv)  # 创建一个aes对象
#
#     def add_16(self, par):
#         par = par.encode(self.encode_)
#         while len(par) % 16 != 0:
#             par += b'\x00'
#         return par
#
#     def encrypt(self, text):
#         self.init_aes()
#         text = self.add_16(text)
#         return base64.encodebytes(self.aes.encrypt(text)).decode().strip()
#
#     def decrypt(self, text):
#         text = base64.decodebytes(text.encode(self.encode_))
#         self.init_aes()
#         return self.aes.decrypt(text).decode(self.encode_).strip('\0').replace("\x05", '').replace("\x06", '').replace(
#             "\x07", '')
#
#

if __name__ == '__main__':
    key = "0353d34719c3f4c3".encode().hex()
    iv = '0809020607070303'.encode().hex()
    enc_str = 'dd2e22a1a29c741b9afe4a3a2802e0f7cb474fdb3257091714da5052e20fc07d226e28fa6c6ab6205c314c4a35af21bdad4a3fb1700d3c1c26d0e07fab468c84f83f45a8b13f126d07e6b1e1e18c25fa7e180f75758335307b77fab394e1a56db91ffde09b0713af8a279868265ab56d5700805b9af6e58ffb6ce80787982d67884ccf6694418818529e94321a1f81c60836c6c8c3c873cb8ac7563e970abb29c72e6fa11fa7860d70e2544caddd71f8af575a4d4342b8e96a1571adbb282b9663692a558ec8c9230f0ee4d8d4e1ab8fb36c1dc8d1a59a10867d32238b9878aa9f7de2678c0edb1a24ba4a188a5d37e5444cedd550e540b4038893e150f426c2c102063240cca589ed96cb1f2e5b1c828b61f02265a189331790133a9af592a20a2484cce551cd5391d45a638beccab710e8c2d5e673abc0391eac371b20f99a79206c2ef46fb43116fa3db436347043c7a7dd0b3b106c65e34d9a4f5159d62fffdc43e60243f20a84af4bb45bebc1890c0ffd76d4411998de63647e991e148d5d6ddc2ee0e83a206323adb9e62fe77ec4fb4c3b7bf612ac3112778956efdb6b70933496937acac78bfe2ab859126daf911abd8977f3165d3e8387f455644d8d16e94f4e58522af16b1954e1372c47402950d76631bae4ebfb9590aee23cf9d1cfb516f80a7a8959632685ea1595bfff33961412a7807a9884420b49659ff42ba4136260ddcaa9d83fbf9d78159b3bbbe376c2fff41b94aaf24f6e089100be67ccd2ad6a77f575988eb7ee16e2f63d5a55f4df702ea629e5dc2fe3ac934c79fcd7ae8564b5c1d7cb1b5aae8a3b237b248bcc121358534a3fdb30c065edb4b2706872b8a9c87ddaa3566cbc5623eb97a4df692e8820e73b101ff302c262ef72d7712be91d167558b9d33052f520dfd0a349fbf915aff89ba96b3597fae50e08ee2877474922a597a0c1802d3a1d514d7e699d7bf27dad76d355616f90bd182cabdffa07f9c1ba8a24f1ee55742d4b63cab98809d2326e898ed15560aafb551521f35710ba61de605a56ab3f361358b38f587498d4799287d79e4376d6aecf9bae5ed1e31ccaf2e27ec84c43f055545cee630384958571b6ca961304ba05d35d2f4e2a7600ce896dcba3ce7d438e387c16890dd17422bc0fdbbf0895e4a4828ef462e43cfe79f812e1af64183fcfeaac5556cc60e169db04820289ff8e2ea64ae4 '
    dec_str = AES_CBC_decrypt(bytes.fromhex(enc_str), bytes.fromhex(key), bytes.fromhex(iv))
    print(binascii.a2b_hex(dec_str).decode().split(","))
