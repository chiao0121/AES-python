#%% 
''' AES 256 encryption/decryption using pycrypto library '''
# https://ithelp.ithome.com.tw/articles/10249953
# https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
# pycryptodome (Python), Crypto++ (C++) 
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# It enhances the alignment of the key and secret phrase with 32 bytes and IV to 16 bytes
class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size # BLOCK_SIZE = 16
        self.key = hashlib.sha256(key.encode('utf-8')).digest()
        # self.key = self.get_private_key(key) # Better security

    @staticmethod
    def get_private_key(password):
        salt = b"this is a salt"
        kdf = PBKDF2(password, salt, 64, 1000)
        key = kdf[:32]
        return key

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode('utf-8')))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

if __name__ == "__main__":
    password = input("Enter encryption password: ")

    AES_algo = AESCipher(password)
    
    # First let us encrypt secret message
    encrypted = AES_algo.encrypt("This is a secret message")
    print("Encrypted:", encrypted)
    
    # Let us decrypt using our original password
    decrypted = AES_algo.decrypt(encrypted)
    print("Decrypted:", decrypted)
# %%
