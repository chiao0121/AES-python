#%%
''' AES 256 encryption/decryption using pycrypto library '''
# https://ithelp.ithome.com.tw/articles/10249953
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
# pycryptodome (Python), Crypto++ (C++) 
import hashlib
import base64
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

class AESCipher(object):
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode('utf-8')).digest()
        # self.key = self.get_private_key(key) # Better security

    @staticmethod
    def get_private_key(password):
        salt = b"this is a salt"
        kdf = PBKDF2(password, salt, 64, 1000)
        key = kdf[:32]
        return key

    def encrypt(self, raw):
        ctr = Counter.new(nbits=128, initial_value=0)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return base64.b64encode(cipher.encrypt(raw.encode('utf-8')))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        ctr = Counter.new(nbits=128, initial_value=0)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(enc).decode('utf-8')

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
