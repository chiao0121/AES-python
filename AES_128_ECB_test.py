#%%
''' AES 128 encryption/decryption using pycrypto library '''
# https://ithelp.ithome.com.tw/articles/10249953
# https://learningsky.io/using-python-to-encrypt-decrypt-aes-128-ecb/
# pycryptodome (Python), Crypto++ (C++) 
import json
from Crypto.Cipher import AES

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(dataDict, AES_KEY):
    cipher = AES.new(bytes(AES_KEY), AES.MODE_ECB)
    cipheredData = cipher.encrypt(pad(json.dumps(dataDict)).encode("utf8"))
    # with open(strFilePath, "wb") as f:
    #     f.write(cipheredData)
    return cipheredData
    
def decrypt(enc, AES_KEY):
    # in_file = open(strFilePath, "rb")
    # enc = in_file.read()
    # in_file.close()
    cipher = AES.new(bytes(AES_KEY), AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(enc))
    jsonString = decrypted.decode('utf-8')
    return decrypted, jsonString

if __name__ == "__main__":
    AES_KEY = [0x50, 0x96, 0x22, 0x66, 0x70, 0x79, 0x60, 0x66, 0x31, 0x70, 0x68, 0x80, 0x33, 0x18, 0x28, 0x66]
    print(f'\nkey-letters             : {bytes(AES_KEY)}')
    print(f'\nkey-length              : {len(AES_KEY)}')

    dataDict = {
        "BPM": 88,
        "RPM": 12,
        "datetime": "2024-02-06 14:39:07",
        "MAC": "34:b4:72:43:0e:08"
    }

    strFilePath = "./sample-encrypt.txt"
  
    encrypted  = encrypt(dataDict, AES_KEY)
    print(f'\nencrypted               : {encrypted}')
    print(f'\nencrypted-length        : {len(encrypted)}')
    decrypted, decrypted_json = decrypt(encrypted, AES_KEY)
    print(f'\ndecrypted               : {decrypted}')
    print(f'\ndecrypted-length        : {len(decrypted)}')
    print(f'\ndecrypted-string        : {decrypted_json}')
    print(f'\ndecrypted-string-length : {len(decrypted_json)}')
# %%
