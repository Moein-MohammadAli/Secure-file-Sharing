import os, sys
import random
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from rest_framework.exceptions import ValidationError
import struct
import json

from backend.settings import P, G, PUBLIC_KEY, PRIVATE_KEY

class CryptoCipher(object):

    def __init__(self, key): 
        self.blockSize = AES.block_size
        self.p = int(P, 16)
        self.g = G
        temp_key = self.private_key_decryption(PRIVATE_KEY, key)
        print(temp_key)
        self.key = hashlib.sha256(temp_key.encode()).digest()

    def encrypt_text(self, plainText):
        plainText = self.pad(plainText)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(plainText.encode()))

    def decrypt_text(self, cipherText):
        cipherText = base64.b64decode(cipherText)
        iv = cipherText[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(cipherText[AES.block_size:])).decode()

    def pad(self, s):
        return s + (self.blockSize - len(s) % self.blockSize) * chr(self.blockSize - len(s) % self.blockSize)

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]


    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plainText = fo.read()

        plainText = plainText + b"\0" * (AES.block_size - len(plainText) % AES.block_size)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        enc = base64.b64encode(iv + cipher.encrypt(plainText))

        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)


    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            cipherText = fo.read()

        cipherText = base64.b64decode(cipherText)
        iv = cipherText[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(cipherText[AES.block_size:])
        dec = plaintext.rstrip(b"\0")

        with open("decrypted_"+file_name[:-4], 'wb') as fo:
            fo.write(dec)

    def private_key_decryption(self, private_key, encrypted):
        return str(pow(int(encrypted, 16), int(private_key, 16), self.p))

    def public_key_encryption(self, public_key, plain_text):
        return str(pow(plain_text, public_key, self.p))


def get_data(request):
    headers = request.headers
    if headers.get('Session-Key'):
        return CryptoCipher(headers['Session-Key'])
    else:
        raise ValidationError("session_key is invalid.")

