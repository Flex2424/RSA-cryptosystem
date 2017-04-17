#!/usr/bin/python3
import os
from struct import pack
from hashlib import sha1
from Crypto.Cipher import DES3

from constants import exponent, d_encryption, d_signature, n_encryption, n_signature
from parser import ASN1

"""
Need to fix!
1. Find cipher text in binary file!
2. Raise error if can't find syb bytes
3. Menu and program logic
"""


class RSACryptoSystem:
    def __init__(self, in_file):
        self.in_file = in_file
        self.cipher_text = None
        self.decrypted_text = None

    def encrypt_triple_des(self, key):
        self.cipher_text = bytes()
        des = DES3.new(key, DES3.MODE_ECB)
        with open(self.in_file, 'r') as file:
            data = file.read()
            to_add = 0
            if len(data) % 8 != 0:
                to_add = 8 - len(data) % 8
            data += ' ' * to_add
            self.cipher_text = des.encrypt(data)
            return self.cipher_text

    def decrypt_triple_des(self, key, filename):
        self.decrypted_text = bytes()
        des = DES3.new(key, DES3.MODE_ECB)
        with open(filename, 'rb') as file:
            while True:
                block = file.read(DES3.block_size)
                if len(block) == 0:
                    break
                self.decrypted_text += des.decrypt(block)
        return self.decrypted_text

    @staticmethod
    def rsa_encrypt(msg, exp, modulus):
        return pow(msg, exp, modulus)

    @staticmethod
    def rsa_decrypt(cipher, private_exp, modulus):
        return pow(cipher, private_exp, modulus)

    @staticmethod
    def rsa_add_signature(file, p_exp, modulus):
        with open(file, 'rb') as msg:
            h = sha1(msg.read())
            r = h.hexdigest()
            signature = RSACryptoSystem.rsa_encrypt(msg=int(r, 16), exp=p_exp, modulus=modulus)
            return signature

    @staticmethod
    def rsa_check_signature(file, signature, exp, modulus):
        with open(file, 'rb') as msg:
            # returns decimal hash
            t = RSACryptoSystem.rsa_decrypt(cipher=signature, private_exp=exp, modulus=modulus)
            h = sha1(msg.read())
            # returns hash in hex
            r = h.hexdigest()
            if int(r, 16) == t:
                return True
            else:
                return False


"""
Encryption - descryption example
"""
rsa = RSACryptoSystem('data_to_encrypt.txt')
key = os.urandom(24)

cipher_text = rsa.encrypt_triple_des(key=key)

with open('encrypted_data', 'wb') as file:
    file.write(cipher_text)

encrypted_key = RSACryptoSystem.rsa_encrypt(
    int.from_bytes(key, byteorder='big'),
    int(exponent, 16),
    int(n_encryption, 16)
)

encoded_bytes = ASN1.encode_file(
    int(n_encryption, 16),
    int(exponent, 16),
    encrypted_key,
    len(cipher_text),
    cipher_text
)

with open('encryption.efn', 'wb') as file:
    file.write(encoded_bytes)

asn = ASN1()
asn.parse_file('encryption.efn')
restored_module = asn.decoded_values[0]
restored_exp = asn.decoded_values[1]
encrypted_key = asn.decoded_values[2]

restored_key = RSACryptoSystem.rsa_decrypt(
    encrypted_key,
    int(d_encryption, 16),
    restored_module
)

restored_key = restored_key.to_bytes((restored_key.bit_length() + 7) // 8, 'big')

decrypted_text = rsa.decrypt_triple_des(key=restored_key, filename='cipher')
try:
    os.remove('encrypted_data')
except:
    pass

print('[+] Decrypted!')
print(decrypted_text.decode('utf-8', 'ignore'))

# ------------------------------------------------------------------

"""
Checking signature example
"""
# rsa = RSACryptoSystem('data_to_encrypt.txt')
# sign = rsa.rsa_add_signature(
#     '/home/dima/BurpSuiteFree/burpsuite_free.jar',
#     int(d_signature, 16),
#     int(n_signature, 16)
# )
#
# encoded_bytes = ASN1.encode_file_signature(
#     int(n_signature, 16),
#     int(d_signature, 16),
#     sign
# )
# with open('test_sig1.enf', 'wb') as file:
#     file.write(encoded_bytes)
#
# asn = ASN1()
# asn.parse_file('test_sig1.enf')
# restored_module = asn.decoded_values[0]
# restored_exp = asn.decoded_values[1]
# restored_sig = asn.decoded_values[2]
# print(RSACryptoSystem.rsa_check_signature('/home/dima/BurpSuiteFree/burpsuite_free.jar',
#                                           restored_sig,
#                                           int(exponent, 16),
#                                           restored_module))
# -----------------------------------------------------------------------------------------
