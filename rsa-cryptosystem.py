#!/usr/bin/python3
from os import urandom
from hashlib import sha1
from Crypto.Cipher import DES3

from constants import exponent, d_encryption, d_signature, n_encryption, n_signature
from parser import ASN1


class RSACryptoSystem:
    def __init__(self, in_file):
        self.in_file = in_file
        self.cipher_text = None

    def encrypt_triple_des(self, key):
        self.cipher_text = bytes()
        des = DES3.new(key, DES3.MODE_ECB)
        with open(self.in_file, 'r') as file:
            while True:
                block = file.read(DES3.block_size)
                if len(block) == 0:
                    break
                elif len(block) != DES3.block_size:
                    block += ' ' * (DES3.block_size - len(block))
                self.cipher_text += des.encrypt(block)
        print('[+] 3DES - Encrypt Done!')
        return self.cipher_text

    def decrypt_triple_des(self, key):
        des = DES3.new(key, DES3.MODE_ECB)
        with open('decrypted.txt', 'w') as out:
            while True:
                block = file.read(DES3.block_size)
                if len(block) == 0:
                    break
                # out.write(des.decrypt(block))

        print('[+] 3DES - Decrypt Done!')

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

# key = urandom(24)
# cipher_text = rsa.encrypt_triple_des(key=key)
#
# encrypted_key = RSACryptoSystem.rsa_encrypt(
#     int.from_bytes(cipher_text, byteorder='big'),
#     int(exponent, 16),
#     int(n_encryption, 16)
# )
#
# encoded_bytes = ASN1.encode_file(
#     int(n_encryption, 16),
#     int(exponent, 16),
#     encrypted_key,
#     len(cipher_text),
#     cipher_text)
#
# with open("encryption.efn", "wb") as file:
#     file.write(encoded_bytes)
#
# parser = ASN1()
# parser.parse_file('encryption.efn')
# for item in parser.decoded_values:
#     print(hex(item))
#     print()

# key = int.from_bytes(key, byteorder='big')
# new_key = rsa.rsa_encrypt(key, int(e, 16), int(n, 16))
# encoded_bytes = ASN1.encode_file_signature()
# restored_key = rsa.rsa_decrypt(int(new_key), int(d, 16), int(n, 16))
# rsa.decrypt_triple_des(key=restored_key)

# sig = RSACryptoSystem.rsa_add_signature('data_to_encrypt.txt', int(d, 16), int(n, 16))
# encoded_bytes = ASN1.encode_file_signature(int(n, 16), int(e, 16), sig)
# with open("binary-asn.efn", "wb") as file:
#     file.write(encoded_bytes)

# print(RSACryptoSystem.rsa_check_signature('data_to_encrypt.txt', sig, int(e, 16), int(n, 16)))


