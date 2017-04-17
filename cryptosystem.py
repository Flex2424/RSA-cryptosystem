#!/usr/bin/python3

from hashlib import sha1
from Crypto.Cipher import DES3


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
