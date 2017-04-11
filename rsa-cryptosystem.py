#!/usr/bin/python3

from os import urandom
import Crypto
import constants


class RSACryptoSystem:
    def __init__(self, filename):
        # random key for 3DES
        self.key = urandom(24)

        with open(filename, 'r') as file:
            self.plain_text = file.read()

    def encrypt_triple_des(self):
        pass

    def rsa_encrypt(self):
        pass

    def rsa_decrypt(self):
        pass


rsa = RSACryptoSystem('data_to_encrypt.txt')

