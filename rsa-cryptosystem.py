#!/usr/bin/python3

from os import urandom
from Crypto.Cipher import DES3
import constants


class RSACryptoSystem:
    def __init__(self, filename):
        self.filename = filename
        self.cipher_text = None

    def encrypt_triple_des(self):
        des = DES3.new(urandom(24), DES3.MODE_ECB)
        try:
            with open(self.filename, 'r') as file:
                while True:
                    block = file.read(DES3.block_size)
                    if len(block) == 0:
                        break
                    elif len(block) != DES3.block_size:
                        block += ' ' * (DES3.block_size - len(block))
                    print(des.encrypt(block))
        except:
            print("Can't fine file!")
            exit(-1)
        print('[+] 3DES - Done!')

    def rsa_encrypt(self):
        pass

    def rsa_decrypt(self):
        pass


rsa = RSACryptoSystem('data_to_encrypt.txt')
rsa.encrypt_triple_des()

