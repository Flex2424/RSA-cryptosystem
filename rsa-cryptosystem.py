#!/usr/bin/python

from __future__ import print_function
from os import urandom
from Crypto.Cipher import DES3
import constants


class RSACryptoSystem:
    def __init__(self, in_file, out_file):
        self.in_file = in_file
        self.out_file = out_file
        self.cipher_text = None
        self.key = urandom(24)

    def encrypt_triple_des(self):
        des = DES3.new(self.key, DES3.MODE_ECB)
        try:
            with open(self.in_file, 'r') as file:
                with open(self.out_file, 'w') as out:
                    while True:
                        block = file.read(DES3.block_size)
                        if len(block) == 0:
                            break
                        elif len(block) != DES3.block_size:
                            block += ' ' * (DES3.block_size - len(block))
                        out.write(des.encrypt(block))
        except:
            print('Encrypt error!')
            exit(-1)
        print('[+] 3DES - Encrypt Done!')

    def decrypt_triple_des(self):
        des = DES3.new(self.key, DES3.MODE_ECB)
        try:
            with open(self.out_file, 'r') as file:
                with open('decrypted.txt', 'w') as out:
                    while True:
                        block = file.read(DES3.block_size)
                        if len(block) == 0:
                            break
                        out.write(des.decrypt(block))
        except:
            print('Decrypt error!')
            exit(-1)
        print('[+] 3DES - Decrypt Done!')

    def rsa_encrypt(self):
        pass

    def rsa_decrypt(self):
        pass


rsa = RSACryptoSystem('data_to_encrypt.txt', 'cipher_text.txt')
rsa.encrypt_triple_des()
rsa.decrypt_triple_des()
