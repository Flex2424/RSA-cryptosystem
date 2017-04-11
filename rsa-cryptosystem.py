#!/usr/bin/python3
from os import urandom
from Crypto.Cipher import DES3
from constants import e, d, n


class RSACryptoSystem:
    def __init__(self, in_file, out_file):
        self.in_file = in_file
        self.out_file = out_file

    def encrypt_triple_des(self, key):
        des = DES3.new(key, DES3.MODE_ECB)
        try:
            with open(self.in_file, 'r') as file:
                with open(self.out_file, 'w') as out:
                    while True:
                        block = file.read(DES3.block_size)
                        if len(block) == 0:
                            break
                        elif len(block) != DES3.block_size:
                            block += ' ' * (DES3.block_size - len(block))
                        # out.write(des.encrypt(block))
        except:
            print('Encrypt error!')
            exit(-1)
        print('[+] 3DES - Encrypt Done!')

    def decrypt_triple_des(self, key):
        des = DES3.new(key, DES3.MODE_ECB)
        try:
            with open(self.out_file, 'r') as file:
                with open('decrypted.txt', 'w') as out:
                    while True:
                        block = file.read(DES3.block_size)
                        if len(block) == 0:
                            break
                        # out.write(des.decrypt(block))
        except:
            print('Decrypt error!')
            exit(-1)
        print('[+] 3DES - Decrypt Done!')

    @staticmethod
    def rsa_encrypt(exp, msg, modulus):
        return pow(msg, exp, modulus)

    @staticmethod
    def rsa_decrypt(cipher, private_exp, modulus):
        return pow(cipher, private_exp, modulus)


rsa = RSACryptoSystem('data_to_encrypt.txt', 'cipher_text.txt')

key = urandom(24)
rsa.encrypt_triple_des(key=key)
key = int.from_bytes(key, byteorder='big')
new_key = rsa.rsa_encrypt(int(e, 16), key, int(n, 16))
restored_key = rsa.rsa_decrypt(int(new_key), int(d, 16), int(n, 16))
# rsa.decrypt_triple_des(key=restored_key)
