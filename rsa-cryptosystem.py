#!/usr/bin/python3
from os import urandom
from hashlib import sha1
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
            # return decimal hash
            t = RSACryptoSystem.rsa_decrypt(cipher=signature, private_exp=exp, modulus=modulus)
            h = sha1(msg.read())
            # return hash in hex
            r = h.hexdigest()
            if int(r, 16) == t:
                return True
            else:
                return False

# rsa = RSACryptoSystem('data_to_encrypt.txt', 'cipher_text.txt')
#
# key = urandom(24)
# rsa.encrypt_triple_des(key=key)
# key = int.from_bytes(key, byteorder='big')
# new_key = rsa.rsa_encrypt(key, int(e, 16), int(n, 16))
# restored_key = rsa.rsa_decrypt(int(new_key), int(d, 16), int(n, 16))
# rsa.decrypt_triple_des(key=restored_key)

sig = RSACryptoSystem.rsa_add_signature('data_to_encrypt.txt', int(d, 16), int(n, 16))
print(RSACryptoSystem.rsa_check_signature('data_to_encrypt.txt', sig, int(e, 16), int(n, 16)))
