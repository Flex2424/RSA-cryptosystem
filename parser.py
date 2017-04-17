#!/usr/bin/python3

import asn1


class ASN1:
    def __init__(self):
        self.decoded_values = []

    @staticmethod
    def encode_file_signature(modulus, exp, signature):
        asn = asn1.Encoder()
        asn.start()
        asn.enter(asn1.Numbers.Sequence)
        asn.enter(asn1.Numbers.Set)
        asn.enter(asn1.Numbers.Sequence)
        asn.write(b'\x00\x06', asn1.Numbers.OctetString)
        asn.write(b'RSASignature. DimaZyuzin', asn1.Numbers.UTF8String)
        asn.enter(asn1.Numbers.Sequence)
        asn.write(modulus, asn1.Numbers.Integer)
        asn.write(exp, asn1.Numbers.Integer)
        asn.leave()
        asn.enter(asn1.Numbers.Sequence)
        asn.leave()
        asn.enter(asn1.Numbers.Sequence)
        asn.write(signature, asn1.Numbers.Integer)
        asn.leave()
        asn.leave()
        asn.leave()
        asn.enter(asn1.Numbers.Sequence)
        asn.leave()
        asn.leave()
        return asn.output()

    @staticmethod
    def encode_file(modulus, exp, encrypted_key, length, cipher_text):
        file = asn1.Encoder()
        file.start()
        file.enter(asn1.Numbers.Sequence)
        file.enter(asn1.Numbers.Set)
        file.enter(asn1.Numbers.Sequence)
        file.write(b'\x00\x01', asn1.Numbers.OctetString)
        file.write(b'Encryption. DimaZyuzin', asn1.Numbers.UTF8String)
        file.enter(asn1.Numbers.Sequence)
        file.write(modulus, asn1.Numbers.Integer)
        file.write(exp, asn1.Numbers.Integer)
        file.leave()
        file.enter(asn1.Numbers.Sequence)
        file.leave()
        file.enter(asn1.Numbers.Sequence)
        file.write(encrypted_key, asn1.Numbers.Integer)
        file.leave()
        file.leave()
        file.leave()
        file.enter(asn1.Numbers.Sequence)
        file.write(b'\x01\x32', asn1.Numbers.OctetString)
        file.write(length, asn1.Numbers.Integer)
        file.leave()
        file.leave()
        file.write(cipher_text)
        return file.output()

    def parse_file(self, filename):
        with open(filename, 'rb') as file:
            data = file.read()
        file = asn1.Decoder()
        file.start(data)
        self.parsing_file(file)

        # because
        if filename == 'signature.enf':
            return

        with open(filename, 'rb') as file:
            data = file.read()
            data = bytearray(data)
            data.reverse()
            file_len = self.decoded_values[-1]
            cipher_text_bytes = bytearray()
            for i in reversed(range(file_len)):
                cipher_text_bytes.append(data[i])
            with open('cipher', 'wb') as file:
                file.write(cipher_text_bytes)

    def parsing_file(self, file):
        while not file.eof():
            try:
                tag = file.peek()
                if tag.nr == asn1.Numbers.Null:
                    break
                if tag.typ == asn1.Types.Primitive:
                    tag, value = file.read()
                    if tag.nr == asn1.Numbers.Integer:
                        self.decoded_values.append(value)
                else:
                    file.enter()
                    self.parsing_file(file)
                    file.leave()
            except asn1.Error:
                break
