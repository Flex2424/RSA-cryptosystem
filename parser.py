#!/usr/bin/python3

import asn1


class ASN1:
    @staticmethod
    def encode_file_signature(modulus, exp, signature):
        asn = asn1.Encoder()
        asn.start()
        asn.enter(asn1.Numbers.Sequence)
        asn.enter(asn1.Numbers.Set)
        asn.enter(asn1.Numbers.Sequence)
        asn.write(b'\x00\x06', asn1.Numbers.OctetString)
        asn.write(b'RSA11. DimaZyuzin', asn1.Numbers.UTF8String)
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

    def encode_file(self):
        pass

    def parse_file(self):
        pass
