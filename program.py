#! /usr/bin/python3

import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--encrypt", help="Encrypt file", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt file", action="store_true")
    parser.add_argument("-s", "--signature", help="Add signature", action="store_true")
    parser.add_argument("-c", "--check", help="Check signature", action="store_true")
    parser.add_argument("-f", "--file", help="File")
    args = parser.parse_args()

    if args.encrypt:
        print('[+] Encryption mode')
        print('[+] filename: ', args.file)
    elif args.decrypt:
        print('[+] Decryption mode')
        print('[+] filename: ', args.file)
    elif args.signature:
        print('[+] Add signature mode')
        print('[+] filename: ', args.file)
    elif args.check:
        print('[+] Check signature mode')
        print('[+] filename: ', args.file)

if __name__ == '__main__':
    main()
