#!/usr/bin/env python3

import sys, hashlib

def decrypt_password(user, pass_enc):
    key = hashlib.md5(user + b"283i4jfkai3389").digest()

    passw = ""
    for i in range(0, len(pass_enc)):
        passw += chr(pass_enc[i] ^ key[i])
    
    return passw.split("\x00")[0]


def get_pair(data):

    user_list = []

    entries = data.split(b"M2")[1:]
    for entry in entries:
        user_len = entry.split(b"\x01\x00\x00\x21")[1][0]
        pass_len = entry.split(b"\x11\x00\x00\x21")[1][0]

        user     = entry.split(b"\x01\x00\x00\x21")[1][1:1 + user_len]
        pass_enc = entry.split(b"\x11\x00\x00\x21")[1][1:1 + pass_len]

        passw = decrypt_password(user, pass_enc)
        user  = user.decode("ascii")

        user_list.append((user, passw))

    return user_list

if __name__ == "__main__":
    if len(sys.argv) == 2:
        user_file = open(sys.argv[1], "rb").read()
        user_pass = get_pair(user_file)
        for u, p in user_pass:
            print("User:", u)
            print("Pass:", p)
            print()
    else:
        print("Usage:")
        print(sys.argv[0], "user.dat")

