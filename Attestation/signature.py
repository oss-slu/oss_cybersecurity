from Crypto.Signature import pss
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
import os


filename = input("Enter filename: ")
priv_key = input("Enter private key: ")
working_directory = os.getcwd()
file_path = os.path.abspath(filename)

with open(file_path, 'rb') as f:
    file_to_sign = f.read()

key = RSA.import_key(open(os.path.abspath(priv_key), 'rb').read())
h = SHA3_256.new()
h.update(file_to_sign)
signature = pss.new(key).sign(h)

print(signature.hex())
