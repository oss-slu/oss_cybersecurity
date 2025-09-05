from Crypto.Signature import pss
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
import os


filename = input("Enter filename: ")
pub_key = input("Enter public key: ")
signature = input("Enter signature (hex): ")
working_directory = os.getcwd()

file_path = os.path.abspath(filename)
with open(file_path, 'r') as f:
    file_to_sign = f.read()

key = RSA.import_key(open(os.path.abspath("private.pem"), 'rb').read())
h = SHA3_256.new()
h.update(file_to_sign.encode())

bytes_signature = bytes.fromhex(signature)

verifier = pss.new(key)
try:
    verifier.verify(h, bytes_signature)
    print("The signature is authentic.")
except (ValueError):
    print("The signature is not authentic.")