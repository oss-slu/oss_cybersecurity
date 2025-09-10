from Crypto.Signature import pss
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
import os
import PyPDF2


filename = input("Enter filename: ")
pub_key = input("Enter public key: ")
signature = input("Enter signature (hex): ")
working_directory = os.getcwd()

file_path = os.path.abspath(filename)

text = ''
with open(file_path, 'rb') as f:
    reader = PyPDF2.PdfReader(f)
    for page_num in range(len(reader.pages)):
        page = reader.pages[page_num]
        text += page.extract_text()

key = RSA.import_key(open(os.path.abspath("private.pem"), 'rb').read())
h = SHA3_256.new()
h.update(text.encode())

bytes_signature = bytes.fromhex(signature)
print("The document hash is: ", h.hexdigest())

verifier = pss.new(key)
try:
    verifier.verify(h, bytes_signature)
    print("The signature is authentic.")
except (ValueError):
    print("The signature is not authentic.")