from Crypto.Signature import pss
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
import os
import PyPDF2


filename = input("Enter filename: ")
priv_key = input("Enter private key: ")
working_directory = os.getcwd()
file_path = os.path.abspath(filename)

text = ''
with open(file_path, 'rb') as f:
    reader = PyPDF2.PdfReader(f)
    for page_num in range(len(reader.pages)):
        page = reader.pages[page_num]
        text += page.extract_text()

key = RSA.import_key(open(os.path.abspath(priv_key), 'rb').read())
h = SHA3_256.new()
h.update(text.encode())
signature = pss.new(key).sign(h)

print("The document hash is: ", h.hexdigest())
print("The signature hash is: ", signature.hex())
