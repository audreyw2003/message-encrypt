import sys
import os
import pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_file(plaintext, filetype, pub_key):
    key, iv, ciphertext = symmetric_encryption(plaintext)
    key_iv = key + iv
    encrypted_key = asymmetric_encrypt(key_iv, pub_key)
    filecontent = package_file(encrypted_key, ciphertext)
    if (filetype == 'txt'):
        with open('encrypted_message.txt', 'w') as f:
            f.write(filecontent)
    elif(filetype == 'pickle'):
        with open('encrypted_message.pk1', 'wb') as f:
            pickle.dump(filecontent, f)
    return filecontent     

def decrypt_file(filetype, priv_key):
    if(filetype == 'txt'):
        with open('encrypted_message.txt', 'r') as f:
            filecontent = f.read()
    elif(filetype == 'pickle'):
        with open('encrypted_message.pk1', 'rb') as f:
            filecontent = pickle.load(f)
    encrypted_key, ciphertext = unpackage_file(filecontent)
    decrypted_key = asymmetric_decrypt(encrypted_key, priv_key)
    plaintext = symmetric_decryption(ciphertext, decrypted_key)
    return plaintext

def gen_keys():
    priv_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
    )
    pub_key = priv_key.public_key()
    return priv_key, pub_key
def symmetric_encryption(plaintext):
    key = os.urandom(32)
    iv = os.urandom(16)
    plaintext = plaintext.encode()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    padder = PKCS7(cipher.algorithm.block_size).padder()
    padded_message = padder.update(plaintext) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return (key, iv, ciphertext)
    
def symmetric_decryption(ciphertext, decrypted_key):
    key = decrypted_key[:32]
    iv = decrypted_key[32:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor() 
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(cipher.algorithm.block_size).unpadder()
    unpadded_message = unpadder.update(plaintext) + unpadder.finalize()
    plaintext = unpadded_message.decode()
    return plaintext
    
def asymmetric_encrypt(key_iv, pub_key):
    encrypted_key = pub_key.encrypt(
    key_iv,
    padding.OAEP(
        mgf = padding.MGF1(algorithm=hashes.SHA256()),
        algorithm = hashes.SHA256(),
        label = None
        )
    )
    return encrypted_key
    
def asymmetric_decrypt(encrypted_key, priv_key):
    decrypted_key = priv_key.decrypt(
        encrypted_key,
        padding.OAEP(
             mgf = padding.MGF1(algorithm = hashes.SHA256()),
             algorithm = hashes.SHA256(),
             label = None
        )
    )
    return decrypted_key
    
def package_file(encrypted_key, ciphertext):
    encrypted_key = encrypted_key.hex()
    ciphertext = ciphertext.hex()
    filecontent = encrypted_key + ciphertext
    return filecontent
    
def unpackage_file(filecontent):
    encrypted_key = filecontent[:512]
    ciphertext = filecontent[512:]
    encrypted_key = bytes.fromhex(encrypted_key)
    ciphertext = bytes.fromhex(ciphertext)
    return encrypted_key, ciphertext
def main():
    message = input('Enter message to encrypt: ')
    filetype = input('write to file type txt or pickle? ')
    priv_key, pub_key = gen_keys()
    encrypt_file(message, filetype, pub_key)
    decrypted_message = decrypt_file(filetype, priv_key)
    print(decrypted_message)
main()
