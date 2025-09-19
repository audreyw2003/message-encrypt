# Hybrid File Encryption Script

This Python script provides a secure hybrid encryption system for storing and retrieving messages using a combination of symmetric (AES) and asymmetric (RSA) encryption. It supports saving encrypted data in either plaintext `.txt` or serialized `.pickle` formats.

---

## Features

- AES-256 encryption with CBC mode and PKCS7 padding  
- RSA-2048 key generation and OAEP padding for secure key exchange  
- File packaging and unpackaging using hex encoding  
- Dual output formats: human-readable `.txt` or binary `.pk1`  
- End-to-end encryption and decryption workflow with automatic key handling

---

## How It Works

1. **Key Generation**  
   RSA key pair is generated using `gen_keys()`.

2. **Encryption**  
   - A random AES key and IV are generated.  
   - The plaintext message is padded and encrypted using AES.  
   - The AES key and IV are concatenated and encrypted using the RSA public key.  
   - The encrypted key and ciphertext are hex-encoded and packaged together.  
   - The result is saved as either a `.txt` or `.pk1` file.

3. **Decryption**  
   - The file is read and unpackaged.  
   - The encrypted AES key and IV are decrypted using the RSA private key.  
   - The ciphertext is decrypted using AES and unpadded to retrieve the original message.

---

## Usage

Run the script directly: 
```bash
python encrypt_script.py
```
## Interactive Usage

You'll be prompted to:

- Enter a message to encrypt  
- Choose a file format: `txt` or `pickle`

### Example Interaction

Enter message to encrypt: Hello, world! write to file type txt or pickle? txt Hello, world!

The encrypted message will be saved to:

- `encrypted_message.txt` (if `txt`)  
- `encrypted_message.pk1` (if `pickle`)

---

## File Structure

| Function               | Purpose                                      |
|------------------------|----------------------------------------------|
| `gen_keys()`           | Generates RSA key pair                       |
| `symmetric_encryption()` | Encrypts plaintext with AES               |
| `symmetric_decryption()` | Decrypts AES ciphertext                   |
| `asymmetric_encrypt()` | Encrypts AES key + IV with RSA              |
| `asymmetric_decrypt()` | Decrypts AES key + IV with RSA              |
| `package_file()`       | Hex-encodes and concatenates encrypted data |
| `unpackage_file()`     | Splits and decodes file content             |
| `encrypt_file()`       | Full encryption pipeline                     |
| `decrypt_file()`       | Full decryption pipeline                     |

---

## Security Notes

- AES key and IV are randomly generated per message  
- RSA encryption uses OAEP padding with SHA-256  
- Hex encoding ensures compatibility with text-based formats

---

## Requirements

- Python 3.6+  
- `cryptography` library

Install dependencies:

```bash
pip install cryptography
