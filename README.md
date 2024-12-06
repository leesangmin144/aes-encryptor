# Simple AES-256-GCM enc/decryptor

## Usage
1. Clone the project and navigate to the folder containing main.py
    - $`cd {cloned folder}/aes-encryptor`
2. Install modules (pycryptodome, argon2-cffi)
    - $`pip install -r requirements.txt`
3. Run main.py to encrypt or decrypt the file
    - Caution: The file to be encrypted or decrypted must be located in the same directory as main.py.
    - You can test using testdata.txt and testdata.txt.enc.