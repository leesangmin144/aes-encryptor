# AES Encryption/Decryption Scripts

This repository contains two Python scripts for file encryption and decryption using different AES modes:
1. **aes-gcm.py**: Implements AES encryption and decryption using GCM mode.
2. **aes-cbc.py**: Implements AES encryption and decryption using CBC mode.

Both scripts are standalone and designed to encrypt or decrypt files located in the same directory as the script. They support **Python 3** only.

---

## **aes-gcm.py**

### **Usage**
1. Clone the repository and navigate to the folder containing `aes-gcm.py`.
   ```bash
   $ cd {cloned folder}/aes-encryptor
   ```
2. Install the required modules (`pycryptodome`, `argon2-cffi`).
   ```bash
   $ pip install -r requirements.txt
   ```
3. Run `aes-gcm.py` to encrypt or decrypt files.
   - **Note**: The file to be encrypted or decrypted must be in the same directory as `aes-gcm.py`.
   - Test the script using the provided test files:
     - `testdata.txt` (plaintext)
     - `testdata.txt_gcm.enc` (encrypted with GCM)
     - `testdata.txt_cbc.enc` (encrypted with CBC)

### **Example**
How to run:
```bash
$ python3 aes-gcm.py
```

---

## **aes-cbc.py**

### **Usage**
1. Clone the repository and navigate to the folder containing `aes-cbc.py`.
   ```bash
   $ cd {cloned folder}/aes-encryptor
   ```
2. No additional installation is required. The script runs with Python's standard libraries.
3. Run `aes-cbc.py` to encrypt or decrypt files.
   - **Note**: The file to be encrypted or decrypted must be in the same directory as `aes-cbc.py`.

### **Example**
How to run:
```bash
$ python3 aes-cbc.py
```
---

## **Common Requirements**
- **Python Version**: Both scripts require Python 3.
- **File Location**: The file to be encrypted or decrypted must always be located in the same directory as the script being executed.
```