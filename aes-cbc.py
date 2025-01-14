import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

def get_key(password):
    # 고정된 SALT 사용 (보안을 위해 랜덤 SALT를 사용하는 것이 권장됨)
    fixed_salt = b'1234567890123456'
    key = PBKDF2(password, fixed_salt, dkLen=32, count=100000)
    return key

def pad(data):
    # AES 블록 크기 (16 바이트)
    block_size = AES.block_size
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def encrypt_file(file_name, password):
    file_path = os.path.join(os.getcwd(), file_name)
    if not os.path.exists(file_path):
        print(f"[-] 파일을 찾을 수 없습니다: {file_path}")
        return
    
    key = get_key(password)
    iv = get_random_bytes(AES.block_size)  # 16바이트 IV 생성
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    padded_data = pad(plaintext)
    ciphertext = cipher.encrypt(padded_data)
    
    # IV + 암호문을 Base64로 인코딩하여 저장
    encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
    encrypted_file = file_name + '_cbc.enc'
    encrypted_path = os.path.join(os.getcwd(), encrypted_file)
    
    with open(encrypted_path, 'w') as f:
        f.write(encrypted_data)
    
    print(f"[+] 파일 암호화 완료: {encrypted_file}")

def decrypt_file(file_name, password):
    file_path = os.path.join(os.getcwd(), file_name)
    if not os.path.exists(file_path):
        print(f"[-] 파일을 찾을 수 없습니다: {file_path}")
        return
    
    key = get_key(password)
    
    with open(file_path, 'r') as f:
        encrypted_data_base64 = f.read()
    
    # Base64 디코딩
    encrypted_data = base64.b64decode(encrypted_data_base64)
    
    iv = encrypted_data[:AES.block_size]  # IV 추출
    ciphertext = encrypted_data[AES.block_size:]  # 암호문 추출
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    try:
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext)
        
        decrypted_file = file_name.replace('_cbc.enc', '')
        decrypted_path = os.path.join(os.getcwd(), decrypted_file)
        
        with open(decrypted_path, 'wb') as f:
            f.write(plaintext)
        
        print(f"[+] 파일 복호화 완료: {decrypted_file}")
    except (ValueError, KeyError) as e:
        print("[-] 복호화 실패: 비밀번호가 틀리거나 파일이 손상되었습니다.")

if __name__ == '__main__':
    action = input("암호화(e) 또는 복호화(d)를 선택하세요: ").strip().lower()
    file_name = input("파일 이름을 입력하세요: ").strip()
    password = input("패스워드를 입력하세요: ").strip()

    if action == 'e':
        encrypt_file(file_name, password)
    elif action == 'd':
        decrypt_file(file_name, password)
    else:
        print("[-] 잘못된 선택입니다.")