import os
from argon2.low_level import hash_secret_raw, Type
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def get_key(password):
    fixed_salt = b'1234567890123456' # Intentionally using a 16-byte fixed salt, but this should be improved for higher security levels.
    memory_cost = 2**16
    time_cost = 10
    parallelism = 1
    key_size = 32

    # Argon2id 키 생성
    key = hash_secret_raw(
        password.encode('utf-8'),  # 첫 번째 인자로 비밀번호 전달
        fixed_salt,
        time_cost,
        memory_cost,
        parallelism,
        key_size,
        Type.ID,
    )

    return key

def encrypt_file(file_name, password):
    file_path = os.path.join(os.getcwd(), file_name)  # 현재 경로에서 파일 찾기
    if not os.path.exists(file_path):
        print(f"[-] 파일을 찾을 수 없습니다: {file_path}")
        return
    
    key = get_key(password)
    iv = get_random_bytes(12)  # AES-GCM용 12바이트 IV 생성
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # IV + TAG + 암호문을 hex 문자열로 변환
    encrypted_data = (iv + tag + ciphertext).hex()
    
    encrypted_file = file_name + '.enc'
    encrypted_path = os.path.join(os.getcwd(), encrypted_file)
    with open(encrypted_path, 'w') as f:
        f.write(encrypted_data)
    
    print(f"[+] 파일 암호화 완료: {encrypted_file}")

def decrypt_file(file_name, password):
    file_path = os.path.join(os.getcwd(), file_name)  # 현재 경로에서 파일 찾기
    if not os.path.exists(file_path):
        print(f"[-] 파일을 찾을 수 없습니다: {file_path}")
        return
    
    key = get_key(password)
    
    with open(file_path, 'r') as f:
        encrypted_data_hex = f.read()
    
    # hex 데이터를 바이너리로 변환
    encrypted_data = bytes.fromhex(encrypted_data_hex)
    
    iv = encrypted_data[:12]  # IV 추출
    tag = encrypted_data[12:28]  # TAG 추출
    ciphertext = encrypted_data[28:]  # 암호문 추출
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_file = file_name.replace('.enc', '')
        decrypted_path = os.path.join(os.getcwd(), decrypted_file)
        
        with open(decrypted_path, 'wb') as f:
            f.write(plaintext)
        
        print(f"[+] 파일 복호화 완료: {decrypted_file}")
    except ValueError:
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