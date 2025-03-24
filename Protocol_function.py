import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

password = b'di\x15w.K\xb3m\x02KU\xfd\xfb\xa2i\xfcj\x96\xd8f\xb4\xf2\\>2\xe36\xdf\x98\x8b>\xff'
def hash_sha256(message):
    ''' hash函数，形参为字节流'''
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    message_hash = digest.finalize()
    return message_hash

def get_PublicKey_from_cert(cert):
    '''从证书中提取公钥'''
    cert = x509.load_pem_x509_certificate(cert, default_backend())
    public_key = cert.public_key()
    return public_key

def AES128_CBC_enc(key,plaintext):
    '''AES128加密函数，工作模式为CBC'''
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(key[32:]))
    padder = sym_padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

def AES128_CBC_dec(key,ciphertext):
    '''AES128解密函数，工作模式为CBC'''
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(key[32:]))
    decryptor = cipher.decryptor()
    decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()
    return plaintext


def RSA_encrypt_data(public_key, data):
    '''利用公钥对data进行RSA加密'''
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def RSA_decrypt_data(private_key, encrypted_data):
    '''RSA解密'''
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def verify_cert(cert,cert_name):
    '''验证证书合法性'''
    cert = x509.load_pem_x509_certificate(cert, default_backend())
    try:
        cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        print("Cert verify: ",cert_name,": success")
        return False
    except Exception as e:
        print("Cert verify: ",cert_name,": failed:",e)
        return True


def sign_data(private_key, data):
    '''对data进行签名'''
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def sig_verify(public_key,message_hash,sig,sig_name):
    '''签名验证'''
    try:
        public_key.verify(
            sig,
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Sig verify:",sig_name, ": success")
        return False
    except Exception as e:
        print(f"verify {sig_name} error: {e}")
        return True


def challenge_response_client(sock,password):
    sock.sendall("request challenge".encode())
    challenge = sock.recv(1024)
    response = hash_sha256(challenge+password)
    sock.sendall(response)
    verify = sock.recv(1024)
    if verify:
        print(">>> Challenge-Response verify success")
        return False
    return True

def challenge_response_server(sock,password):
    request = sock.recv(1024)
    if request:
        challenge = os.urandom(32)
        sock.sendall(challenge)
        response = sock.recv(1024)
        if response == hash_sha256(challenge+password):
            print(">>> Challenge-Response verify success")
            sock.sendall("pass".encode())
            return False
    return True