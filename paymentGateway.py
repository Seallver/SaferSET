import json
import os
import socket
import ssl
import time

import Protocol_function
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend



def load_paymentGateway_private_key():
    '''load自己的私钥,默认为签名私钥'''
    with open(r"Certification/payment gateway/pay_gateway.key", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def load_paymentGateway_private_key_for_enc():
    '''load自己的私钥,默认为签名私钥'''
    with open(r"Certification/payment gateway/pay_gateway_enc.key", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def load_enc_certification():
    '''load自己的加密证书'''
    with open(r'Certification/payment gateway/pay_gateway_enc.crt', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return cert

def load_sig_certification():
    '''load自己的签名证书'''
    with open(r'Certification/payment gateway/pay_gateway.crt', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return cert

def load_merchant_enc_certification():
    '''load商家的加密证书'''
    with open(r'Certification/merchant/merchant_enc.crt', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return cert


def recv_authREQ(merchant_socket,authREQ):
    '''支付授权阶段：
    接收授权请求信息'''
    print("PaymentGateway: Receive authorization request")
    message = merchant_socket.recv(10240)
    if message:
        authREQ_message = json.loads(message.decode())
        print("receive OI_PI_message:")
        print(json.dumps(authREQ_message, indent=4))
        authREQ.append(authREQ_message)
        merchant_socket.sendall(b"received")
        print()
        return False
    else:
        return True

def verify_authREQ(authREQ,account):
    '''支付授权阶段：
    验证支付授权请求'''
    print("PaymentGateway: Verify authorization request")
    Enc_AuthREQ_Sig = eval(authREQ["Enc_AuthREQ_Sig"])
    Enc_sk2 = eval(authREQ["Enc_sk2"])
    Enc_acc_sk1 = eval(authREQ["Enc_acc_sk1"])
    Enc_OI_PI_Sig = eval(authREQ["Enc_OI_PI_Sig"])
    Merchant_Cert_for_Sig = eval(authREQ["Merchant_Cert_for_Sig"])
    Merchant_Cert_for_Enc = eval(authREQ["Merchant_Cert_for_Enc"])
    Consumer_Cert = eval(authREQ["Consumer_Cert"])
    paymentGateway_private_key_for_enc = load_paymentGateway_private_key_for_enc()

    #验证证书合法性
    err = Protocol_function.verify_cert(Merchant_Cert_for_Enc,"Merchant_Cert_for_Enc")
    if err:
        print("verify cert failed")
        return True
    err = Protocol_function.verify_cert(Merchant_Cert_for_Sig,"Merchant_Cert_for_Sig")
    if err:
        print("verify cert failed")
        return True
    err = Protocol_function.verify_cert(Consumer_Cert,"Consumer_Cert")
    if err:
        print("verify cert failed")
        return True


    #验证authREQ的签名
    ##解密RSA得到对称密码的密钥然后解密AES得到明文
    Sk_2 = Protocol_function.RSA_decrypt_data(paymentGateway_private_key_for_enc,Enc_sk2)
    plaintext = Protocol_function.AES128_CBC_dec(Sk_2,Enc_AuthREQ_Sig)
    ##分离签名和消息
    AuthREQ_Sig = plaintext[:256]
    AuthREQ = plaintext[256:]
    AuthREQ_hash = Protocol_function.hash_sha256(AuthREQ)
    ##获取签名验证公钥
    merchant_public_key_for_sig = Protocol_function.get_PublicKey_from_cert(Merchant_Cert_for_Sig)
    ##验证签名
    err = Protocol_function.sig_verify(merchant_public_key_for_sig,AuthREQ_hash,AuthREQ_Sig,"AuthREQ_Sig")
    if err:
        print("verify authREQ sig failed")
        return True

    #验证OI_PI的签名
    ##解密得到密钥和account
    acc_sk1 = Protocol_function.RSA_decrypt_data(paymentGateway_private_key_for_enc, Enc_acc_sk1)
    ##分离出密钥
    AuthREQ = json.loads(AuthREQ.decode())
    acc = AuthREQ["acc"]
    account.append(acc)
    length = len(acc.encode())
    Sk_1 = acc_sk1[length:]
    ##解密得到明文,分离得到签名和消息,并做好hash
    plaintext = Protocol_function.AES128_CBC_dec(Sk_1, Enc_OI_PI_Sig)
    OI_PI_Sig = plaintext[:256]
    OI_hash = plaintext[256:288]
    PI = plaintext[288:]
    PI_hash = Protocol_function.hash_sha256(PI)
    combined_hash = Protocol_function.hash_sha256(OI_hash+PI_hash)
    ##获取签名验证公钥
    consumer_public_key = Protocol_function.get_PublicKey_from_cert(Consumer_Cert)
    ##验证签名
    err = Protocol_function.sig_verify(consumer_public_key,combined_hash,OI_PI_Sig,"OI_PI_Sig")
    if err:
        print("verify OI_PI sig failed")
        return True

    ##验证tid
    PI = json.loads(PI.decode())
    tid_from_PI = PI["tid"]
    tid_from_authREQ = AuthREQ["tid"]
    if tid_from_PI == tid_from_authREQ:
        print("verify tid success, tid =",tid_from_PI)
    else:
        print("verify tid failed")
        return True

    #输出支付网关得到的PI
    print("PaymentGateway get PI: ")
    print(json.dumps(PI,indent=4))
    print("PaymentGateway get authREQ: ")
    print(json.dumps(AuthREQ,indent=4))
    print()
    return False


def send_authRES(merchant_socket,authREQ,account):
    '''支付授权阶段：
    发送支付授权响应'''
    print("PaymentGateway: Send authorization response")
    AuthRES = b"Allow payment"
    CapTok = b"Proof of payment"
    print("create AuthRES: ",AuthRES.decode())
    print("       CapTok: ",CapTok.decode())
    #加载证书
    Merchant_Cert_for_Enc = eval(authREQ["Merchant_Cert_for_Enc"])
    paymentGateway_Cert_for_enc = load_enc_certification()
    paymentGateway_Cert_for_sig = load_sig_certification()
    #得到签名私钥和商家加密公钥
    payment_gateway_private_key_for_sig = load_paymentGateway_private_key()
    merchant_public_key = Protocol_function.get_PublicKey_from_cert(Merchant_Cert_for_Enc)
    payment_gateway_public_key_for_enc = Protocol_function.get_PublicKey_from_cert(paymentGateway_Cert_for_enc)

    #准备对授权回应进行签名
    AuthRES_hash = Protocol_function.hash_sha256(AuthRES)
    AuthRES_sig = Protocol_function.sign_data(payment_gateway_private_key_for_sig,AuthRES_hash)
    #对签名先进行对称加密
    plaintext = AuthRES_sig + AuthRES
    Sk_3 = os.urandom(48)
    Enc_AuthRES_Sig = Protocol_function.AES128_CBC_enc(Sk_3, plaintext)
    #对AES的密钥进行RSA加密
    Enc_sk3 = Protocol_function.RSA_encrypt_data(merchant_public_key,Sk_3)

    #对请款凭据的签名
    CapTok_hash = Protocol_function.hash_sha256(CapTok)
    CapTok_sig = Protocol_function.sign_data(payment_gateway_private_key_for_sig, CapTok_hash)
    #对签名进行AES
    plaintext = CapTok_sig + CapTok
    Sk_4 = os.urandom(48)
    Enc_CapTok_Sig = Protocol_function.AES128_CBC_enc(Sk_4, plaintext)
    #对AES密钥进行RSA
    plaintext = Sk_4 + account.encode()
    Enc_sk4_acc = Protocol_function.RSA_encrypt_data(payment_gateway_public_key_for_enc, plaintext)

    #构造消息并发送
    message={
        "Enc_sk3":str(Enc_sk3),
        "Enc_AuthRES_Sig":str(Enc_AuthRES_Sig),
        "Enc_sk4_acc":str(Enc_sk4_acc),
        "Enc_CapTok_Sig":str(Enc_CapTok_Sig),
        "PaymentGateway_Cert_for_Sig":str(paymentGateway_Cert_for_sig)
    }
    message_byte = json.dumps(message).encode()
    merchant_socket.sendall(message_byte)
    ack = merchant_socket.recv(1024)
    if ack:
        return False
    return True


def recv_CapREQ(merchant_socket,CapREQ):
    '''支付请款阶段：
    接收支付请款请求'''
    print("PaymentGateway: Receive CapREQ")
    message = merchant_socket.recv(10240)
    if message:
        CapREQ_message = json.loads(message.decode())
        print("receive CapREQ_message:")
        print(json.dumps(CapREQ_message, indent=4))
        CapREQ.append(CapREQ_message)
        merchant_socket.sendall(b"received")
        print()
        return False
    else:
        return True

def verify_CapREQ(CapREQ):
    '''支付请款阶段：
    验证支付请款请求'''
    print("PaymentGateway: Verify CapREQ")
    Enc_sk4_acc = eval(CapREQ["Enc_sk4_acc"])
    Enc_CapTok_Sig = eval(CapREQ["Enc_CapTok_Sig"])
    Enc_sk5 = eval(CapREQ["Enc_sk5"])
    Enc_CapREQ = eval(CapREQ["Enc_CapREQ"])
    Merchant_Cert_for_Sig = eval(CapREQ["Merchant_Cert_for_Sig"])
    PaymentGateway_PrivateKey_for_enc = load_paymentGateway_private_key_for_enc()
    PaymentGateway_Cert_for_sig = load_sig_certification()
    PaymentGateway_PublicKey_for_sig = Protocol_function.get_PublicKey_from_cert(PaymentGateway_Cert_for_sig)
    Merchant_PublicKey_for_Sig = Protocol_function.get_PublicKey_from_cert(Merchant_Cert_for_Sig)

    #验证证书合法性
    err = Protocol_function.verify_cert(Merchant_Cert_for_Sig,"Merchant_Cert_for_Sig")
    if err:
        return True

    #解密得到签名
    Sk_5 = Protocol_function.RSA_decrypt_data(PaymentGateway_PrivateKey_for_enc,Enc_sk5)
    CapREQ_Sig_and_CapREQ = Protocol_function.AES128_CBC_dec(Sk_5,Enc_CapREQ)

    Sk4_acc = Protocol_function.RSA_decrypt_data(PaymentGateway_PrivateKey_for_enc,Enc_sk4_acc)
    Sk_4 = Sk4_acc[:48]
    CapTok_Sig_and_CapTok = Protocol_function.AES128_CBC_dec(Sk_4,Enc_CapTok_Sig)

    #验证签名
    CapREQ_Sig = CapREQ_Sig_and_CapREQ[:256]
    CapREQ_hash = Protocol_function.hash_sha256(CapREQ_Sig_and_CapREQ[256:])
    err = Protocol_function.sig_verify(Merchant_PublicKey_for_Sig,CapREQ_hash,CapREQ_Sig,"CapREQ_Sig")
    if err:
        return True

    CapTok_Sig = CapTok_Sig_and_CapTok[:256]
    CapTok_hash = Protocol_function.hash_sha256(CapTok_Sig_and_CapTok[256:])
    err = Protocol_function.sig_verify(PaymentGateway_PublicKey_for_sig,CapTok_hash,CapTok_Sig,"CapTok_Sig")
    if err:
        return True
    print()
    return False

def send_CapRES(merchant_socket):
    '''支付请款阶段：
    发送支付请款回应'''
    print("PaymentGateway: Send CapRES")
    CapRES = b"A cap response"
    print("create CapRES: ",CapRES.decode())
    PaymentGateway_Cert = load_sig_certification()
    PaymentGateway_PrivateKey_for_Sig = load_paymentGateway_private_key()
    Merchant_Cert_for_Enc = load_merchant_enc_certification()
    Merchant_PublicKey_for_Enc = Protocol_function.get_PublicKey_from_cert(Merchant_Cert_for_Enc)

    #对CapRES签名
    CapRES_hash = Protocol_function.hash_sha256(CapRES)
    CapRES_Sig = Protocol_function.sign_data(PaymentGateway_PrivateKey_for_Sig,CapRES_hash)

    #对签名加密
    Sk_6 = os.urandom(48)
    plaintext = CapRES_Sig + CapRES
    Enc_CapRES_Sig = Protocol_function.AES128_CBC_enc(Sk_6,plaintext)

    #对密钥加密
    Enc_sk6 = Protocol_function.RSA_encrypt_data(Merchant_PublicKey_for_Enc,Sk_6)

    #构造消息
    message = {
        "Enc_sk6":str(Enc_sk6),
        "Enc_CapRES_Sig":str(Enc_CapRES_Sig),
        "PaymentGateway_Cert":str(PaymentGateway_Cert)
    }
    message_byte = json.dumps(message).encode()
    merchant_socket.sendall(message_byte)
    ack = merchant_socket.recv(1024)
    if ack:
        return False
    return True


if __name__ == "__main__":
    ###支付授权阶段###
    print("====================Start: Payment authorization phase====================")
    addr = ('localhost', 54321)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=r'Certification/SSL/merchant_to_PaymentGateway_ssl.crt', keyfile=r'Certification/SSL/merchant_to_PaymentGateway_ssl.key')
    gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    gateway_socket.bind(addr)
    gateway_socket.listen(5)
    secure_socket = context.wrap_socket(gateway_socket, server_side=True)
    merchant_socket, addr = secure_socket.accept()
    print(f"Connected securely by {addr}")
    start = time.time()

    #请求-挑战验证
    err = Protocol_function.challenge_response_server(merchant_socket, Protocol_function.password)
    if err:
        print("Challenge-Response verify failed")
        print()
        merchant_socket.close()
    print()


    #接收授权信息
    authREQ = []
    err = recv_authREQ(merchant_socket,authREQ)
    if err:
        print("recv payment authorization request failed")
        secure_socket.close()

    #验证授权请求
    authREQ = authREQ[0]
    account = []
    err = verify_authREQ(authREQ,account)
    if err:
        print("verify payment authorization request failed")
        secure_socket.close()

    #网关向银行发送支付授权请求，在此不做考虑

    #请求-挑战验证
    err = Protocol_function.challenge_response_server(merchant_socket, Protocol_function.password)
    if err:
        print("Challenge-Response verify failed")
        print()
        merchant_socket.close()
    print()

    #支付授权回应
    account = account[0]
    err = send_authRES(merchant_socket,authREQ,account)
    if err:
        print("send payment authorization response failed")
        secure_socket.close()
    ###支付授权阶段结束###
    merchant_socket.close()
    end = time.time()
    print("====================End: Payment authorization phase====================")
    print("PaymentGateway payment authorization phase cost ", end - start, "s\n")

    ###支付请款阶段###
    print("====================Start: Payment request phase====================")
    #与商家建立连接
    addr = ('localhost', 32106)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=r'Certification/SSL/merchant_to_PaymentGateway_ssl.crt', keyfile=r'Certification/SSL/merchant_to_PaymentGateway_ssl.key')
    gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    gateway_socket.bind(addr)
    gateway_socket.listen(5)
    secure_socket = context.wrap_socket(gateway_socket, server_side=True)
    merchant_socket, addr = secure_socket.accept()
    print(f"Connected securely by {addr}")
    start = time.time()

    #请求-挑战验证
    err = Protocol_function.challenge_response_server(merchant_socket, Protocol_function.password)
    if err:
        print("Challenge-Response verify failed")
        print()
        merchant_socket.close()
    print()

    #接收支付请款请求
    CapREQ = []
    err = recv_CapREQ(merchant_socket,CapREQ)
    if err:
        print("receive CapREQ failed")
        merchant_socket.close()

    #验证支付请款请求
    CapREQ = CapREQ[0]
    err = verify_CapREQ(CapREQ)
    if err:
        print("verify CapREQ failed")
        merchant_socket.close()

    #网关向银行发送支付请款请求，这里不做考虑

    #请求-挑战验证
    err = Protocol_function.challenge_response_server(merchant_socket, Protocol_function.password)
    if err:
        print("Challenge-Response verify failed")
        print()
        merchant_socket.close()
    print()

    #支付请款回应
    err = send_CapRES(merchant_socket)
    if err:
        print("send CapRES failed")
        merchant_socket.close()

    ###支付请款阶段结束###
    merchant_socket.close()
    end = time.time()
    print("====================Start: Payment request phase====================")
    print("PaymentGateway payment request phase cost ", end - start, "s\n")