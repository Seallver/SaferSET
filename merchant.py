import json
import socket
import os
import ssl
import time

import Protocol_function
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime
def load_merchant_private_key():
    '''load自己的私钥'''
    with open(r"Certification/merchant/merchant.key", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def load_merchant_private_key_for_enc():
    '''load自己的解密私钥'''
    with open(r"Certification/merchant/merchant_enc.key", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
def load_certification():
    '''load自己的证书，这里默认指的是签名证书'''
    with open(r'Certification/merchant/merchant.crt', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return cert

def load_enc_certification():
    '''load自己的加密证书'''
    with open(r'Certification/merchant/merchant_enc.crt', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return cert


def load_payGateway_certification():
    '''load支付网关的加密证书，发送给持卡人'''
    with open(r'Certification/payment gateway/pay_gateway_enc.crt', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return cert

def recv_request_and_send_response(consumer_socket,time_start,time_frame):
    '''购买请求阶段：
    接收持卡人的购买请求，并回应'''
    print("Merchant: Receive request and send response")
    request = consumer_socket.recv(2048)
    request = json.loads(request.decode())
    if request:
        print("receive:")
        print(json.dumps(request,indent=4))
        time_start.append(request["time_start"])
        time_frame.append(request["time_frame"])
        response = {
            "tid" : "123",
            "account_m":"234567"
        }
        print("create response: ")
        print(json.dumps(response, indent=4))
        response_byte = json.dumps(response).encode()
        response_hash = Protocol_function.hash_sha256(response_byte)
        response_sig = Protocol_function.sign_data(merchant_private_key,response_hash)
        cert = load_certification()
        pay_gateway_enc_cert = load_payGateway_certification()

        message = {
            "Response":str(response_byte),
            "Response_Sig":str(response_sig),
            "Merchant_Cert":str(cert),
            "PaymentGateway_Cert":str(pay_gateway_enc_cert)
        }
        message_byte = json.dumps(message).encode()
        consumer_socket.sendall(message_byte)
        print()
        return False
    return True

def recv_OI_PI(consumer_socket,OI_PI):
    '''购买请求阶段：
    接收订单信息和支付信息'''
    print("Merchant: Receive order information and payment information")
    message = consumer_socket.recv(8192)
    if message:
        OI_PI_message = json.loads(message.decode())
        print("receive OI_PI_message:")
        print(json.dumps(OI_PI_message, indent=4))
        OI_PI.append(OI_PI_message)
        consumer_socket.sendall(b"received")
        print()
        return False
    else:
        return True

def verify_OI_PI_sig(OI_PI):
    '''购买请求阶段：
    验证订单信息和支付信息签名的合法性'''
    print("Merchant: Verify order information and payment information")
    sig = eval(OI_PI["Sig"])
    OI = eval(OI_PI["OI"])
    PI_hash = eval(OI_PI["PI_hash"])
    OI_hash = Protocol_function.hash_sha256(OI)
    message = Protocol_function.hash_sha256(OI_hash + PI_hash)
    consumer_cert = eval(OI_PI["Consumer_Cert"])

    # 验证持卡人证书
    err = Protocol_function.verify_cert(consumer_cert, "Consumer_Cert")
    if err:
        return True

    # 得到持卡人公钥进行签名验证
    consumer_public_key = Protocol_function.get_PublicKey_from_cert(consumer_cert)
    err = Protocol_function.sig_verify(consumer_public_key,message,sig,"OI_PI_sig")
    if err:
        return True

    #输出商家得到的消息：
    print("Merchant get OI: ")
    OI = json.loads(OI.decode())
    print(json.dumps(OI,indent=4))

    return False

def send_Payment_authorization_request(ssock,OI_PI):
    '''支付授权阶段：
    发送支付授权请求'''
    print("Merchant: Send payment authorization request")
    Enc_acc_sk1 = OI_PI["Enc_acc_sk"]
    Enc_OI_PI_Sig = OI_PI["Enc_Sig"]
    Consumer_Cert = OI_PI["Consumer_Cert"]
    OI = eval(OI_PI["OI"])
    OI = json.loads(OI.decode())
    tid = OI["tid"]

    ##生成支付授权请求信息签名的加密结果
    AuthREQ = {
        "tid":tid,
        "acc":"123456",
        "date":"2024/6/12",
        "cost":"$100"
    }
    print("create AuthREQ:")
    print(json.dumps(AuthREQ, indent=4))
    AuthREQ_byte = json.dumps(AuthREQ).encode()
    AuthREQ_hash = Protocol_function.hash_sha256(AuthREQ_byte)
    auth_sig = Protocol_function.sign_data(merchant_private_key,AuthREQ_hash)
    plaintext = auth_sig + AuthREQ_byte
    Sk_2 = os.urandom(48)
    Enc_AuthREQ_Sig = Protocol_function.AES128_CBC_enc(Sk_2,plaintext)

    ##用RSA加密sk2
    pay_gateway_enc_cert = load_payGateway_certification()
    pay_gateway_enc_public_key = Protocol_function.get_PublicKey_from_cert(pay_gateway_enc_cert)
    Enc_sk2 = Protocol_function.RSA_encrypt_data(pay_gateway_enc_public_key, Sk_2)

    #load商家自己的加密证书和签名证书
    Merchant_Cert_for_Sig = load_certification()
    Merchant_Cert_for_Enc = load_enc_certification()


    #构建出消息
    message = {
        "Enc_sk2":str(Enc_sk2),
        "Enc_AuthREQ_Sig":str(Enc_AuthREQ_Sig),
        "Enc_acc_sk1":Enc_acc_sk1,
        "Enc_OI_PI_Sig":Enc_OI_PI_Sig,
        "Merchant_Cert_for_Sig":str(Merchant_Cert_for_Sig),
        "Merchant_Cert_for_Enc":str(Merchant_Cert_for_Enc),
        "Consumer_Cert":Consumer_Cert
    }
    message_byte = json.dumps(message).encode()
    ssock.sendall(message_byte)
    ack = ssock.recv(1024)
    if ack:
        print()
        return False
    return True

def recv_AuthRES(ssock,AuthRES):
    '''支付授权阶段：
    接收支付授权响应'''
    print("Merchant: Receive authorization response")
    message = ssock.recv(8192)
    if message:
        AuthRES_message = json.loads(message.decode())
        print("receive AuthRES_message:")
        print(json.dumps(AuthRES_message, indent=4))
        AuthRES.append(AuthRES_message)
        ssock.sendall(b"received")
        print()
        return False
    else:
        return True

def verify_AuthRES(AuthRES):
    '''支付授权阶段：
    验证支付授权响应'''
    print("Merchant: Verify authorization response")
    PaymentGateway_Cert_for_Sig = eval(AuthRES["PaymentGateway_Cert_for_Sig"])
    PaymentGateway_public_key_for_Sig = Protocol_function.get_PublicKey_from_cert(PaymentGateway_Cert_for_Sig)
    Merchant_private_key_for_enc = load_merchant_private_key_for_enc()
    Enc_sk3 = eval(AuthRES["Enc_sk3"])
    Enc_AuthRES_Sig = eval(AuthRES["Enc_AuthRES_Sig"])
    #验证支付网关证书
    err = Protocol_function.verify_cert(PaymentGateway_Cert_for_Sig,"PaymentGateway_Cert_for_Sig")
    if err:
        return True
    #验证AuthRES的签名
    ##解密得到对称密码的临时密钥
    Sk_3 = Protocol_function.RSA_decrypt_data(Merchant_private_key_for_enc,Enc_sk3)
    ##通过Sk3解密并分离明文得到签名
    AuthRES_Sig_and_AuthRES = Protocol_function.AES128_CBC_dec(Sk_3,Enc_AuthRES_Sig)
    AuthRES_Sig = AuthRES_Sig_and_AuthRES[:256]
    AuthRES_hash = Protocol_function.hash_sha256(AuthRES_Sig_and_AuthRES[256:])
    ##进行签名验证
    err = Protocol_function.sig_verify(PaymentGateway_public_key_for_Sig,AuthRES_hash,AuthRES_Sig,"AuthRES_Sig")
    if err:
        return True
    print()
    return False


def send_response2(ssock):
    '''支付授权阶段：
    向持卡人回应订单'''
    print("Merchant: Send response2")
    RES2 = b"Payment authorization successful. Ready for delivery"
    print("create response2:",RES2.decode())
    merchant_private_key_for_sig = load_merchant_private_key()
    RES2_hash = Protocol_function.hash_sha256(RES2)
    RES2_Sig = Protocol_function.sign_data(merchant_private_key_for_sig,RES2_hash)
    Merchant_Cert_for_Sig = load_certification()

    #验证交易有没有超时
    time_end = datetime.now()
    time_end = datetime.strftime(time_end, "%Y-%m-%d %H:%M:%S")
    time_end = int(time_end[0:4] + time_end[5:7] + time_end[8:10] + time_end[11:13] + time_end[14:16] + time_end[17:19])
    time_cost = time_end - time_start
    print("time cost:",time_cost,"s")
    if time_cost <= time_frame:
        print("Not timeout. Allow delivery")
    else:
        print("Trading timeout")
        return True

    #构建消息
    message = {
        "RES2_Sig" : str(RES2_Sig),
        "Merchant_Cert_for_Sig":str(Merchant_Cert_for_Sig)
    }

    #发送消息
    message_byte = json.dumps(message).encode()
    ssock.sendall(message_byte)
    ack = ssock.recv(1024)
    if ack:
        return False
    return True

def send_CapREQ(ssock,AuthRES):
    '''支付请款阶段：
    向支付网关发送支付请款请求'''
    print("Merchant: Send CapREQ")
    Enc_sk4_acc = AuthRES["Enc_sk4_acc"]
    Enc_CapTok_Sig = AuthRES["Enc_CapTok_Sig"]
    Merchant_Cert_for_Sig = load_certification()
    Merchant_private_key_for_sig = load_merchant_private_key()
    PaymentGateway_Cert_for_enc = load_payGateway_certification()
    PaymentGateway_public_key_for_enc = Protocol_function.get_PublicKey_from_cert(PaymentGateway_Cert_for_enc)
    #对请求签名
    CapREQ = b"A cap request"
    print("create CapREQ: ",CapREQ)
    CapREQ_hash = Protocol_function.hash_sha256(CapREQ)
    CapREQ_Sig = Protocol_function.sign_data(Merchant_private_key_for_sig,CapREQ_hash)

    #对签名加密
    Sk_5 = os.urandom(48)
    plaintext = CapREQ_Sig + CapREQ
    Enc_CapREQ = Protocol_function.AES128_CBC_enc(Sk_5,plaintext)

    #对密钥加密
    Enc_sk5 = Protocol_function.RSA_encrypt_data(PaymentGateway_public_key_for_enc,Sk_5)

    #构造消息
    message = {
        "Enc_sk4_acc" : Enc_sk4_acc,
        "Enc_CapTok_Sig": Enc_CapTok_Sig,
        "Enc_sk5":str(Enc_sk5),
        "Enc_CapREQ":str(Enc_CapREQ),
        "Merchant_Cert_for_Sig":str(Merchant_Cert_for_Sig)
    }
    message_byte = json.dumps(message).encode()
    ssock.sendall(message_byte)
    ack = ssock.recv(1024)
    if ack:
        print()
        return False
    return True

def recv_CapRES(ssock,CapRES):
    '''支付请款阶段：
    接收支付请款回应'''
    print("Merchant: Receive CapRES")
    message = ssock.recv(8192)
    if message:
        CapRES_message = json.loads(message.decode())
        print("receive CapRES_message:")
        print(json.dumps(CapRES_message, indent=4))
        CapRES.append(CapRES_message)
        ssock.sendall(b"received")
        print()
        return False
    else:
        return True

def verify_CapRES(CapRES,time_start,time_frame):
    '''支付请款阶段：
    验证支付请款回应'''
    print("Merchant: Verify CapRES")
    Enc_sk6 = eval(CapRES["Enc_sk6"])
    Enc_CapRES_Sig = eval(CapRES["Enc_CapRES_Sig"])
    PaymentGateway_Cert = eval(CapRES["PaymentGateway_Cert"])
    Merchant_PrivateKey_for_enc = load_merchant_private_key_for_enc()
    PaymentGateway_PublicKey_for_sig = Protocol_function.get_PublicKey_from_cert(PaymentGateway_Cert)

    #验证证书
    err = Protocol_function.verify_cert(PaymentGateway_Cert,"PaymentGateway_Cert")
    if err:
        return True

    #获取AES密钥
    Sk_6 = Protocol_function.RSA_decrypt_data(Merchant_PrivateKey_for_enc,Enc_sk6)

    #AES解密并分离得到签名
    CapRES_Sig_and_CapRES = Protocol_function.AES128_CBC_dec(Sk_6,Enc_CapRES_Sig)
    CapRES_Sig = CapRES_Sig_and_CapRES[:256]
    CapRES_hash = Protocol_function.hash_sha256(CapRES_Sig_and_CapRES[256:])

    #验证签名
    err = Protocol_function.sig_verify(PaymentGateway_PublicKey_for_sig,CapRES_hash,CapRES_Sig,"CapRES_Sig")
    if err:
        return True
    return False




if __name__ == "__main__":
    merchant_private_key = load_merchant_private_key()
    ###购买请求阶段###
    print("====================Start: Purchase request phase====================")
    #建立连接
    addr = ('localhost', 65432)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=r'Certification/SSL/consumer_to_merchant_ssl.crt', keyfile=r'Certification/SSL/consumer_to_merchant_ssl.key')
    merchant_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    merchant_socket.bind(addr)
    merchant_socket.listen(5)
    secure_socket = context.wrap_socket(merchant_socket, server_side=True)
    consumer_socket, addr = secure_socket.accept()
    print(f"Connected securely by {addr}")
    start = time.time()

    #请求-挑战验证
    err = Protocol_function.challenge_response_server(consumer_socket, Protocol_function.password)
    if err:
        print("Challenge-Response verify failed")
        print()
        consumer_socket.close()
    print()

    #接收购买请求并发送回应，同时记录请求开始时间和允许最长时间段
    time_start = []
    time_frame = []
    err = recv_request_and_send_response(consumer_socket,time_start,time_frame)
    if err:
        print("recv request failed")
        consumer_socket.close()
    time_start = int(time_start[0])
    time_frame = int(time_frame[0])


    #请求-挑战验证
    err = Protocol_function.challenge_response_server(consumer_socket, Protocol_function.password)
    if err:
        print("Challenge-Response verify failed")
        print()
        consumer_socket.close()
    print()

    #接收订单与支付信息
    OI_PI = []
    err = recv_OI_PI(consumer_socket,OI_PI)
    if err:
        print("recv order information and payment information failed")
        consumer_socket.close()
    OI_PI  = OI_PI[0]

    #验证签名信息
    err = verify_OI_PI_sig(OI_PI)
    if err:
        print("verify order information and payment information signature failed")
        consumer_socket.close()

    ###购买请求阶段结束###
    consumer_socket.close()
    end = time.time()
    print("====================End: Purchase request phase====================")
    print("Merchant purchase request phase cost ", end - start, "s\n")


    ###支付授权阶段###
    print("====================Start: Payment authorization phase====================")
    addr = ('localhost', 54321)
    #尝试与支付网关通信，建立SSL安全通信连接
    context = ssl.create_default_context()
    context.load_verify_locations(r'Certification/SSL/merchant_to_PaymentGateway_ssl.crt')
    with socket.create_connection(addr) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as ssock:
            start = time.time()

            # 请求-挑战验证
            err = Protocol_function.challenge_response_client(ssock,Protocol_function.password)
            if err:
                print("Challenge-Response verify failed")
                print()
                ssock.close()
            print()

            # 发送支付授权请求
            err = send_Payment_authorization_request(ssock,OI_PI)
            if err:
                print("send payment authorization request failed")
                ssock.close()

            # 请求-挑战验证
            err = Protocol_function.challenge_response_client(ssock,Protocol_function.password)
            if err:
                print("Challenge-Response verify failed")
                print()
                ssock.close()
            print()

            #接收授权回应
            AuthRES = []
            err = recv_AuthRES(ssock,AuthRES)
            if err:
                print("receive payment authorization response failed")
                ssock.close()

            #验证支付授权回应
            AuthRES = AuthRES[0]
            err = verify_AuthRES(AuthRES)
            if err:
                print("verify payment authorization response failed")
                ssock.close()

    ssock.close()

    #与持卡人建立连接
    addr = ('localhost', 43210)
    #尝试与持卡人通信，建立SSL安全通信连接
    context = ssl.create_default_context()
    context.load_verify_locations(r'Certification/SSL/merchant_to_consumer_ssl.crt')
    with socket.create_connection(addr) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as ssock:

            # 请求-挑战验证
            err = Protocol_function.challenge_response_client(ssock,Protocol_function.password)
            if err:
                print("Challenge-Response verify failed")
                print()
                ssock.close()
            print()

            #得到了支付授权，向持卡人回应订单，商家准备发货
            err = send_response2(ssock)
            if err:
                print("send response2 failed")
                ssock.close()

    ###支付授权阶段结束###
    ssock.close()
    end = time.time()
    print("====================End: Payment authorization phase====================")
    print("Merchant payment authorization phase cost ", end - start, "s\n")


    ###支付请款阶段###
    print("====================Start: Payment request phase====================")
    addr = ('localhost', 32106)
    #尝试与支付网关通信，建立SSL安全通信连接
    context = ssl.create_default_context()
    context.load_verify_locations(r'Certification/SSL/merchant_to_PaymentGateway_ssl.crt')
    with socket.create_connection(addr) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as ssock:
            start = time.time()

            # 请求-挑战验证
            err = Protocol_function.challenge_response_client(ssock,Protocol_function.password)
            if err:
                print("Challenge-Response verify failed")
                print()
                ssock.close()
            print()

            #发送支付请款请求
            err = send_CapREQ(ssock,AuthRES)
            if err:
                print("send CapREQ failed")
                ssock.close()

            # 请求-挑战验证
            err = Protocol_function.challenge_response_client(ssock,Protocol_function.password)
            if err:
                print("Challenge-Response verify failed")
                print()
                ssock.close()
            print()

            #接收支付请款回应
            CapRES = []
            err = recv_CapRES(ssock,CapRES)
            if err:
                print("recv CapRES failed")
                ssock.close()

            #验证支付请款回应
            CapRES = CapRES[0]
            err = verify_CapRES(CapRES,time_start,time_frame)
            if err:
                print("verify CapRES failed")
                ssock.close()

    ###支付请款阶段结束###
    ssock.close()
    end = time.time()
    print("====================End: Payment request phase====================")
    print("Merchant payment request phase cost ", end - start, "s\n")
