import socket
import ssl
import json
import os
import Protocol_function
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from datetime import datetime
def load_consumer_private_key():
    '''load自己的私钥'''
    with open(r"Certification/consumer/consumer.key", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def load_certification():
    '''load自己的证书'''
    with open(r'Certification/consumer/consumer.crt', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return cert


def send_purchase_request_and_recv_response(ssock,response):
    '''购买请求阶段：
    持卡人向商家发送购买请求，并接收商家的响应'''
    print("Consumer: Send purchase request and receive response")
    time_start = datetime.now()
    time_start = datetime.strftime(time_start,"%Y-%m-%d %H:%M:%S")
    time_start = time_start[0:4]+time_start[5:7]+time_start[8:10]+time_start[11:13]+time_start[14:16]+time_start[17:19]
    time_frame = 1
    request = {
        "time_start" : str(time_start),
        "time_frame":str(time_frame)
    }
    request = json.dumps(request).encode()
    ssock.sendall(request)
    message_response = ssock.recv(10240)
    if message_response:
        print("receive response:")
        message_from_merchant = json.loads(message_response.decode())
        print(json.dumps(message_from_merchant, indent=4))
        response.append(message_from_merchant)
        print()
        return False
    return True

def verify_response_sig(response,pay_gateway_enc_public_key,ID):
    '''购买请求阶段：
    对响应进行签名验证，确保是商家的回复'''
    print("Consumer: Verify response")
    # 验证响应合法性
    Response_Sig = eval(response["Response_Sig"])
    Merchant_Cert = eval(response["Merchant_Cert"])
    PaymentGateway_Cert = eval(response["PaymentGateway_Cert"])
    Response = json.loads(eval(response["Response"]).decode())
    ID.append(Response["tid"])
    ##验证证书合法性
    err = Protocol_function.verify_cert(Merchant_Cert, "Merchant_Cert_for_Sig")
    if err:
        return True
    err = Protocol_function.verify_cert(PaymentGateway_Cert, "PaymentGateway_Cert_for_Enc")
    if err:
        return True
    ##从证书中获取公钥
    merchant_public_key = Protocol_function.get_PublicKey_from_cert(Merchant_Cert)
    pay_gateway_enc_public_key.append(Protocol_function.get_PublicKey_from_cert(PaymentGateway_Cert))
    ##验证签名合法性
    message = eval(response["Response"])
    message_hash = Protocol_function.hash_sha256(message)
    err = Protocol_function.sig_verify(merchant_public_key,message_hash,Response_Sig,"Purchase_Response_Sig")
    if err:
        return True
    print("Consumer get response: ")
    Response = json.loads(message.decode())
    print(json.dumps(Response, indent=4))
    print()
    return False

#小优化：发送给商家后让商家返回一个ack表示发送成功
def send_OI_PI(ssock,ID):
    '''购买请求阶段：
    向商家发送订单信息和支付信息'''
    print("Consumer: Send order information and payment information")
    tid = ID
    #生成OI、PI信息并签名
    OI_ = {
        "tid":tid,
        "Order":"Item1*1,Item2*3,Item3*8",
        "Total":"$1000"
    }
    OI = json.dumps(OI_).encode()

    date = datetime.now()
    date = datetime.strftime(date,"%Y-%m-%d %H:%M:%S")
    date = date[0:4]+date[5:7]+date[8:10]+date[11:13]+date[14:16]

    PI_ = {
        "tid":tid,
        "CardNumber":"1234-6543-6789-2345",
        "date":date
    }
    PI = json.dumps(PI_).encode()

    print("Consumer create \nOI: ")
    print(json.dumps(OI_,indent=4))
    print("PI: ")
    print(json.dumps(PI_,indent=4))

    account = b"123456"
    OI_hash = Protocol_function.hash_sha256(OI)
    PI_hash = Protocol_function.hash_sha256(PI)
    combined_hash = Protocol_function.hash_sha256(OI_hash+PI_hash)
    Sig = Protocol_function.sign_data(consumer_private_key,combined_hash)

    #生成AES128密钥并进行加密
    ##加密签名
    plaintext = Sig + OI_hash + PI
    Sk_1 = os.urandom(48)
    Enc_Sig = Protocol_function.AES128_CBC_enc(Sk_1,plaintext)

    ##加密账户和临时密钥
    plaintext = account + Sk_1
    Enc_acc_sk = Protocol_function.RSA_encrypt_data(pay_gateway_enc_public_key,plaintext)

    #发送消息
    Cert_consumer = load_certification()
    message = {
        "Sig":str(Sig),
        "OI":str(OI),
        "PI_hash":str(PI_hash),
        "Consumer_Cert":str(Cert_consumer),
        "Enc_acc_sk":str(Enc_acc_sk),
        "Enc_Sig":str(Enc_Sig)
    }
    message_byte = json.dumps(message).encode()
    ssock.sendall(message_byte)
    ack = ssock.recv(1024)
    if ack:
        return False
    print()
    return True

def recv_RES2(merchant_socket,RES2):
    '''支付授权阶段：
    接收支付回应'''
    print("Consumer: Receive response2")
    message = merchant_socket.recv(4096)
    if message:
        RES2_message = json.loads(message.decode())
        print("receive AuthRES_message:")
        print(json.dumps(RES2_message, indent=4))
        RES2.append(RES2_message)
        merchant_socket.sendall(b"received")
        print()
        return False
    return True

def verify_RES2(RES2):
    '''支付授权阶段：
    验证支付回应'''
    print("Consumer: Verify response2")
    RES2_Sig = eval(RES2["RES2_Sig"])
    Merchant_Cert_for_Sig = eval(RES2["Merchant_Cert_for_Sig"])
    #验证证书
    err = Protocol_function.verify_cert(Merchant_Cert_for_Sig,"Merchant_Cert_for_Sig")
    if err:
        return True
    #从证书中提取签名公钥
    Merchant_Public_Key_for_Sig = Protocol_function.get_PublicKey_from_cert(Merchant_Cert_for_Sig)

    #验证签名
    message = b"Payment authorization successful. Ready for delivery"
    message_hash = Protocol_function.hash_sha256(message)
    err = Protocol_function.sig_verify(Merchant_Public_Key_for_Sig,message_hash,RES2_Sig,"RES2_Sig")
    if err:
        return True
    return False

if __name__ == "__main__":
    consumer_private_key = load_consumer_private_key()
    ###购买请求阶段###
    print("====================Start: Purchase request phase====================")
    addr = ('localhost', 65432)
    #尝试与商家通信，建立SSL安全通信连接
    context = ssl.create_default_context()
    context.load_verify_locations(r'Certification/SSL/consumer_to_merchant_ssl.crt')
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

            #发送购买请求并接收响应
            response = []
            err = send_purchase_request_and_recv_response(ssock,response)
            if err:
                print("recv response failed")
                ssock.close()

            ##验证签名合法性,同时保留支付网关的加密公钥,为支付授权阶段使用
            response = response[0]
            pay_gateway_enc_public_key = []
            ID = []
            err = verify_response_sig(response,pay_gateway_enc_public_key,ID)
            if err:
                print("verify response sig failed")
                ssock.close()
            pay_gateway_enc_public_key = pay_gateway_enc_public_key[0]
            ID = ID[0]

            # 请求-挑战验证
            err = Protocol_function.challenge_response_client(ssock,Protocol_function.password)
            if err:
                print("Challenge-Response verify failed")
                print()
                ssock.close()
            print()

            #发送订单与支付信息
            err = send_OI_PI(ssock,ID)
            if err:
                print("send order information and payment information failed")
                ssock.close()

    ###购买请求阶段结束###
    ssock.close()
    end = time.time()
    print("====================End: Purchase request phase====================")
    print("Consumer purchase request phase cost ",end-start,"s\n")

    ###支付授权阶段###

    print("====================Start: Payment authorization phase====================")
    #与商家建立连接
    addr = ('localhost', 43210)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=r'Certification/SSL/merchant_to_consumer_ssl.crt', keyfile=r'Certification/SSL/merchant_to_consumer_ssl.key')
    consumer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    consumer_socket.bind(addr)
    consumer_socket.listen(5)
    secure_socket = context.wrap_socket(consumer_socket, server_side=True)
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

    #接收回应订单
    RES2 = []
    err = recv_RES2(merchant_socket,RES2)
    if err:
        print("recv RES2 failed")
        merchant_socket.close()

    #验证回应订单
    RES2 = RES2[0]
    err = verify_RES2(RES2)
    if err:
        print("verify RES2 failed")
        merchant_socket.close()

    ###支付授权阶段结束###
    merchant_socket.close()
    end = time.time()
    print("====================End: Payment authorization phase====================")
    print("Consumer payment authorization phase cost ", end - start, "s\n")