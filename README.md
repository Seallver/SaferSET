- 代码分为三个参与方分别实现，并用socket模块进行本地通信。

- 在启用时先运行merchant.py和paymentGateway.py，二者启动后对端口保持监听，这时再启动consumer.py进行连接

- 代码中每个函数作用都在开头标有注释

- 如果有某处验证不通过通信会中断，会在输出窗口输出错误信息：...... failed

- Protocol_function.py是三方都会用到的一些函数，定义在这里方便复用

- Certification内部是各个参与方的证书，包括签名和加密证书，都是通过openssl本地生成的，其中SSL文件夹的证书是用于ssl库实现TSL安全连接需要的证书