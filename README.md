# HttpsServer
qt https server(ssl双向认证)

为便于说明现规定以下文件名称:


服务证书|            server-cert.pem

服务密钥 |           server-cert.key

客户证书  |          client-cert.pem

客户私钥   |         client-cert.key

浏览器证书  |        client.p12


用qt简单实现了HTTPS服务器:
1) 服务端(也就是本代码生成的程序),需要CA证书, 服务证书, 服务密钥.

2) 客户端(未实现,但可以用浏览器测试), 需要CA证书, client.p12(或client-cert.key和client-cert.pem).

3) 以上文件生成方式, 请参照openssl的官方.

