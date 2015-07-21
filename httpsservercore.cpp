//! qt
#include <QByteArray>
#include <QSslKey>
#include <QFile>
#include <QDebug>
#include <QDir>
#include <QDateTime>
#include <QUrl>
#include <QHttpResponseHeader>
//! self
#include "httpsservercore.h"


//! CA证书
#define CA_CERTIFICATE_FILE          ":/certificate/certificate/ca-cert.pem"
//! 服务证书
#define SERVER_PRIVATEKEY_FILE       ":/certificate/certificate/server-cert.key"
//! 服务密钥
#define SERVER_CERTIFICATE_FILE      ":/certificate/certificate/server-cert.pem"
//! 客户证书
#define CLIENT_CERTIFICATE_FILE      ":/certificate/certificate/client-cert.pem"


HttpsServerCore::HttpsServerCore() :
  m_SslKey(NULL)
{
}

HttpsServerCore::~HttpsServerCore()
{
}

void HttpsServerCore::_connectSocketSignals (QSslSocket *socket)
{
    connect(socket, SIGNAL(encrypted()), this, SLOT(slot_encrypted()));
    connect(socket, SIGNAL(encryptedBytesWritten(qint64)),
            this, SLOT(slot_encryptedBytesWritten(qint64)));
    connect(socket, SIGNAL(modeChanged(QSslSocket::SslMode)),
            this, SLOT(slot_modeChanged(QSslSocket::SslMode)));
    connect(socket, SIGNAL(peerVerifyError(const QSslError &)),
            this, SLOT(slot_peerVerifyError (const QSslError &)));
    connect(socket, SIGNAL(sslErrors(const QList<QSslError> &)),
            this, SLOT(slot_sslErrors(const QList<QSslError> &)));
    connect(socket, SIGNAL(readyRead()),
            this, SLOT(slot_readyRead()));
    connect(socket, SIGNAL(connected()),
            this, SLOT(slot_connected()));
    connect(socket, SIGNAL(disconnected()),
            this, SLOT(slot_disconnected()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
            this, SLOT(slot_error(QAbstractSocket::SocketError)));
    connect(socket, SIGNAL(hostFound()),
            this, SLOT(slot_hostFound()));
    connect(socket, SIGNAL(proxyAuthenticationRequired(const QNetworkProxy &, QAuthenticator *)),
            this, SLOT(slot_proxyAuthenticationRequired(const QNetworkProxy &, QAuthenticator *)));
    connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),
            this, SLOT(slot_stateChanged(QAbstractSocket::SocketState)));
}

bool HttpsServerCore::StartListen(const QHostAddress &address, quint16 port)
{
    //! 密钥文件
    QFile privateKeyFile(SERVER_PRIVATEKEY_FILE);
    privateKeyFile.open(QIODevice::ReadOnly);
    if (!privateKeyFile.isOpen())
    {
        return false;
    }

    if(!m_SslKey)
        m_SslKey = new QSslKey(&privateKeyFile, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey, "123456");

    if(!m_SslKey || m_SslKey->isNull())
    {
        return false;
    }
    if( !this->listen(address, port) )
    {
        return false;
    }
}



//! 有新连接进来
void HttpsServerCore::incomingConnection (int socketDescriptor)
{
   qDebug() << QString("HttpsServerCore::incomingConnection(%1)").arg(socketDescriptor) ;
   QSslSocket *socket = new QSslSocket;
   if (!socket) {
      qDebug("not enough memory to create new QSslSocket");
      return;
   }

   //! socket 描述符写入
   if (!socket->setSocketDescriptor(socketDescriptor))
   {
       qDebug("couldn't set socket descriptor");
       CloseConnection(socket);
       return;
   }
   //! 检查是否是attachedservice
   const QHostAddress &address = socket->peerAddress();
   qDebug() << "host:" << address.toString();

   //! 设置协议
   socket->setProtocol(QSsl::AnyProtocol); // maybe TlsV1

   //! 绑定信号
   _connectSocketSignals(socket);
   //! 开始验证证书
   _startServerEncryption(socket);
}

void HttpsServerCore::_startServerEncryption (QSslSocket *socket)
{
   //! 设置CA证书
   if (!socket->addCaCertificates(CA_CERTIFICATE_FILE))
   {
        qDebug() << QString("Couldn't add CA certificates {%1}").arg(CA_CERTIFICATE_FILE);
        CloseConnection(socket);
        return;
   }

    //! 设置证书
    socket->setLocalCertificate(SERVER_CERTIFICATE_FILE);
    //! 设置密钥
    socket->setPrivateKey(*m_SslKey);
    //! 启动解密
    socket->startServerEncryption();
}

void HttpsServerCore::slot_encrypted ()
{
   qDebug("HttpsServerCore::slot_encrypted"); //! 解密完成
}

void HttpsServerCore::slot_encryptedBytesWritten (qint64 written)
{
   qDebug() << QString("HttpsServerCore::slot_encryptedBytesWritten:{%1}").arg((long) written); //! 3. 字节数
}


void HttpsServerCore::slot_modeChanged (QSslSocket::SslMode mode)
{
   qDebug() << QString("HttpsServerCore::slot_modeChanged(%1)").arg(mode); //! 2. server mode
}

void HttpsServerCore::slot_peerVerifyError (const QSslError &)
{
   qDebug() << "HttpsServerCore::slot_peerVerifyError";
}

void HttpsServerCore::slot_sslErrors (const QList<QSslError> &)
{
   qDebug() << "HttpsServerCore::slot_sslErrors";
}

void HttpsServerCore::slot_readyRead ()
{
    qDebug("HttpsServerCore::slot_readyRead");
    QSslSocket* socket = dynamic_cast<QSslSocket*>(sender());
    //! 获取远程证书
    QSslCertificate cert = socket->peerCertificate();
    if(cert.isNull() || !cert.isValid())
    {
       qDebug("certificate is invalid!");
       CloseConnection(socket);
       return;
    }

    //! 就是client-cert.pem
    qDebug() << cert.toPem();
    //! 版本
    qDebug() << cert.version(); //! 1
    //! 序列号
    qDebug() << cert.serialNumber(); //! 8e:36:d8:e3:db:5e:1b:3f
    //! 指纹,因为指纹算法是sha1,所以用sha1算法
    qDebug() << cert.digest(QCryptographicHash::Sha1).toHex(); //! 4706bf359a3f85f4a75f38b8b58c72df57e70df6
    //! 颁发者
    qDebug() << cert.issuerInfo(QSslCertificate::Organization); //!
    qDebug() << cert.issuerInfo(QSslCertificate::CommonName); //! hsl
    qDebug() << cert.issuerInfo(QSslCertificate::LocalityName); //! beijing
    qDebug() << cert.issuerInfo(QSslCertificate::OrganizationalUnitName); //! .bj
    qDebug() << cert.issuerInfo(QSslCertificate::CountryName); //! ca
    qDebug() << cert.issuerInfo(QSslCertificate::StateOrProvinceName); //! ca-china
    //! 使用者
    qDebug() << cert.subjectInfo(QSslCertificate::Organization); //!
    qDebug() << cert.subjectInfo(QSslCertificate::CommonName); //! hsl
    qDebug() << cert.subjectInfo(QSslCertificate::LocalityName); //! beijing
    qDebug() << cert.subjectInfo(QSslCertificate::OrganizationalUnitName); //! .bj
    qDebug() << cert.subjectInfo(QSslCertificate::CountryName); //! cl
    qDebug() << cert.subjectInfo(QSslCertificate::StateOrProvinceName); //! cl-china
    //! 有效期开始
    qDebug() << cert.effectiveDate(); //! 周五 五月 30 09:52:28 2014
    //! 有效期结束
    qDebug() << cert.expiryDate(); //! 周一 五月 27 09:52:28 2024

    if("abc" != cert.issuerInfo(QSslCertificate::Organization) ||
        "efg" != cert.issuerInfo(QSslCertificate::CommonName))
    {
        qDebug() << QString("certificate is wrong: {Organization, CommonName} = {%1, %2}")
                      .arg(cert.issuerInfo(QSslCertificate::Organization))
                      .arg(cert.issuerInfo(QSslCertificate::CommonName));
        CloseConnection(socket);
        return;
    }

    ///////////////////////////////////////////////////
    //! 至此 SSL验证结束
    ///////////////////////////////////////////////////

    //! 读取请求数据报文
    QByteArray byRecv = socket->readAll();
    //! log
    qDebug() << QString("=== https-server-recv ========== peer-host:{%1}===")
                        .arg(socket->peerAddress().toString());
    qDebug() << QString::fromUtf8(byRecv);

    ReplyInfo replyInfo;
    replyInfo.socket = socket;
    replyInfo.nHttsCode = HTTP_SUCCESS;

    do {
        //! 1. 解析请求
        QHttpRequestHeader header(QString::fromUtf8(byRecv));
        if(!header.isValid())
        {
           replyInfo.nHttsCode = HTTP_FAILURE;
           break;
        }

        //! 1.1 解析header第一行的path,可以用url方式解析
        QUrl url(header.path());
        qDebug() << url.queryItemValue("Account");
        qDebug() << url.queryItemValue("Type");

        //! 1.2 解析header中的value, 主要是获取session-id
        if( !header.hasKey("Cookie") )
        {
            replyInfo.nHttsCode = HTTP_FAILURE;
            break;
        }

       QString strCookie = header.value("Cookie");
       if(strCookie.isEmpty())
       {
           replyInfo.nHttsCode = HTTP_FAILURE;
           break;
       }
       qDebug() << QString("get Cookie:{%1}").arg(strCookie) ;

    } while(0);

    HttpsReply(replyInfo);
}

void HttpsServerCore::HttpsReply(ReplyInfo &replyInfo)
{
    QString strHead;
    QString strBody;
    //! head
    if(HTTP_SUCCESS == replyInfo.nHttsCode)
    {
        strBody = "OK";
        strBody += "\r\n\r\n";
        strHead += QString("HTTP/1.1 %1 OK\r\n").arg(replyInfo.nHttsCode);
        strHead += QString("Content-Length: %1\r\n").arg(strBody.length());
    }
    else
    {
        strHead += QString("HTTP/1.1 %1 Forbidden\r\n").arg(replyInfo.nHttsCode);
    }
    strHead += "Server: AuthorService /0.1\r\n";
    strHead += "Content-Type:text/xml;encoding=utf-8\r\n";
    strHead += "\r\n";
    //! all
    QString strReply = strHead + strBody;

    //! log
    qDebug() << QString("=== https-server-send ========== peer-host:{%1}===")
                        .arg(replyInfo.socket->peerAddress().toString());

    qDebug() << strReply;
    //! write
    replyInfo.socket->write(strReply.toLatin1(), strReply.length());
}

void HttpsServerCore::slot_connected ()
{
   qDebug("HttpsServerCore::slot_connected");
}

void HttpsServerCore::slot_disconnected ()
{
   qDebug("HttpsServerCore::slot_disconnected");
}



void HttpsServerCore::slot_error (QAbstractSocket::SocketError err)
{
    QSslSocket* socket = dynamic_cast<QSslSocket*>(sender());
    qDebug() << QString("HttpsServerCore::slot_error:{%1, %2}").arg(err).arg(socket->errorString());
}



void HttpsServerCore::slot_hostFound ()
{
   qDebug("HttpsServerCore::slot_hostFound");
}

void HttpsServerCore::slot_proxyAuthenticationRequired (const QNetworkProxy &, QAuthenticator *)
{
   qDebug("HttpsServerCore::slot_proxyAuthenticationRequired");
}



void HttpsServerCore::slot_stateChanged (QAbstractSocket::SocketState state)
{
    qDebug() << QString("HttpsServerCore::slot_stateChanged:{%1}").arg(state);
}


void HttpsServerCore::CloseConnection(QSslSocket *socket)
{
    socket->disconnectFromHost();
    socket->deleteLater();
}

