#ifndef ___HTTPS_SERVER_CORE_H__
#define ___HTTPS_SERVER_CORE_H__

#include <QTcpServer>
#include <QList>
#include <QSslSocket>


enum HttpsReturnCode {
    HTTP_SUCCESS = 200,
    HTTP_FAILURE = 300
};

class HttpsServerCore : public QTcpServer
{
Q_OBJECT
public:

    HttpsServerCore();
    virtual ~HttpsServerCore();

    bool StartListen(const QHostAddress &address, quint16 port);

protected:
    void incomingConnection (int socketDescriptor);

private:
    void _startServerEncryption (QSslSocket *socket);
    void _connectSocketSignals (QSslSocket *socket);

private slots:
    void slot_encrypted ();
    void slot_encryptedBytesWritten (qint64 written);
    void slot_modeChanged (QSslSocket::SslMode mode);
    void slot_peerVerifyError (const QSslError &error);
    void slot_sslErrors (const QList<QSslError> &errors);
    void slot_connected ();
    void slot_disconnected ();
    void slot_error (QAbstractSocket::SocketError);
    void slot_hostFound ();
    void slot_proxyAuthenticationRequired (const QNetworkProxy &, QAuthenticator *);
    void slot_stateChanged (QAbstractSocket::SocketState);
    void slot_readyRead ();
private:
    //! 关闭连接, ssl鉴权失败时调用
    void CloseConnection(QSslSocket *socket);

    struct ReplyInfo{
        QSslSocket      *socket;
        HttpsReturnCode  nHttsCode;
    };

    void HttpsReply(ReplyInfo &replyInfo);

private:

    //! 密钥key
    QSslKey               *m_SslKey;
};



#endif // ___HTTPS_SERVER_CORE_H__
