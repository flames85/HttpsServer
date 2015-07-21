#include <QCoreApplication>
#include <QHostAddress>
#include "httpsservercore.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    HttpsServerCore core;
    core.StartListen(QHostAddress::Any, 3000);

    return a.exec();
}
