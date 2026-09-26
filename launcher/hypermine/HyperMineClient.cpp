// SPDX-License-Identifier: GPL-3.0-only
/*
 *  Prism Launcher - Minecraft Launcher
 *  Copyright (C) 2025 IAG Engineers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "HyperMineClient.h"

#include <QAbstractSocket>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

namespace {

/** How long a panel request may take before it is treated as unreachable. */
constexpr int kRequestTimeoutMs = 8000;

HyperMineServer serverFromJson(const QJsonObject& object)
{
    HyperMineServer server;
    server.id = object.value("id").toString();
    server.name = object.value("name").toString();
    server.state = object.value("state").toString();
    server.mcPort = static_cast<quint16>(object.value("mcPort").toInt(25565));
    server.playersOnline = object.value("playersOnline").toInt();
    server.playersMax = object.value("playersMax").toInt();
    server.javaVersion = object.value("javaVersion").toString();

    const QJsonObject failsafe = object.value("failsafe").toObject();
    if (!failsafe.isEmpty()) {
        server.failsafeKnown = true;
        server.damagedRegions = failsafe.value("damaged").toInt();
        server.lastCheckpoint = static_cast<qint64>(failsafe.value("lastCheckpoint").toDouble());
        server.mirroredRegions = failsafe.value("mirrored").toInt();
    }
    return server;
}

/** True when `host` is one the panel could legitimately live on without a tunnel. */
bool isPrivateHost(const QHostAddress& address)
{
    if (address.isNull()) {
        return false;
    }
    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        return address.isInSubnet(QHostAddress("10.0.0.0"), 8) || address.isInSubnet(QHostAddress("172.16.0.0"), 12)
            || address.isInSubnet(QHostAddress("192.168.0.0"), 16) || address == QHostAddress(QHostAddress::LocalHost);
    }
    // Unique-local (fc00::/7) and link-local (fe80::/10).
    return address.isInSubnet(QHostAddress("fc00::"), 7) || address.isInSubnet(QHostAddress("fe80::"), 10)
        || address == QHostAddress(QHostAddress::LocalHostIPv6);
}

}  // namespace

HyperMineClient::HyperMineClient(QObject* parent) : QObject(parent), m_manager(new QNetworkAccessManager(this)) {}

HyperMineClient::~HyperMineClient() = default;

void HyperMineClient::setBaseUrl(const QUrl& url)
{
    m_baseUrl = url;
}

void HyperMineClient::setToken(const QString& token)
{
    m_token = token;
}

void HyperMineClient::setTunnelUp(bool up)
{
    if (m_tunnelUp == up) {
        return;
    }
    m_tunnelUp = up;
    // Deliberately silent. Losing the link is not a failed request, and the page reports
    // it from the tunnel's own state change; emitting requestFailed here would blame a
    // request that was never made.
}

bool HyperMineClient::canSend() const
{
    if (!m_baseUrl.isValid() || m_baseUrl.host().isEmpty()) {
        return false;
    }
    if (m_tunnelUp) {
        return true;
    }
    // Without a tunnel, only a private or loopback destination is acceptable, since the
    // panel token would otherwise go out over whatever network the user happens to be on.
    if (m_baseUrl.scheme() == QLatin1String("https")) {
        return true;
    }
    return isPrivateHost(QHostAddress(m_baseUrl.host()));
}

QString HyperMineClient::blockedReason() const
{
    if (canSend()) {
        return {};
    }
    if (!m_baseUrl.isValid() || m_baseUrl.host().isEmpty()) {
        return tr("No panel address is configured.");
    }
    return tr("Bring up the WireGuard tunnel first. The panel at %1 is not on a private network, so the tab "
              "will not send anything to it in the clear.")
        .arg(m_baseUrl.toString());
}

void HyperMineClient::setBusy(bool busy)
{
    if (m_busy == busy) {
        return;
    }
    m_busy = busy;
    emit busyChanged(m_busy);
}

void HyperMineClient::send(const QUrl& url, const QString& method, std::function<void(int, const QByteArray&)> done)
{
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setTransferTimeout(kRequestTimeoutMs);
    if (!m_token.isEmpty()) {
        request.setRawHeader("Authorization", QByteArray("Bearer ") + m_token.toUtf8());
    }

    QNetworkReply* reply = m_manager->sendCustomRequest(request, method.toUtf8());
    if (!reply) {
        // 0, not -1: callers test `status == 0` to mean "never reached the panel", and a
        // negative code would be rendered as "HTTP -1".
        done(0, QByteArray());
        return;
    }

    connect(reply, &QNetworkReply::finished, this, [reply, done] {
        reply->deleteLater();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (reply->error() != QNetworkReply::NoError && status == 0) {
            // Transport-level failure: DNS, refused, timed out, TLS. Reported as 0 so it
            // is distinguishable from a real HTTP reply, and the reason is dropped because
            // Qt's wording here is not something to put in front of a user.
            done(0, QByteArray());
            return;
        }
        done(status, reply->readAll());
    });
}

void HyperMineClient::fetchServers()
{
    if (!canSend()) {
        emit requestFailed(blockedReason());
        return;
    }
    if (m_busy) {
        // A second refresh while one is already in flight would only race the first to
        // deliver its older answer last.
        return;
    }
    setBusy(true);

    const QUrl url = m_baseUrl.resolved(QUrl("api/v1/servers"));
    send(url, "GET", [this](int status, const QByteArray& body) {
        setBusy(false);

        if (status < 200 || status > 299) {
            emit requestFailed(status == 0
                                   ? tr("Could not reach the panel at %1. Is the tunnel up and the address correct?")
                                         .arg(m_baseUrl.toString())
                                   : tr("The panel returned HTTP %1.").arg(status));
            return;
        }

        QJsonParseError parseError{};
        const QJsonDocument document = QJsonDocument::fromJson(body, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            emit requestFailed(tr("The panel's reply was not valid JSON: %1").arg(parseError.errorString()));
            return;
        }

        const QJsonArray array = document.object().value("servers").toArray();
        QVector<HyperMineServer> servers;
        servers.reserve(array.size());
        for (const QJsonValue& value : array) {
            if (!value.isObject()) {
                continue;
            }
            const HyperMineServer server = serverFromJson(value.toObject());
            if (server.id.isEmpty()) {
                // A record with no id cannot be acted on, so it is dropped rather than
                // shown as a row that does nothing when clicked.
                continue;
            }
            servers << server;
        }
        emit serversReceived(servers);
    });
}

void HyperMineClient::startServer(const QString& id)
{
    postAction(id, "start", tr("start"));
}

void HyperMineClient::stopServer(const QString& id)
{
    postAction(id, "stop", tr("stop"));
}

void HyperMineClient::postAction(const QString& id, const QString& action, const QString& verb)
{
    if (!canSend()) {
        emit requestFailed(blockedReason());
        return;
    }
    if (id.isEmpty()) {
        return;
    }
    setBusy(true);

    // Build the path from segments rather than interpolating the id into a string and
    // patching it afterwards. setPath re-encodes what it is given, and a string replace
    // would also hit matching characters elsewhere in the path -- an id of "1" would
    // corrupt the "1" in "v1".
    QUrl url = m_baseUrl;
    QString path = url.path();
    if (!path.endsWith(QLatin1Char('/'))) {
        path += QLatin1Char('/');
    }
    path += QStringLiteral("api/v1/servers/");
    path += QString::fromLatin1(QUrl::toPercentEncoding(id));
    path += QLatin1Char('/');
    path += action;
    url.setPath(path, QUrl::TolerantMode);

    send(url, "POST", [this, id, verb](int status, const QByteArray&) {
        setBusy(false);
        if (status >= 200 && status <= 299) {
            emit actionFinished(id, true, tr("Asked the panel to %1 the server.").arg(verb));
        } else {
            emit actionFinished(id, false,
                                status == 0 ? tr("The panel could not be reached.")
                                            : tr("The panel refused the %1 request (HTTP %2).").arg(verb).arg(status));
        }
    });
}
