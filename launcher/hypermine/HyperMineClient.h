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

#pragma once

#include <functional>

#include <QObject>
#include <QString>
#include <QUrl>
#include <QVector>

class QNetworkAccessManager;
class QNetworkReply;

/** One server as the panel reports it. */
struct HyperMineServer {
    QString id;
    QString name;
    /** `running`, `stopped`, `starting`, `stopping` or `crashed`. */
    QString state;
    /** The port the game listens on *inside* the tunnel. */
    quint16 mcPort = 25565;
    int playersOnline = 0;
    int playersMax = 0;
    QString javaVersion;
    /** World integrity as of the last failsafe checkpoint, when the panel reports it. */
    bool failsafeKnown = false;
    int damagedRegions = 0;
    qint64 lastCheckpoint = 0;
    int mirroredRegions = 0;

    bool isRunning() const { return state == QLatin1String("running"); }
};

/**
 * Talks to the HyperMine panel's HTTP API over the WireGuard tunnel.
 *
 * The base URL is normally the tunnel peer's address, because that is the only route to
 * the panel: a HyperMine server is not meant to be reachable from the open internet. The
 * client therefore refuses to talk to a plain-HTTP address that is not a tunnel address
 * unless the tunnel is up, rather than sending the panel token in the clear over a
 * public link.
 *
 * ## API contract
 *
 * The panel side of this is not implemented yet. These are the calls the tab makes:
 *
 *     GET  /api/v1/servers
 *          -> { "servers": [ { "id", "name", "state", "mcPort", "playersOnline",
 *                               "playersMax", "javaVersion",
 *                               "failsafe": { "known", "damaged", "lastCheckpoint",
 *                                             "mirrored" } } ] }
 *     POST /api/v1/servers/{id}/start
 *     POST /api/v1/servers/{id}/stop
 *
 * Every request carries `Authorization: Bearer <token>` when a token is set. A non-2xx
 * reply is reported as an error string rather than thrown, so a panel that is merely
 * down reads as "panel unreachable" in the UI instead of a crash.
 */
class HyperMineClient : public QObject {
    Q_OBJECT
   public:
    explicit HyperMineClient(QObject* parent = nullptr);
    ~HyperMineClient() override;

    /**
     * Point the client at a panel. The tunnel is not required to be up, but requests
     * made while it is down are refused when the URL is not a private address -- see
     * the class comment.
     */
    void setBaseUrl(const QUrl& url);
    QUrl baseUrl() const { return m_baseUrl; }

    void setToken(const QString& token);
    QString token() const { return m_token; }

    /**
     * Whether requests may be sent right now. False when the URL is plain HTTP to a
     * non-private address and no tunnel is up, which is the case that would leak the
     * token onto an untrusted network.
     */
    void setTunnelUp(bool up);
    bool tunnelUp() const { return m_tunnelUp; }
    bool canSend() const;

    /** Reason {@link canSend} is false, for the UI. Empty when it is true. */
    QString blockedReason() const;

    /** Fetch the server list. Result arrives via {@link serversReceived}. */
    void fetchServers();

    /** Ask the panel to start or stop a server. Result arrives via {@link actionFinished}. */
    void startServer(const QString& id);
    void stopServer(const QString& id);

    /** True while a request is in flight. */
    bool isBusy() const { return m_busy; }

   signals:
    void serversReceived(const QVector<HyperMineServer>& servers);
    /** Emitted for a failed request, with a message fit to show a user. */
    void requestFailed(const QString& message);
    /** Emitted when a start/stop call has been accepted or rejected. */
    void actionFinished(const QString& serverId, bool success, const QString& message);
    void busyChanged(bool busy);

   private:
    void send(const QUrl& url, const QString& method, std::function<void(int, const QByteArray&)> done);
    void setBusy(bool busy);
    /** POST `api/v1/servers/{id}/{action}` and report the outcome. */
    void postAction(const QString& id, const QString& action, const QString& verb);

    QNetworkAccessManager* m_manager = nullptr;
    QUrl m_baseUrl;
    QString m_token;
    bool m_tunnelUp = false;
    bool m_busy = false;
};
