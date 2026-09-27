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

#include <QElapsedTimer>
#include <QObject>
#include <QString>

class QTcpSocket;
class QTimer;

/**
 * Answers one question: can the game server be reached at this address right now?
 *
 * This exists because WireGuard on Windows cannot tell us. `wg show` needs elevation, so
 * there is no handshake timestamp to read and "the interface exists" is the most the
 * tunnel can honestly claim. A TCP connect to the server's address needs no privileges,
 * works the same on every platform, and answers the question that actually matters:
 * whether pressing Play will get you into a world.
 *
 * Reachability is treated as a fact about the last {@link kFreshWindowMs} rather than
 * an instantaneous result, so one dropped packet does not make the label flap, while a
 * server that really is gone does eventually show as gone.
 */
class ServerProbe : public QObject {
    Q_OBJECT
   public:
    explicit ServerProbe(QObject* parent = nullptr);
    ~ServerProbe() override;

    /** Probe `host:port`, and keep probing on an interval until told otherwise. */
    void watch(const QString& host, quint16 port);
    /** Stop probing. Reachability is reported as unknown immediately. */
    void stop();

    /** True only if the last probe succeeded recently. Never true before a probe runs. */
    bool isReachable() const;
    /** Why the last probe failed, for the UI. Empty when the last probe succeeded. */
    QString lastError() const { return m_lastError; }
    /** True once at least one probe has completed. */
    bool hasResult() const { return m_hasResult; }

    /** How often to re-probe while watching. */
    void setIntervalMs(int msec) { m_timer->setInterval(msec); }

   signals:
    /** Emitted whenever {@link isReachable} may have changed. */
    void resultChanged();

   private slots:
    void probe();

   private:
    QTcpSocket* m_socket = nullptr;
    QTimer* m_timer = nullptr;
    QString m_host;
    quint16 m_port = 0;
    bool m_hasResult = false;
    bool m_reachable = false;
    qint64 m_lastSuccessMs = 0;
    QString m_lastError;
    /** Guards against a second probe starting while one is still in flight. */
    bool m_inFlight = false;
    QElapsedTimer m_clock;
};
