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

#include "ServerProbe.h"

#include <QTcpSocket>
#include <QTimer>

namespace {

/**
 * How long a successful probe keeps counting as "reachable".
 *
 * Long enough that a single dropped packet does not make the status flap, short enough
 * that a server which has really gone stops being reported as joinable.
 */
constexpr qint64 kFreshWindowMs = 15000;

/** A connect attempt that has not answered by now has answered no. */
constexpr int kConnectTimeoutMs = 4000;

}  // namespace

ServerProbe::ServerProbe(QObject* parent) : QObject(parent)
{
    m_clock.start();

    m_timer = new QTimer(this);
    m_timer->setInterval(5000);
    connect(m_timer, &QTimer::timeout, this, &ServerProbe::probe);

    m_socket = new QTcpSocket(this);
    connect(m_socket, &QTcpSocket::connected, this, [this] {
        m_inFlight = false;
        m_hasResult = true;
        m_reachable = true;
        m_lastError.clear();
        m_lastSuccessMs = m_clock.elapsed();
        m_socket->abort();
        emit resultChanged();
    });
    connect(m_socket, &QTcpSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        m_inFlight = false;
        m_hasResult = true;
        m_reachable = false;
        m_lastError = m_socket->errorString();
        m_socket->abort();
        emit resultChanged();
    });
}

ServerProbe::~ServerProbe() = default;

void ServerProbe::watch(const QString& host, quint16 port)
{
    if (host.isEmpty() || port == 0) {
        stop();
        return;
    }
    const bool changed = (host != m_host) || (port != m_port);
    m_host = host;
    m_port = port;
    if (changed) {
        // A different target is a different question: the previous answer no longer
        // applies, so drop it rather than showing a stale verdict.
        m_hasResult = false;
        m_reachable = false;
        m_lastError.clear();
        m_lastSuccessMs = 0;
        emit resultChanged();
    }
    m_timer->start();
    probe();
}

void ServerProbe::stop()
{
    m_timer->stop();
    m_socket->abort();
    m_inFlight = false;
    m_host.clear();
    m_port = 0;
    if (m_hasResult || m_reachable) {
        m_hasResult = false;
        m_reachable = false;
        m_lastError.clear();
        emit resultChanged();
    }
}

bool ServerProbe::isReachable() const
{
    if (!m_hasResult) {
        return false;
    }
    if (!m_reachable) {
        return false;
    }
    // A success that has aged out is not a success any more, and the interval timer will
    // correct it shortly. Reporting false meanwhile is the honest answer.
    return (m_clock.elapsed() - m_lastSuccessMs) <= kFreshWindowMs;
}

void ServerProbe::probe()
{
    if (m_host.isEmpty() || m_port == 0 || m_inFlight) {
        return;
    }
    m_inFlight = true;
    m_socket->abort();
    m_socket->connectToHost(m_host, m_port);

    // A TCP connect to a closed port is refused quickly on a healthy network but can hang
    // behind a black-holed route, so the attempt is bounded rather than left to the socket.
    QTimer::singleShot(kConnectTimeoutMs, this, [this] {
        if (!m_inFlight) {
            return;
        }
        m_inFlight = false;
        m_hasResult = true;
        m_reachable = false;
        m_lastError = tr("No answer within %1 seconds.").arg(kConnectTimeoutMs / 1000);
        m_socket->abort();
        emit resultChanged();
    });
}
