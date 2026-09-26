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

#include "WireGuardTunnel.h"

#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTimer>

#include "LoggedProcess.h"
#include "MessageLevel.h"

namespace {

/**
 * How often the tunnel is polled while it is up.
 *
 * This is a status query, not a health check, so it does not need to be frequent enough
 * to catch a millisecond blip. Five seconds also keeps a hand-brought tunnel and a
 * launcher-managed one indistinguishable to the user.
 */
constexpr int kPollIntervalMs = 5000;
constexpr int kStartTimeoutMs = 12000;

/**
 * Consecutive failed `wg show` calls tolerated while a tunnel is up before it is called
 * down. One failure is routinely just a busy tunnel service; a run of them is not.
 */
constexpr int kFailureTolerance = 3;

/**
 * Whether `text` is a plausible `host:port` endpoint.
 *
 * `wg` emits either a real endpoint or the literal `(none)`, so this is only ever a guard
 * against a truncated or unexpected reply -- but a cheap one, since whatever fails it
 * would otherwise be rendered in the status line.
 */
bool looksLikeEndpoint(const QString& text)
{
    const int colon = text.lastIndexOf(':');
    if (colon <= 0 || colon == text.size() - 1) {
        return false;
    }
    bool ok = false;
    const uint port = text.mid(colon + 1).toUInt(&ok);
    return ok && port > 0 && port <= 65535;
}

}  // namespace

WireGuardTunnel::WireGuardTunnel(QObject* parent) : QObject(parent)
{
    m_pollTimer = new QTimer(this);
    m_pollTimer->setInterval(kPollIntervalMs);
    connect(m_pollTimer, &QTimer::timeout, this, &WireGuardTunnel::refresh);
}

WireGuardTunnel::~WireGuardTunnel() = default;

QString WireGuardTunnel::wgToolPath()
{
#if defined(Q_OS_WIN)
    // wg.exe is the CLI. wireguard.exe next to it is only the GUI front end and does not
    // implement `wg show`, so it is deliberately not used for status queries.
    static const QStringList candidates = {
        "C:/Program Files/WireGuard/wg.exe",
        "C:/Program Files (x86)/WireGuard/wg.exe",
    };
    for (const QString& candidate : candidates) {
        if (QFileInfo::exists(candidate)) {
            return candidate;
        }
    }
    const QString found = QStandardPaths::findExecutable("wg.exe");
    return found.isEmpty() ? QString{} : found;
#else
    return QStandardPaths::findExecutable("wg");
#endif
}

QString WireGuardTunnel::installToolPath()
{
#if defined(Q_OS_WIN)
    // Only wireguard.exe implements /installtunnels, by talking to the tunnel service.
    static const QStringList candidates = {
        "C:/Program Files/WireGuard/wireguard.exe",
        "C:/Program Files (x86)/WireGuard/wireguard.exe",
    };
    for (const QString& candidate : candidates) {
        if (QFileInfo::exists(candidate)) {
            return candidate;
        }
    }
    const QString found = QStandardPaths::findExecutable("wireguard.exe");
    return found.isEmpty() ? QString{} : found;
#else
    return {};
#endif
}

bool WireGuardTunnel::watchToolAvailable()
{
    return !wgToolPath().isEmpty();
}

bool WireGuardTunnel::controlToolAvailable()
{
    if (!watchToolAvailable()) {
        return false;
    }
#if defined(Q_OS_WIN)
    // Both halves are needed: wg.exe to read state, wireguard.exe to install the tunnel.
    return !installToolPath().isEmpty();
#else
    return !wgQuickPath().isEmpty() && !QStandardPaths::findExecutable("pkexec").isEmpty();
#endif
}

QString WireGuardTunnel::controlToolHint()
{
    if (!watchToolAvailable()) {
#if defined(Q_OS_WIN)
        return tr("WireGuard was not found. Install it from https://www.wireguard.com/install/ and restart the launcher.");
#else
        return tr("The 'wg' tool was not found. Install wireguard-tools to let HyperMine manage the tunnel.");
#endif
    }
#if defined(Q_OS_WIN)
    if (installToolPath().isEmpty()) {
        return tr("wireguard.exe was not found, so the launcher cannot install the tunnel. It can still watch a "
                  "tunnel you bring up yourself.");
    }
    return {};
#else
    if (wgQuickPath().isEmpty()) {
        return tr("'wg-quick' was not found. Install wireguard-tools, or bring the tunnel up yourself with "
                  "'sudo wg-quick up' and HyperMine will still watch it.");
    }
    return tr("'pkexec' was not found, so the launcher cannot elevate to bring the tunnel up. Bring it up "
              "yourself with 'sudo wg-quick up' and HyperMine will still watch it.");
#endif
}

QString WireGuardTunnel::wgQuickPath()
{
    return QStandardPaths::findExecutable("wg-quick");
}

/**
 * Build the program and arguments that bring the tunnel up.
 *
 * On Linux `wg-quick` needs root, so it is run under `pkexec` with the absolute path
 * passed as argv[0] -- the elevation helper will not search PATH itself.
 */
QPair<QString, QStringList> WireGuardTunnel::upInvocation(const QString& conf)
{
#if defined(Q_OS_WIN)
    // The interface name comes from the file name, which is why the conf is written to a
    // canonical location before this is called.
    return { installToolPath(), { "/installtunnels", conf } };
#else
    return { QStringLiteral("pkexec"), { wgQuickPath(), QStringLiteral("up"), conf } };
#endif
}

QPair<QString, QStringList> WireGuardTunnel::downInvocation(const QString& interfaceName, const QString& conf)
{
#if defined(Q_OS_WIN)
    Q_UNUSED(conf)
    return { installToolPath(), { "/uninstalltunnels", interfaceName } };
#else
    Q_UNUSED(interfaceName)
    return { QStringLiteral("pkexec"), { wgQuickPath(), QStringLiteral("down"), conf } };
#endif
}

void WireGuardTunnel::setConfigDir(const QDir& dir)
{
    m_configDir = dir;
}

QString WireGuardTunnel::confPath() const
{
    if (m_interface.name.isEmpty() || m_configDir.path().isEmpty()) {
        return {};
    }
    return m_configDir.absoluteFilePath(m_interface.name + ".conf");
}

void WireGuardTunnel::setInterface(const WireGuardInterface& iface)
{
    // Any re-import supersedes what is known about the old one, and a bring-up in flight
    // was for the old keys. Not just a name change: the same file name with different
    // keys is just as much a different tunnel.
    stopPolling();
    killPending();
    m_status = Status{};
    m_consecutiveFailures = 0;
    m_interface = iface;

    QString error;
    if (!writeConfFile(&error)) {
        setState(State::Failed, error);
        return;
    }
    setState(State::Down);
}

void WireGuardTunnel::clearInterface()
{
    // Without this the poll timer kept ticking against a tunnel that no longer exists,
    // and a bring-up already in flight would still call back to set a failure.
    stopPolling();
    killPending();
    m_interface = WireGuardInterface{};
    m_status = Status{};
    m_consecutiveFailures = 0;
    emit statusChanged();
}

void WireGuardTunnel::writeConfFile(QString* error) const
{
    const QString path = confPath();
    if (path.isEmpty()) {
        if (error) {
            *error = tr("No config directory is set for the tunnel.");
        }
        return false;
    }

    if (!m_configDir.mkpath(QStringLiteral("."))) {
        if (error) {
            *error = tr("Could not create the tunnel config directory at %1.").arg(m_configDir.path());
        }
        return false;
    }

    const auto& iface = m_interface;
    QStringList lines;
    lines << "# Generated by HyperMine. Edits are overwritten when the tunnel is re-imported.";
    lines << "[Interface]";
    lines << QStringLiteral("PrivateKey = %1").arg(iface.privateKey);
    if (!iface.addresses.isEmpty()) {
        lines << QStringLiteral("Address = %1").arg(iface.addresses.join(QStringLiteral(", ")));
    }
    if (!iface.dns.isEmpty()) {
        lines << QStringLiteral("DNS = %1").arg(iface.dns.join(QStringLiteral(", ")));
    }
    if (iface.hasMtu) {
        lines << QStringLiteral("MTU = %1").arg(iface.mtu);
    }
    lines << QStringLiteral("SaveConfig = false");
    lines << QString();
    lines << "[Peer]";
    lines << QStringLiteral("PublicKey = %1").arg(iface.peer.publicKey);
    if (!iface.peer.presharedKey.isEmpty()) {
        lines << QStringLiteral("PresharedKey = %1").arg(iface.peer.presharedKey);
    }
    if (!iface.peer.allowedIps.isEmpty()) {
        lines << QStringLiteral("AllowedIPs = %1").arg(iface.peer.allowedIps.join(QStringLiteral(", ")));
    }
    if (!iface.peer.endpoint.isEmpty()) {
        lines << QStringLiteral("Endpoint = %1").arg(iface.peer.endpoint);
    }
    if (iface.peer.persistentKeepalive > 0) {
        lines << QStringLiteral("PersistentKeepalive = %1").arg(iface.peer.persistentKeepalive);
    }
    lines << QString();

    const QByteArray payload = lines.join(QLatin1Char('\n')).toUtf8();

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) {
            *error = tr("Could not write the tunnel config to %1: %2").arg(path, file.errorString());
        }
        return false;
    }
    if (file.write(payload) != payload.size()) {
        if (error) {
            *error = tr("Could not write the whole tunnel config to %1.").arg(path);
        }
        return false;
    }
    file.close();

#if !defined(Q_OS_WIN)
    // wg-quick refuses to use a private key that other users can read.
    if (!file.setPermissions(QFile::ReadOwner | QFile::WriteOwner)) {
        if (error) {
            *error = tr("Could not restrict permissions on %1; wg-quick will reject it.").arg(path);
        }
        return false;
    }
#endif
    return true;
}

void WireGuardTunnel::runTool(const QString& program, const QStringList& args, std::function<void(int, const QString&)> done)
{
    killPending();

    auto* process = new LoggedProcess(QStringConverter::Utf8, this);
    m_process = process;

    // LoggedProcess reports stderr line by line, but it also emits its own bookkeeping
    // ("Process exited with code 0.") on every run. Those are forwarded only for
    // bring-up and teardown, where a single run is worth narrating; a status poll runs
    // every few seconds and would otherwise bury the log in noise.
    if (m_forwardToolLogs) {
        connect(process, &LoggedProcess::log, this, [this](const QStringList& lines, MessageLevel) {
            for (const QString& line : lines) {
                if (!line.trimmed().isEmpty()) {
                    emit logMessage(line);
                }
            }
        });
    }

    // A process that cannot be started never emits finished(), so m_process would stay
    // set for good and the isBusy() guard in refresh() would wedge every later query.
    connect(process, &QProcess::errorOccurred, this, [this, process, done](QProcess::ProcessError error) {
        if (error != QProcess::FailedToStart) {
            return;
        }
        if (m_process == process) {
            m_process = nullptr;
        }
        const QString reason = process->errorString();
        process->deleteLater();
        stopPolling();
        setState(State::Failed, tr("Could not run '%1': %2").arg(program, reason));
        done(-1, reason.toUtf8());
    });

    connect(process, &QProcess::finished, this, [this, process, done](int exitCode, QProcess::ExitStatus status) {
        // Only stdout is parsed. Concatenating stderr would shift every field index if wg
        // printed a warning, turning a valid dump into silently wrong values.
        const QString output = QString::fromUtf8(process->readAllStandardOutput());
        if (m_process == process) {
            m_process = nullptr;
        }
        process->deleteLater();
        if (status == QProcess::CrashExit) {
            done(-1, tr("The WireGuard tool crashed."));
            return;
        }
        done(exitCode, output);
    });

    process->start(program, args);
}

void WireGuardTunnel::killPending()
{
    if (!m_process) {
        return;
    }
    // The finished handler must not run for a process we cancelled on purpose. QProcess
    // still emits finished(CrashExit) after kill(), and without this disconnect a
    // cancelled query would report itself as a crash -- which, on the bring-up path,
    // would overwrite a perfectly good result with a bogus failure.
    disconnect(m_process, &QProcess::finished, nullptr, nullptr);
    m_process->kill();
    m_process->deleteLater();
    m_process = nullptr;
}

void WireGuardTunnel::stopPolling()
{
    m_pollTimer->stop();
}

void WireGuardTunnel::setState(State state, const QString& error)
{
    const bool changed = (m_status.state != state) || (m_status.error != error);
    m_status.state = state;
    m_status.error = error;
    if (changed) {
        emit statusChanged();
    }
}

void WireGuardTunnel::bringUp()
{
    if (!hasInterface()) {
        setState(State::Failed, tr("No tunnel is loaded. Import a WireGuard .conf file first."));
        return;
    }
    if (isUp() || m_status.state == State::Starting) {
        return;
    }
    if (!controlToolAvailable()) {
        setState(State::Failed, controlToolHint());
        return;
    }

    QString error;
    if (!writeConfFile(&error)) {
        setState(State::Failed, error);
        return;
    }

    const QString conf = confPath();
    m_upSince.start();
    m_consecutiveFailures = 0;
    const auto [program, args] = upInvocation(conf);
    setForwardToolLogs(true);

    emit logMessage(tr("Bringing up the %1 tunnel...").arg(m_interface.name));
    setState(State::Starting);

    // /installtunnels returns as soon as the service is asked to start, so the interface
    // showing up is confirmed by polling rather than by the exit code. The timer is not
    // restarted unnecessarily -- stopPolling first so a repeated click does not reset it.
    stopPolling();
    m_pollTimer->start();

    runTool(program, args, [this](int exitCode, const QString& output) {
        if (exitCode != 0) {
            const QString detail = output.trimmed();
            setState(State::Failed,
                     detail.isEmpty() ? tr("WireGuard could not bring the tunnel up (exit code %1).").arg(exitCode)
                                      : tr("WireGuard could not bring the tunnel up: %1").arg(detail));
            m_pollTimer->stop();
            return;
        }
        emit logMessage(tr("Tunnel %1 requested; waiting for the interface.").arg(m_interface.name));
        refresh();
    });
}

void WireGuardTunnel::bringDown()
{
    if (!hasInterface()) {
        setState(State::Down);
        return;
    }
    if (!controlToolAvailable()) {
        // Report the reason without pretending the tunnel changed state: it did not.
        m_status.error = controlToolHint();
        emit statusChanged();
        return;
    }
    if (m_status.state == State::Down) {
        return;
    }

    const QString conf = confPath();
    const auto [program, args] = downInvocation(m_interface.name, conf);
    setForwardToolLogs(true);

    emit logMessage(tr("Taking down the %1 tunnel...").arg(m_interface.name));
    stopPolling();

    runTool(program, args, [this](int exitCode, const QString& output) {
        if (exitCode != 0) {
            const QString detail = output.trimmed();
            // Not fatal: the interface may already be gone, which is the goal anyway.
            emit logMessage(detail.isEmpty() ? tr("wg reported exit code %1 while taking the tunnel down.").arg(exitCode)
                                            : tr("wg: %1").arg(detail));
        }
        m_status.lastHandshake = 0;
        setState(State::Down);
    });
}

void WireGuardTunnel::forget()
{
    // Tear down first, then discard. clearInterface() cancels any in-flight tool, so
    // discarding while an uninstall is still running would abort it and leave the tunnel
    // installed at the OS level with no configuration left to bring it down.
    if (m_status.state == State::Up || m_status.state == State::Starting) {
        connect(this, &WireGuardTunnel::statusChanged, this, [this] {
            if (m_status.state == State::Down) {
                // Only ever connected to the tunnel itself, so this cannot disturb the
                // page's own connection.
                disconnect(this, &WireGuardTunnel::statusChanged, this, nullptr);
                clearInterface();
            }
        });
        bringDown();
        return;
    }
    clearInterface();
}

void WireGuardTunnel::refresh()
{
    if (!hasInterface()) {
        return;
    }
    // One tool at a time. Without this a 1.5s tick that lands while the previous `wg show`
    // is still running would cancel it, and the cancelled call's own error path would
    // conclude that a perfectly healthy tunnel had gone down.
    if (isBusy()) {
        return;
    }
    const QString wg = wgToolPath();
    if (wg.isEmpty()) {
        stopPolling();
        setState(m_status.state, tr("The 'wg' tool is no longer available."));
        return;
    }

    const QString name = m_interface.name;
    setForwardToolLogs(false);

    // One `dump` rather than separate `latest-handshakes` / `listen-port` / `endpoints`
    // queries: it is a single round trip, and sibling queries started from one callback
    // would cancel each other.
    runTool(wg, { "show", name, "dump" }, [this, name](int exitCode, const QString& output) {
        if (exitCode != 0) {
            // The interface is gone, or wg could not answer this once. Those are not the
            // same thing: a service that is briefly busy during a roaming rekey should
            // not be reported as a tunnel that died. Only a run of failures is believed.
            ++m_consecutiveFailures;
            m_status.lastHandshake = 0;
            m_status.listenPort = 0;

            if (m_status.state == State::Starting) {
                if (m_upSince.isValid() && m_upSince.elapsed() < kStartTimeoutMs) {
                    return;  // still inside the bring-up window; keep waiting
                }
                stopPolling();
                setState(State::Failed,
                         tr("The tunnel did not come up within %1 seconds. Check that the endpoint is reachable "
                            "and that the keys match the server.")
                             .arg(kStartTimeoutMs / 1000));
                return;
            }
            if (m_status.state == State::Up && m_consecutiveFailures < kFailureTolerance) {
                return;  // treat as transient and let the next poll decide
            }
            if (m_status.state == State::Up) {
                emit logMessage(tr("The %1 tunnel went down.").arg(name));
            }
            stopPolling();
            setState(State::Down);
            return;
        }
        m_consecutiveFailures = 0;

        const auto lines = output.split(QRegularExpression("\r\n|\n|\r"), Qt::SkipEmptyParts);
        if (lines.isEmpty()) {
            // A successful exit with nothing to parse is not a usable dump. Treat it as
            // "no information" rather than reporting a healthy tunnel off no data.
            return;
        }
        bool changed = false;

        // Line 1: private-key  public-key  listening-port  fwmark
        {
            const auto fields = lines.at(0).split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
            if (fields.size() >= 3) {
                bool ok = false;
                const quint16 port = static_cast<quint16>(fields.at(2).toUShort(&ok));
                if (ok && port != m_status.listenPort) {
                    m_status.listenPort = port;
                    changed = true;
                }
            }
        }

        // Line 2: peer-key  preshared-key  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
        if (lines.size() >= 2) {
            const auto fields = lines.at(1).split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
            if (fields.size() >= 5) {
                bool ok = false;
                // 0 means "never handshaked", which is what to expect for the first few
                // seconds after the interface appears.
                const qint64 stamp = fields.at(4).toLongLong(&ok);
                const qint64 handshake = ok ? stamp : 0;
                if (handshake != m_status.lastHandshake) {
                    m_status.lastHandshake = handshake;
                    changed = true;
                    if (handshake) {
                        emit logMessage(tr("Handshake with the %1 endpoint succeeded.").arg(name));
                    }
                }

                // `wg` writes "(none)" rather than leaving the field out. Anything else
                // has to look like host:port before it is shown, so a malformed peer line
                // cannot put arbitrary text in the UI.
                const QString endpoint = fields.at(2);
                if (endpoint != "(none)" && looksLikeEndpoint(endpoint) && endpoint != m_status.endpoint) {
                    m_status.endpoint = endpoint;
                    changed = true;
                }
            }
        }

        // The state transition comes after the parse, so "Up" is never reported on the
        // strength of a reply that turned out to be unusable.
        if (m_status.state != State::Up) {
            m_upSince.start();
            setState(State::Up);
            emit logMessage(tr("The %1 tunnel is up.").arg(name));
            // Keep watching for as long as the tunnel is up. This is also what makes a
            // tunnel that somebody else brought up visible to this launcher.
            m_pollTimer->start();
        }

        if (changed) {
            emit statusChanged();
        }
    });
}

bool WireGuardTunnel::isHandshakeFresh(qint64 maxAgeSeconds) const
{
    if (m_status.lastHandshake <= 0) {
        return false;
    }
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 age = now - m_status.lastHandshake;
    // A timestamp in the future means a clock change, not a live peer; treat it as
    // unknown rather than as permanently fresh.
    if (age < 0) {
        return false;
    }
    return age <= maxAgeSeconds;
}

QString WireGuardTunnel::tunnelAddress(quint16 port) const
{
    const QString host = m_interface.host();
    if (host.isEmpty()) {
        return {};
    }
    return QStringLiteral("%1:%2").arg(host).arg(port);
}
