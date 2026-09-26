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

#include <QDir>
#include <QElapsedTimer>
#include <QObject>
#include <QString>
#include <QStringList>

#include "WireGuardConf.h"

class LoggedProcess;
class QTimer;

/**
 * Brings a WireGuard tunnel up and down with the platform's open-source WireGuard tools,
 * and reports whether a handshake has genuinely happened.
 *
 * Both platforms are driven through the same `wg show` queries, because Windows'
 * `wireguard.exe` embeds the `wg` utility. Only the bring-up call differs:
 *
 *   - Windows: `wireguard.exe /installtunnels <name>.conf`
 *   - Linux:   `wg-quick up <name>.conf`, via `pkexec` because it needs root
 *
 * The interface name comes from the config's *file* name on both platforms, so a
 * canonical copy is written to {@link confPath} and never handed to a tool by any
 * other path.
 *
 * Monitoring is deliberately usable without the bring-up tools: once {@link refresh} sees
 * an interface that exists, it keeps polling for as long as the tunnel is up, so a tunnel
 * brought up by hand (`sudo wg-quick up hypermine`) is picked up and reported. Watching
 * needs no privileges; only bring-up and tear-down do.
 */
class WireGuardTunnel : public QObject {
    Q_OBJECT
   public:
    enum class State {
        Down,
        Starting,
        Up,
        Failed,
    };
    Q_ENUM(State)

    struct Status {
        State state = State::Down;
        /** Unix seconds of the most recent handshake; 0 means it has never handshaked. */
        qint64 lastHandshake = 0;
        quint16 listenPort = 0;
        /** The endpoint the peer is actually reached at, which can differ when roaming. */
        QString endpoint;
        /** Set when {@link state} is {@link State::Failed}. */
        QString error;
    };

    explicit WireGuardTunnel(QObject* parent = nullptr);
    ~WireGuardTunnel() override;

    /** True when the `wg` tool is present, i.e. when the tunnel can at least be watched. */
    static bool watchToolAvailable();
    /** True when the tunnel can also be brought up and down by this launcher. */
    static bool controlToolAvailable();
    /** Why {@link controlToolAvailable} is false, phrased for the UI. */
    static QString controlToolHint();

    /** Directory holding the canonical `<name>.conf`. Created on demand. */
    void setConfigDir(const QDir& dir);
    QDir configDir() const { return m_configDir; }

    /**
     * Adopt a parsed interface. Writes the canonical config to {@link confPath} and
     * remembers it. Brings nothing up and touches no system state.
     */
    void setInterface(const WireGuardInterface& iface);
    void clearInterface();

    const WireGuardInterface& interface() const { return m_interface; }
    bool hasInterface() const { return !m_interface.name.isEmpty(); }

    /** Absolute path of the canonical config, or empty when no interface is loaded. */
    QString confPath() const;

    const Status& status() const { return m_status; }
    State state() const { return m_status.state; }
    bool isUp() const { return m_status.state == State::Up; }
    bool hasHandshake() const { return m_status.lastHandshake != 0; }

    /**
     * Whether the last handshake is recent enough to call the peer connected.
     *
     * A non-zero `lastHandshake` alone is not enough: `wg` keeps the timestamp from
     * before the interface went away, so a tunnel that dropped an hour ago still
     * reports one. Age is the only honest test.
     */
    bool isHandshakeFresh(qint64 maxAgeSeconds = 180) const;

    /**
     * Bring the tunnel up. Does nothing when it is already up; fails with a readable
     * {@link Status::error} when the platform tools are missing or refuse the config.
     */
    void bringUp();

    /** Tear the tunnel down. Safe to call when already down. */
    void bringDown();

    /**
     * Discard the loaded interface, tearing the tunnel down first if one is up.
     *
     * The ordering matters and is why this is not just {@link clearInterface}: clearing
     * cancels any in-flight tool, so doing it while an uninstall is still running would
     * abort the teardown and leave the interface installed at the OS level with no
     * configuration left to bring it down again.
     */
    void forget();

    /**
     * Re-read the interface from `wg show`. Cheap, non-blocking, and the only thing
     * that can discover a tunnel that came up or died outside this launcher.
     */
    void refresh();

    /** The address a Minecraft client should dial, or empty when unknown. */
    QString tunnelAddress(quint16 port) const;

   signals:
    void statusChanged();
    void logMessage(const QString& message);

   private:
    void setState(State state, const QString& error = {});
    void stopPolling();
    /** Whether {@link runTool} should surface the tool's own log lines. */
    void setForwardToolLogs(bool forward) { m_forwardToolLogs = forward; }

    /**
     * Path to the `wg` command-line utility, used for every status query. Empty if absent.
     *
     * On Windows this must be `wg.exe`, not `wireguard.exe`: the latter is the GUI
     * front end and does not implement `wg show`.
     */
    static QString wgToolPath();
    /**
     * Path to the Windows `wireguard.exe`, which is what implements
     * `/installtunnels` and `/uninstalltunnels`. Empty on other platforms.
     */
    static QString installToolPath();
    /** Path to `wg-quick`, or empty when it is not installed. */
    static QString wgQuickPath();
    /**
     * Program and arguments that bring the tunnel up. Kept as a pair because on Linux
     * the program is `pkexec` and the real tool has to be passed as the first argument,
     * where an elevation helper will not resolve it from PATH on its own.
     */
    static QPair<QString, QStringList> upInvocation(const QString& conf);
    /** Program and arguments that take the tunnel down. */
    static QPair<QString, QStringList> downInvocation(const QString& interfaceName, const QString& conf);

    /** Write the canonical `<name>.conf`. False on failure, with `error` set. */
    bool writeConfFile(QString* error) const;
    /** Run a tool, collect its stdout, and invoke `done` on the event thread. */
    void runTool(const QString& program, const QStringList& args, std::function<void(int, const QString&)> done);
    /** Cancel any in-flight tool without its completion handler running. */
    void killPending();
    /** True while a tool is running, so overlapping queries can be skipped. */
    bool isBusy() const { return m_process != nullptr; }

    QDir m_configDir;
    WireGuardInterface m_interface;
    Status m_status;
    /** When the current tunnel was brought up, so handshake age can be judged. */
    QElapsedTimer m_upSince;
    /** Repeats `refresh()` while a bring-up is in flight or a tunnel is up. */
    QTimer* m_pollTimer = nullptr;
    LoggedProcess* m_process = nullptr;
    /** False for status polls, true while bringing a tunnel up or down. */
    bool m_forwardToolLogs = true;
    /** Consecutive `wg show` failures seen while the tunnel was up. */
    int m_consecutiveFailures = 0;
};
