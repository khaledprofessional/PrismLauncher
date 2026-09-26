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

#include <optional>

#include <QString>
#include <QVector>

#include "HyperMineClient.h"
#include "WireGuardTunnel.h"

class QStandardItemModel;
class QTimer;

namespace Ui {
class HyperMinePage;
}

/**
 * The HyperMine tab: manage the WireGuard tunnel, list the panel's servers, and launch an
 * instance straight into one through the tunnel.
 *
 * The order the three groups are stacked in is the order the work happens in: get the
 * tunnel up, see what the panel says, then play. Nothing below depends on anything above
 * it being finished first, so a panel that is not running still leaves a usable tunnel
 * control panel rather than a dead tab.
 *
 * The tab never launches the game until the tunnel has actually handshaked. Bringing the
 * interface up is not the same as having a route to the server, and launching into a
 * tunnel that has not handshaked just produces a connection-timeout screen.
 */
class HyperMinePage : public QWidget {
    Q_OBJECT
   public:
    explicit HyperMinePage(QWidget* parent = nullptr);
    ~HyperMinePage() override;

    /** Bring the tunnel up and report once it is ready, then refresh the panel. */
    void activate();

    /** Re-read the persisted settings and reflect them in the UI. */
    void reload();

   private slots:
    void onImportClicked();
    void onForgetClicked();
    void onUpClicked();
    void onDownClicked();
    void onSavePanelClicked();
    void onRefreshClicked();
    void onStartClicked();
    void onStopClicked();
    void onPlayClicked();
    void onSelectionChanged();
    void onTunnelStatusChanged();
    void onTunnelLog(const QString& message);
    void onServersReceived(const QVector<HyperMineServer>& servers);
    void onRequestFailed(const QString& message);
    void onActionFinished(const QString& serverId, bool success, const QString& message);
    /** Fired when a Play click has waited as long as it is willing to. */
    void onPendingPlayTimeout();

   private:
    void loadTunnelFromSettings();
    void saveTunnelToSettings(const QString& confPath);
    /** Push the panel fields into {@link m_client}. */
    void applyPanelSettings();
    void refreshTunnelLabels();
    void refreshButtonStates();
    void refreshPanelAvailability();
    void refreshPlayAddress();
    void populateInstances();
    void populateServers(const QVector<HyperMineServer>& servers);
    void appendLog(const QString& line);
    /** The server currently selected in the table, if any. */
    std::optional<HyperMineServer> selectedServer() const;
    /** The port to dial: the selected server's, or the default when nothing is selected. */
    quint16 targetPort() const;
    /** Where the panel should be reachable once the tunnel is up. */
    QUrl suggestedPanelUrl() const;
    /**
     * Launch into the server, waiting for a handshake first when the tunnel still needs
     * one. Sets {@link m_pendingPlay} instead of launching when it has to wait.
     */
    void beginPlay(const QString& instanceId, const QString& address);
    void tryCompletePendingPlay();
    void clearPendingPlay();

    Ui::HyperMinePage* ui = nullptr;
    WireGuardTunnel* m_tunnel = nullptr;
    HyperMineClient* m_client = nullptr;
    QStandardItemModel* m_serverModel = nullptr;

    QVector<HyperMineServer> m_servers;
    /** Set when Play is waiting on a handshake. */
    QString m_pendingInstanceId;
    QString m_pendingAddress;
    /** Bounds how long a Play click waits. Not the tunnel's poll timer. */
    QTimer* m_pendingPlayTimer = nullptr;
    /** Whether the panel label is currently showing a "cannot reach the panel" reason. */
    bool m_panelBlocked = false;
};
