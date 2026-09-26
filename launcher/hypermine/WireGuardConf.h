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
 *
 *  This file incorporates work covered by the following copyright and
 *  permission notice:
 *
 *      Copyright 2017-2023 WireGuard contributors
 *
 *      Licensed under the MIT License, (the "License"); you may not use
 *      this file except in compliance with the License. You may obtain a
 *      copy of the License at
 *
 *          http://www.opensource.org/licenses/mit-license.php
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#pragma once

#include <QString>
#include <QStringList>

/**
 * A single `[Peer]` stanza.
 *
 * HyperMine talks to exactly one peer (the box running the panel), which is the shape of
 * every config a `wg-quick`/`wg` invocation hands out. A config listing more than one
 * peer is rejected rather than partially honoured: quietly ignoring a peer means quietly
 * not connecting, and a user who is not told will sit waiting on a tunnel that can never
 * carry the traffic they asked for.
 */
struct WireGuardPeer {
    QString publicKey;
    QString presharedKey;
    /** CIDRs this peer is reachable at, e.g. `10.13.0.1/32`. */
    QStringList allowedIps;
    /** `host:port` of the peer's WireGuard endpoint. Empty when roaming. */
    QString endpoint;
    int persistentKeepalive = 0;

    bool isValid(QString* error) const;
    /**
     * The peer's address with the prefix length stripped, i.e. the tunnel IP the game
     * server is reachable at. Empty when there is no IPv4 AllowedIPs entry.
     */
    QString host() const;
    /** The first IPv4 AllowedIPs entry with its prefix length stripped. */
    QString hostOfFirstIpv4() const;
};

/**
 * A parsed `[Interface]` + `[Peer]` pair, i.e. everything needed to bring one tunnel up.
 */
struct WireGuardInterface {
    /**
     * Tunnel/interface name. Both `wg-quick` and `wireguard.exe /installtunnels` derive
     * the name from the *file name*, never from the file's contents, so this is not
     * cosmetic: it decides what `wg show <name>` reports.
     */
    QString name;
    QString privateKey;
    /** Local addresses in CIDR form, e.g. `10.13.0.7/32`. */
    QStringList addresses;
    QStringList dns;
    bool hasMtu = false;
    int mtu = 0;
    WireGuardPeer peer;

    bool isValid(QString* error) const;

    /** The local address with the prefix length stripped, e.g. `10.13.0.7`. */
    QString localHost() const;

    /**
     * Build the address a Minecraft client should connect to, combining the tunnel
     * interface's address with the peer's.
     */
    QString host() const { return peer.hostOfFirstIpv4(); }

    /**
     * Parse the text of a `wg-quick` config. `name` becomes
     * {@link WireGuardInterface::name}. On failure returns a default-constructed
     * interface and, when `error` is non-null, points it at a human-readable reason.
     */
    static WireGuardInterface fromConf(const QString& text, const QString& name, QString* error);

    /**
     * True when `key` is a syntactically valid Curve25519 key: 44 characters of standard
     * base64 that decode to 32 bytes. Checks length and alphabet only — it cannot tell a
     * real key from a well-formed random string, and does not pretend to.
     */
    static bool isValidKey(const QString& key);
};
