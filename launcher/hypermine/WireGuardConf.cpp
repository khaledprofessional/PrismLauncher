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

#include "WireGuardConf.h"

#include <QAbstractSocket>
#include <QByteArray>
#include <QCoreApplication>
#include <QHostAddress>
#include <QRegularExpression>

namespace {

QString tr(const char* text)
{
    return QCoreApplication::translate("WireGuardInterface", text);
}

QString stripPrefixLength(const QString& cidr)
{
    const int slash = cidr.indexOf('/');
    return (slash < 0) ? cidr : cidr.left(slash);
}

QStringList splitList(const QString& value)
{
    QStringList out;
    const auto pieces = value.split(',', Qt::SkipEmptyParts);
    for (const QString& piece : pieces) {
        const QString trimmed = piece.trimmed();
        if (!trimmed.isEmpty()) {
            out << trimmed;
        }
    }
    return out;
}

bool isIpv4(const QString& host)
{
    const QHostAddress address(host);
    return !address.isNull() && address.protocol() == QAbstractSocket::IPv4Protocol;
}

bool isInterfaceNameSafe(const QString& name)
{
    // Deliberately strict: letters, digits, dash, underscore. The name becomes a network
    // interface name, and a space, slash or backslash turns into an error from deep
    // inside wg that says nothing about which file was at fault.
    for (const QChar c : name) {
        if (!c.isLetterOrNumber() && c != QLatin1Char('-') && c != QLatin1Char('_')) {
            return false;
        }
    }
    return !name.isEmpty();
}

}  // namespace

bool WireGuardInterface::isValidKey(const QString& key)
{
    // 32 bytes of key material is 43 base64 characters plus one '=' pad. The 43rd
    // character only carries 4 significant bits, so its low 2 bits must be zero --
    // that is what restricts the final character to the set below. Qt's base64 decoder
    // silently skips characters it dislikes, so the alphabet has to be checked here or
    // "43 characters of anything" would pass.
    static const QRegularExpression shape("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$");
    if (!shape.match(key).hasMatch()) {
        return false;
    }
    return QByteArray::fromBase64(key.toLatin1()).size() == 32;
}

QString WireGuardPeer::host() const
{
    return hostOfFirstIpv4();
}

QString WireGuardPeer::hostOfFirstIpv4() const
{
    for (const QString& cidr : allowedIps) {
        const QString candidate = stripPrefixLength(cidr.trimmed());
        if (isIpv4(candidate)) {
            return candidate;
        }
    }
    return {};
}

bool WireGuardPeer::isValid(QString* error) const
{
    if (publicKey.isEmpty()) {
        if (error)
            *error = tr("the [Peer] section has no PublicKey");
        return false;
    }
    if (!WireGuardInterface::isValidKey(publicKey)) {
        if (error)
            *error = tr("the [Peer] PublicKey is not a valid Curve25519 key");
        return false;
    }
    if (!presharedKey.isEmpty() && !WireGuardInterface::isValidKey(presharedKey)) {
        if (error)
            *error = tr("the [Peer] PresharedKey is not a valid Curve25519 key");
        return false;
    }
    if (allowedIps.isEmpty()) {
        if (error)
            *error = tr("the [Peer] section has no AllowedIPs, so there is nothing to route to the server");
        return false;
    }
    return true;
}

QString WireGuardInterface::localHost() const
{
    for (const QString& cidr : addresses) {
        const QString candidate = stripPrefixLength(cidr.trimmed());
        if (isIpv4(candidate)) {
            return candidate;
        }
    }
    return {};
}

bool WireGuardInterface::isValid(QString* error) const
{
    if (name.trimmed().isEmpty()) {
        if (error)
            *error = tr("the tunnel needs a name, which comes from the config's file name");
        return false;
    }
    // The name becomes a network interface name. Linux caps those at IFNAMSIZ-1 = 15
    // bytes and silently truncates or fails, so both the characters and the length are
    // checked here where the message can say what actually went wrong.
    if (!isInterfaceNameSafe(name)) {
        if (error)
            *error = tr("the file name '%1' cannot be used as a tunnel name; rename it to letters, digits, "
                        "dashes or underscores")
                         .arg(name);
        return false;
    }
    if (name.size() > 15) {
        if (error)
            *error = tr("the file name '%1' is longer than 15 characters, which is the limit for a network "
                        "interface name; shorten it")
                         .arg(name);
        return false;
    }
    if (privateKey.isEmpty()) {
        if (error)
            *error = tr("the [Interface] section has no PrivateKey");
        return false;
    }
    if (!isValidKey(privateKey)) {
        if (error)
            *error = tr("the [Interface] PrivateKey is not a valid Curve25519 key");
        return false;
    }
    if (addresses.isEmpty()) {
        if (error)
            *error = tr("the [Interface] section has no Address, so the tunnel would have no local IP");
        return false;
    }
    return peer.isValid(error);
}

WireGuardInterface WireGuardInterface::fromConf(const QString& text, const QString& name, QString* error)
{
    const auto fail = [error](const QString& why) {
        if (error) {
            *error = why;
        }
        return WireGuardInterface{};
    };

    if (name.trimmed().isEmpty()) {
        return fail(tr("no tunnel name was given; a '.conf' file name is required"));
    }

    WireGuardInterface iface;
    iface.name = name.trimmed();

    enum class Section { None, Interface, Peer };
    Section section = Section::None;
    int peersSeen = 0;

    const QStringList lines = text.split(QRegularExpression("\r\n|\n|\r"));
    for (const QString& rawLine : lines) {
        // A '#' runs to end of line. wg's own parser treats it the same way, so a '#'
        // inside a value is a malformed config there too -- not something to rescue here.
        QString line = rawLine;
        const int hash = line.indexOf('#');
        if (hash >= 0) {
            line.truncate(hash);
        }
        line = line.trimmed();
        if (line.isEmpty()) {
            continue;
        }

        if (line.startsWith('[')) {
            // Tolerate a bare '[' or a missing ']' rather than reading off the end.
            const auto inner = line.size() >= 2 ? line.mid(1, line.size() - 2) : QString{};
            const QString sectionName = inner.trimmed().toLower();
            if (sectionName == "interface") {
                section = Section::Interface;
            } else if (sectionName == "peer") {
                section = Section::Peer;
                peersSeen += 1;
            } else {
                section = Section::None;
            }
            continue;
        }

        const int equals = line.indexOf('=');
        if (equals < 0) {
            // wg-quick is lenient about stray lines; staying lenient keeps commented-out
            // or templated configs importable.
            continue;
        }
        const QString key = line.left(equals).trimmed().toLower();
        const QString value = line.mid(equals + 1).trimmed();

        if (section == Section::Interface) {
            if (key == "privatekey") {
                iface.privateKey = value;
            } else if (key == "address") {
                iface.addresses = splitList(value);
            } else if (key == "dns") {
                iface.dns = splitList(value);
            } else if (key == "mtu") {
                bool ok = false;
                const int number = value.toInt(&ok);
                if (ok) {
                    iface.hasMtu = true;
                    iface.mtu = number;
                }
            }
            // SaveConfig, Table, PreUp and friends belong to wg-quick, not to us.
        } else if (section == Section::Peer && peersSeen == 1) {
            // Only the first peer is modelled. Extra ones are rejected below rather than
            // dropped, because quietly ignoring a peer means quietly not connecting.
            if (key == "publickey") {
                iface.peer.publicKey = value;
            } else if (key == "presharedkey") {
                iface.peer.presharedKey = value;
            } else if (key == "allowedips") {
                iface.peer.allowedIps = splitList(value);
            } else if (key == "endpoint") {
                iface.peer.endpoint = value;
            } else if (key == "persistentkeepalive") {
                bool ok = false;
                const int number = value.toInt(&ok);
                if (ok) {
                    iface.peer.persistentKeepalive = number;
                }
            }
        }
    }

    if (peersSeen > 1) {
        return fail(tr("the config lists %1 peers, but HyperMine connects to exactly one server").arg(peersSeen));
    }
    if (peersSeen == 0) {
        return fail(tr("the config has no [Peer] section, so there is no server to connect to"));
    }

    if (!iface.isValid(error)) {
        return WireGuardInterface{};
    }

    if (error) {
        error->clear();
    }
    return iface;
}
