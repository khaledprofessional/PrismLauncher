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

#include <QString>
#include <QStringList>

/**
 * Runs a program with elevated rights and lets the caller poll for completion.
 *
 * This exists for one reason: `wireguard.exe /installtunnelservice` needs
 * administrator, and when it is started unelevated it does not report failure -- it
 * opens a dialog and waits forever. A launcher that spawned it and awaited it would hang
 * with no way out. Here the elevation is requested explicitly through the shell, so the
 * user either approves the UAC prompt or the start simply fails, and completion is polled
 * rather than waited on, so a caller can always give up.
 *
 * Only Windows has a meaningful implementation. Elsewhere {@link start} fails and says
 * why, because the caller should fall back to its normal path instead of silently doing
 * nothing.
 */
class ElevatedProcess {
   public:
    ElevatedProcess();
    ~ElevatedProcess();

    ElevatedProcess(const ElevatedProcess&) = delete;
    ElevatedProcess& operator=(const ElevatedProcess&) = delete;

    /**
     * Request elevation and launch `program`.
     *
     * Returns false if elevation is unavailable, the user declined the prompt, or the
     * shell could not start the process, with `error` set. On success the process is
     * running and {@link finished} will eventually become true.
     */
    bool start(const QString& program, const QStringList& args, QString* error);

    /** True once the process has exited. Safe to call repeatedly. */
    bool finished() const;

    /**
     * Exit code, valid only once {@link finished} is true. Returns -1 if the process
     * failed to start or its code could not be read.
     */
    int exitCode() const;

    /** True if a process is currently running under this object. */
    bool isRunning() const { return m_handle != nullptr; }

    /** Static: whether this platform supports elevation at all. */
    static bool isSupported();

   private:
    /** Platform handle: a HANDLE on Windows, nullptr elsewhere. */
    void* m_handle = nullptr;
};
