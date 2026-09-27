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

#include "ElevatedProcess.h"

#include <QCoreApplication>

#if defined(Q_OS_WIN)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#endif

namespace {

QString tr(const char* text)
{
    return QCoreApplication::translate("ElevatedProcess", text);
}

/**
 * Join `args` into a single command line, quoting the ones that need it.
 *
 * ShellExecuteEx takes the program and its arguments as separate fields and does no
 * quoting of its own, so anything with a space in it has to arrive already quoted --
 * which matters here because the config path routinely contains a space ("Program
 * Files").
 */
QString buildParameters(const QStringList& args)
{
    QStringList quoted;
    for (const QString& arg : args) {
        if (!arg.contains(QLatin1Char(' ')) && !arg.contains(QLatin1Char('"'))) {
            quoted << arg;
            continue;
        }
        QString escaped = arg;
        escaped.replace(QLatin1Char('"'), QLatin1String("\\\""));
        quoted << (QLatin1Char('"') + escaped + QLatin1Char('"'));
    }
    return quoted.join(QLatin1Char(' '));
}

}  // namespace

bool ElevatedProcess::isSupported()
{
#if defined(Q_OS_WIN)
    return true;
#else
    return false;
#endif
}

ElevatedProcess::ElevatedProcess() = default;

ElevatedProcess::~ElevatedProcess()
{
#if defined(Q_OS_WIN)
    if (m_handle) {
        CloseHandle(static_cast<HANDLE>(m_handle));
        m_handle = nullptr;
    }
#endif
}

bool ElevatedProcess::start(const QString& program, const QStringList& args, QString* error)
{
#if defined(Q_OS_WIN)
    if (program.isEmpty()) {
        if (error) {
            *error = tr("No program was given to elevate.");
        }
        return false;
    }
    if (m_handle) {
        if (error) {
            *error = tr("An elevated command is already running.");
        }
        return false;
    }

    const QString parameters = buildParameters(args);

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    // NOCLOSEPROCESS is the whole point: it hands back a handle so completion can be
    // polled instead of waited on.
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = L"runas";
    info.lpFile = reinterpret_cast<LPCWSTR>(program.utf16());
    info.lpParameters = parameters.isEmpty() ? nullptr : reinterpret_cast<LPCWSTR>(parameters.utf16());
    info.nShow = SW_HIDE;

    if (!ShellExecuteExW(&info)) {
        if (error) {
            const DWORD code = GetLastError();
            // ERROR_CANCELLED (1223) is the user saying no to the UAC prompt, which is a
            // choice rather than a fault, so it is reported as its own thing.
            *error = (code == ERROR_CANCELLED)
                ? tr("Elevation was declined, so the tunnel was not changed.")
                : tr("Could not start '%1' with administrator rights (Windows error %2).")
                      .arg(program)
                      .arg(static_cast<quint32>(code));
        }
        return false;
    }

    m_handle = info.hProcess;
    return true;
#else
    Q_UNUSED(program)
    Q_UNUSED(args)
    if (error) {
        *error = tr("Raising this program's privileges is only implemented on Windows. On this system the tunnel "
                    "is brought up with 'wg-quick' under pkexec instead.");
    }
    return false;
#endif
}

bool ElevatedProcess::finished() const
{
#if defined(Q_OS_WIN)
    if (!m_handle) {
        return true;
    }
    return WaitForSingleObject(static_cast<HANDLE>(m_handle), 0) == WAIT_OBJECT_0;
#else
    return true;
#endif
}

int ElevatedProcess::exitCode() const
{
#if defined(Q_OS_WIN)
    if (!m_handle) {
        return -1;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(static_cast<HANDLE>(m_handle), &code)) {
        return -1;
    }
    return static_cast<int>(code);
#else
    return -1;
#endif
}
