/**
 * @file: AutoConnect/src/main.cpp
 *
 * Copyright 2022
 * Carnegie Robotics, LLC
 * 4501 Hatfield Street, Pittsburgh, PA 15201
 * http://www.carnegierobotics.com
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Carnegie Robotics, LLC nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CARNEGIE ROBOTICS, LLC BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Significant history (date, user, action):
 *   2022-11-23, mgjerde@carnegierobotics.com, Created file.
 **/
// AutoConnect program
// Must be started with elevated privileges. Can be launched as part of a program or as a standalone
//
// Starts by finding all ethernet adapters
// Creates a listener in separate thread for each network adapter
// Waits of an IGMP packet on each adapter
// If IGMP received then read source of that IGMP packet and try to connect to camera

// Finding ethernet adapters: possible cases to consider
// User can plug/unplug an adapter at any time
// User can have unsupported adapters plugged in
// User can have preoccupied adapters by other software
// User can have virtual adapters

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "Windows.h"
#include "AutoConnect/AutoConnectWindows.h"
#include "../getopt/getopt.h"

#else
#include "AutoConnect/AutoConnectLinux.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <semaphore.h>
#include <string.h>
#include <csignal>
#include <getopt.h>
#endif

volatile bool stopProgram = false;

#ifdef WIN32
BOOL WINAPI signalHandler(DWORD dwCtrlType) {
    std::cerr << "Shutting down on signal: CTRL-C" << std::endl;
    stopProgram = true;
    return TRUE;
}
#else
void signalHandler(int sig) {
    std::cerr << "Shutting down on signal: " << strsignal(sig) << std::endl;
    stopProgram = true;
}
#endif

void usage(const char *programNameP) {
    std::cerr << "USAGE: " << programNameP << " [<options>]" << std::endl;
    std::cerr << "Where <options> are:" << std::endl;
    std::cerr << "\t-i on/off    : Run with IPC enabled or disabled (useful when embedding into another application)"
              << std::endl;
    std::cerr << "\t-c on/off    : Everthing logged to shared memory (IPC) is also logged to console (default false)"
              << std::endl;
    exit(1);
}

int main(int argc, char **argv) {
#if WIN32
    SetConsoleCtrlHandler(signalHandler, TRUE);
#else
    if (getuid() != 0) {
        std::cerr << "ERROR: This program must be run with root privileges" << std::endl;
        exit(1);
    }

    signal(SIGINT, signalHandler);
#endif

    // Parse args
    bool runWithIpc = false;
    bool logToConsole = false;
    int c;
    if (argc == 1)
        usage(*argv);

    char * a = (char*) "i:c:";
    while (-1 != (c = getopt(argc, argv, a)))
        switch (c) {
            case 'i':
                runWithIpc = std::string(optarg) == "on";
                break;
            case 'c':
                logToConsole = std::string(optarg) == "on";
                break;
            default:
                usage(*argv);
                break;
        }

#ifdef WIN32
    AutoConnectWindows  autoConnect(runWithIpc, logToConsole);
#else
    AutoConnectLinux autoConnect(runWithIpc, logToConsole);
#endif
    while (autoConnect.pollEvents() && !stopProgram) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    autoConnect.cleanUp();

    return 0;
}
