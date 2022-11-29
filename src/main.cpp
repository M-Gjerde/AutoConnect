//
// Created by magnus on 11/23/22.
//

// AutoConnect program
// Must be started with elevated privileges. The invoker should take this into account.
//

// Starts by finding all ethernet adapters
// Creates a listener for each network adapter
// Waits of an IGMP packet on each adapter
// Sends a list through another process that can test for camera on IGMP's senders address


// Finding ethernet adapters: possible cases to consider
// User can plug/unplug an adapter at any time
// User can have unsupported adapters plugged in
// User can have preoccupied adapters by other software
// User can have virtual adapters

// Once an adapter is detected it should spawn a thread that will listen on that adapter
//
#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "Windows.h"
#include "getopt.h"
#include "AutoConnect/AutoConnectWindows.h"
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

    while (-1 != (c = getopt(argc, argv, "i:c:")))
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
