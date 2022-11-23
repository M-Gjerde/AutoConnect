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

#else

#include "AutoConnect/AutoConnectLinux.h"

int main(){

    AutoConnectLinux autoConnect;
    autoConnect.run();

    return 0;
}

#endif