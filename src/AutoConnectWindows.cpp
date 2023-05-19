/**
 * @file: AutoConnect/src/AutoConnectWindows.cpp
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
 *   2022-07-14, mgjerde@carnegierobotics.com, Created file.
 **/


#include "AutoConnect/AutoConnectWindows.h"

#include <cstring>
#include <mutex>
#include <fcntl.h>
#include <sys/stat.h>
#include <MultiSense/MultiSenseChannel.hh>
#include <WinPcap/pcap.h>
#include <iphlpapi.h>
#include <AclAPI.h>

#include "AutoConnect/WinRegEditor.h"

struct iphdr {
    unsigned char ip_verlen;            // 4-bit IPv4 version, 4-bit header length (in 32-bit words)
    unsigned char ip_tos;                 // IP type of service
    unsigned short ip_totallength;    // Total length
    unsigned short ip_id;                  // Unique identifier
    unsigned short ip_offset;            // Fragment offset field
    unsigned char ip_ttl;                   // Time to liv
    unsigned char protocol;       // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;    // IP checksum
    unsigned int saddr;           // Source address
    unsigned int ip_destaddr;         // Source address

};

void AutoConnectWindows::reportAndExit(const char *msg) {
    log("%s ", msg);
    m_IsRunning = false;
}


void AutoConnectWindows::sendMessage(LPCTSTR pBuf) {
    std::scoped_lock<std::mutex> lock(m_logQueueMutex);
    strcpy_s((char *) pBuf, (SharedBufferSize / 2), nlohmann::to_string(out).c_str());
}


void AutoConnectWindows::getMessage(LPCTSTR pBuf) {
    std::string str("0", SharedBufferSize);
    std::memcpy(str.data(), pBuf + (SharedBufferSize / 2), SharedBufferSize / 2);
    memset((char *) pBuf + (SharedBufferSize / 2), 0x00, SharedBufferSize / 2);

    if (!str.empty()) {
        try {
            auto json = nlohmann::json::parse(str);
            std::cout << json.dump(4) << std::endl;
            if (json.contains("Command")) {
                if (json["Command"] == "Stop") {
                    log("Stopping Auto Connect");
                    sendMessage(pBuf);
                    cleanUp();
                }

            }
            if (json.contains("SetIP")) {
                std::string indexStr = json["index"];
                int index = 0;
                try {
                    index = std::stoi(indexStr);
                    // Use the 'index' variable here
                    nlohmann::json res = out["Result"];
                    std::string adapterName = res[index]["Name"];
                    std::string ip = res[index]["AddressList"][0];
                    int ifIndex = res[index]["Index"];
                    std::string description = res[index]["Description"];
                    // Set the host ip address to the same subnet but with *.2 at the end.
                    std::string hostAddress = ip;
                    std::string last_element(hostAddress.substr(hostAddress.rfind(".")));
                    auto ptr = hostAddress.rfind('.');
                    hostAddress.replace(ptr, last_element.length(), ".2");
                    //log("Setting ip: " + hostAddress + " At interface: " + adapterName);

                    WinRegEditor regEditorStatic(adapterName, description, ifIndex);
                    //log("Setting MTU size to 9014 on: ", description);
                    regEditorStatic.setJumboPacket("9014");
                    std::cout << "Setting jumbo packet: " << std::endl;

                    regEditorStatic.restartNetAdapters();
                    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
                    WinRegEditor setIpAddress(ifIndex, hostAddress, "255.255.255.0");
                    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
                    std::cout << "Set ip: " << hostAddress << " on adapter: " << description << std::endl;

                } catch (nlohmann::json::exception &e) {
                    // output exception information
                    std::cout << "message: " << e.what() << '\n'
                              << "exception id: " << e.id << '\n';
                }

            }
        } catch (const std::exception &e) {
        }
    }
}


void AutoConnectWindows::runInternal(void *ctx, bool enableIPC) {
    auto *app = static_cast<AutoConnectWindows *>(ctx);
    auto time = std::chrono::steady_clock::now();
    HANDLE hMapFile;
    LPCTSTR pBuf;
    TCHAR szName[] = TEXT("Global\\MyFileMappingObject");

    if (enableIPC) {
        EXPLICIT_ACCESS ea[1];
        PSID pEveryoneSID = NULL;
        PACL pACL = NULL;

        SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
        // Create a well-known SID for the Everyone group.
        if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
                                      SECURITY_WORLD_RID,
                                      0, 0, 0, 0, 0, 0, 0,
                                      &pEveryoneSID)) {
            _tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
        }

        // Initialize an EXPLICIT_ACCESS structure for an ACE.
        // The ACE will allow Everyone read access to the key.
        ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
        ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
        ea[0].grfAccessMode = SET_ACCESS;
        ea[0].grfInheritance = NO_INHERITANCE;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[0].Trustee.ptstrName = (LPTSTR) pEveryoneSID;

        // Create a new ACL that contains the new ACEs.
        DWORD dwRes = SetEntriesInAcl(1, ea, NULL, &pACL);
        if (ERROR_SUCCESS != dwRes) {
            _tprintf(_T("SetEntriesInAcl Error %u\n"), GetLastError());
        }

        PSECURITY_DESCRIPTOR pSD = NULL;
        pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR,
                                                SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (!InitializeSecurityDescriptor(pSD,
                                          SECURITY_DESCRIPTOR_REVISION)) {
            _tprintf(_T("InitializeSecurityDescriptor Error %u\n"),
                     GetLastError());
        }

        // Add the ACL to the security descriptor.
        if (!SetSecurityDescriptorDacl(pSD,
                                       TRUE,     // bDaclPresent flag
                                       pACL,
                                       FALSE))   // not a default DACL
        {
            _tprintf(_T("SetSecurityDescriptorDacl Error %u\n"),
                     GetLastError());
        }

        SECURITY_ATTRIBUTES mapAttributes{};
        mapAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
        mapAttributes.bInheritHandle = true;
        mapAttributes.lpSecurityDescriptor = pSD;

        hMapFile = CreateFileMapping(
                INVALID_HANDLE_VALUE,    // use paging file
                &mapAttributes,                    // default security
                PAGE_READWRITE,          // read/write access
                0,                       // maximum object size (high-order DWORD)
                SharedBufferSize,                // maximum object size (low-order DWORD)
                szName);                 // name of mapping object

        if (hMapFile == nullptr) {
            app->reportAndExit("Can't CreateFileMapping for shared mem segment...");
            return;
        }
        pBuf = (LPTSTR) MapViewOfFile(hMapFile,   // handle to map object
                                      FILE_MAP_ALL_ACCESS, // read/write permission
                                      0,
                                      0,
                                      SharedBufferSize);

        if (pBuf == nullptr) {
            CloseHandle(hMapFile);
            app->reportAndExit("Can't MapViewOfFile of shared mem segment...");
            return;
        }

        memset((void *) pBuf, 0, SharedBufferSize); // Set the memory pointed by pBuf to 0 for SharedBufferSize bytes


    }

    while (app->m_IsRunning) {
        // Find a list of available adapters
        {
            std::scoped_lock<std::mutex> lock(app->m_AdaptersMutex);
            for (auto &item: app->m_Adapters) {
                if (item.supports && item.available) {
                    item.available = false;
                    app->m_Pool->Push(AutoConnectWindows::listenOnAdapter, app, &item);
                }
            }
        }
        // Add a task to check for cameras on an adapter
        {
            std::scoped_lock<std::mutex> lock(app->m_AdaptersMutex);
            for (auto &item: app->m_Adapters) {
                if (!item.IPAddresses.empty() && !item.checkingForCamera) {
                    app->m_Pool->Push(AutoConnectWindows::checkForCamera, app, &item);
                    item.checkingForCamera = true;
                }
            }
        }
        if (enableIPC)
            app->sendMessage(pBuf);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (enableIPC)
            app->getMessage(pBuf);
        auto time_span = std::chrono::duration_cast<std::chrono::duration<float>>(
                std::chrono::steady_clock::now() - time);
        if (time_span.count() > 60) {
            app->log("Time limit of 60s reached. Exiting AutoConnect.");
            break;
        }
    }
    app->log("Exiting Auto Connect");

    if (enableIPC) {
        app->notifyStop();
        app->sendMessage(pBuf);
        UnmapViewOfFile(pBuf);
        CloseHandle(hMapFile);
    }
    app->m_IsRunning = false;
}


bool AutoConnectWindows::findAllDevices(pcap_if_t **alldevsp, char *errbuf) {
    if (pcap_findalldevs(alldevsp, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return false;
    }
    return true;
}


void AutoConnectWindows::adapterScan(void *ctx) {
    auto *app = static_cast<AutoConnectWindows *>(ctx);
    app->log("Performing adapter scan");
    constexpr auto timeout = std::chrono::seconds(5);

    while (app->m_ScanAdapters) {
        std::vector<Adapter> adapters;
        pcap_if_t *alldevs;
        pcap_if_t *d;
        char errbuf[PCAP_ERRBUF_SIZE] = {0};

        auto findDevicesFuture = std::async(std::launch::async, &AutoConnectWindows::findAllDevices, app, &alldevs,
                                            errbuf);

        if (findDevicesFuture.wait_for(timeout) == std::future_status::ready) {
            if (!findDevicesFuture.get()) {
                app->log("pcap device list returned error");
                continue;
            } else {

            }
        } else {
            app->log("Waiting for pcap device list");
            continue;
        }

        // Print the list
        int i = 0;
        std::string prefix = "\\Device\\Tcpip_";
        const char *token = "{";
        // Find { token in order to find correct prefix
        for (d = alldevs; d; d = d->next) {
            Adapter adapter(d->name, 0);
            if (d->description)
                adapter.description = d->description;
            size_t found = std::string(d->name).find(token);
            if (found != std::string::npos)
                prefix = std::string(d->name).substr(0, found);
        }
        pcap_freealldevs(alldevs);

        DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
        PIP_ADAPTER_INFO AdapterInfo;
        AdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
        // Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
        if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(AdapterInfo);
            AdapterInfo = (IP_ADAPTER_INFO *) malloc(dwBufLen);
            if (AdapterInfo == NULL) {
                app->log("Error in allocating memory for GetAdaptersInfo");
                free(AdapterInfo);
                continue;
            }
        }
        if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
            // Contains pointer to current adapter info
            PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
            do {
                // Somehow The integrated bluetooth adapter is considered an ethernet adapter cause of the same type in PIP_ADAPTER_INFO field "MIB_IF_TYPE_ETHERNET"
                // I'll filter it out here assuming it has Bluetooth in its name. Just a soft error which increases running time of the auto connect feature
                char *bleFoundInName = strstr(pAdapterInfo->Description, "Bluetooth");
                if (bleFoundInName || pAdapterInfo->Type != MIB_IF_TYPE_ETHERNET) {
                    pAdapterInfo = pAdapterInfo->Next;
                    continue;
                }

                // Internal loopback device always located at index = 1. Skip it..
                if (pAdapterInfo->Index == 1) {
                    pAdapterInfo = pAdapterInfo->Next;
                    continue;
                }

                Adapter adapter("Unnamed", 0);
                adapter.supports = (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET);
                adapter.description = pAdapterInfo->Description;

                //CONCATENATE two strings safely windows workaround
                int lenA = strlen(prefix.c_str());
                int lenB = strlen(pAdapterInfo->AdapterName);
                char *con = (char *) malloc(lenA + lenB + 1);
                memcpy(con, prefix.c_str(), lenA);
                memcpy(con + lenA, pAdapterInfo->AdapterName, lenB + 1);
                adapter.ifName = con;
                //adapter.networkAdapter = pAdapterInfo->AdapterName;
                adapter.ifIndex = pAdapterInfo->Index;
                adapters.push_back(adapter);
                free(con);
                pAdapterInfo = pAdapterInfo->Next;
            } while (pAdapterInfo);
        }
        free(AdapterInfo);
        // Put into shared list
        // If the name is new then insert it in the list
        {
            std::scoped_lock<std::mutex> lock(app->m_AdaptersMutex);
            for (const auto &adapter: adapters) {
                bool exist = false;
                for (const auto &shared: app->m_Adapters) {
                    if (shared.ifName == adapter.ifName)
                        exist = true;
                }
                if (!exist) {
                    app->m_Adapters.emplace_back(adapter);
                    app->log("Found adapter: ", adapter.description, " index: ", adapter.ifIndex, " supports: ",
                             adapter.supports);

                }
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void AutoConnectWindows::listenOnAdapter(void *ctx, Adapter *adapter) {
    auto *app = static_cast<AutoConnectWindows *>(ctx);
    // Submit request for a socket descriptor to look up interface.


    pcap_if_t *alldevs{};
    pcap_t *adhandle{};
    int res = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct tm *ltime{};
    char timestr[16];
    struct pcap_pkthdr *header{};
    const u_char *pkt_data{};
    time_t local_tv_sec{};
    // Open the adapter
    app->log("Opening adapter: ", adapter->description);
    if ((adhandle = pcap_open_live(adapter->ifName.c_str(),    // name of the device
                                   65536,            // portion of the packet to capture.
            // 65536 grants that the whole packet will be captured on all the MACs.
                                   1,                // promiscuous mode (nonzero means promiscuous)
                                   1000,            // read timeout
                                   errbuf            // error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. \n %s is not supported by WinPcap\n",
                adapter->ifName.c_str());
        app->log("WinPcap was unable to open the adapter: \n'" + adapter->description +
                 "'\nMake sure WinPcap is installed \nCheck the adapter connection and try again");
        return;
    }
    auto startListenTime = std::chrono::steady_clock::now();
    float timeOut = 15.0f;
    app->log("Performing MultiSense camera search on adapter: ", adapter->description);
    while (app->m_ListenOnAdapter) {
        // Timeout handler
        // Will timeout MAX_CONNECTION_ATTEMPTS times until retrying on new adapter
        auto timeSpan = std::chrono::duration_cast<std::chrono::duration<float>>(
                std::chrono::steady_clock::now() - startListenTime);
        if (timeSpan.count() > timeOut)         // x Seconds, then break loop
            break;

        res = pcap_next_ex(adhandle, &header, &pkt_data);

        // Retry if no packet was received
        if (res == 0)
            continue;

        // convert the timestamp to readable format
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
        if (pkt_data == nullptr) {
            continue;
        }

        // retireve the position of the ip header
        auto *ih = (iphdr *) (pkt_data + 14); //length of ethernet header

        char ips[255];
        sprintf(ips, "%d.%d.%d.%d", (ih->saddr >> (8 * 0)) & 0xff,
                (ih->saddr >> (8 * 1)) & 0xff,
                (ih->saddr >> (8 * 2)) & 0xff,
                (ih->saddr >> (8 * 3)) & 0xff);

        if (ih->protocol == 2) {
            //Check the Protocol and do accordingly...
            std::string address = std::string(ips);
            // If not already in vector
            std::scoped_lock<std::mutex> lock(app->m_AdaptersMutex);
            if (std::find(adapter->IPAddresses.begin(), adapter->IPAddresses.end(), address) ==
                adapter->IPAddresses.end() &&
                std::find(adapter->searchedIPs.begin(), adapter->searchedIPs.end(), address) ==
                adapter->searchedIPs.end()
                    ) {
                app->log("Found address ", address.c_str(), " On adapter: ", adapter->description.c_str());
                adapter->IPAddresses.emplace_back(address);

            }
        }
    }
}

void AutoConnectWindows::checkForCamera(void *ctx, Adapter *adapter) {
    std::string address;
    std::string adapterName;
    std::string description;
    uint32_t ifIndex;
    auto *app = static_cast<AutoConnectWindows *>(ctx);
    {
        std::scoped_lock<std::mutex> lock(app->m_AdaptersMutex);
        if (!app->m_IsRunning || !app->m_ListenOnAdapter || !app->m_ScanAdapters)
            return;
        bool searchedAll = false;
        for (const auto &item: adapter->IPAddresses) {
            if (adapter->isSearched(item)) {
                searchedAll = true;
            }
        }
        if (searchedAll) {
            adapter->checkingForCamera = false;
            return;
        }
        description = adapter->description;
        ifIndex = adapter->ifIndex;
        address = adapter->IPAddresses.front();
        adapterName = adapter->ifName;
        adapter->IPAddresses.erase(adapter->IPAddresses.begin());

    }

    // Set the host ip address to the same subnet but with *.2 at the end.
    std::string hostAddress = address;
    std::string last_element(hostAddress.substr(hostAddress.rfind(".")));
    auto ptr = hostAddress.rfind('.');
    hostAddress.replace(ptr, last_element.length(), ".2");
    app->log("Checking if there is a MultiSense device at: ", address, " Adapter: ", description);


    //str = "Configuring NetAdapter...";
    //m_EventCallback(str, m_Context, 0);
    //regEditor.readAndBackupRegisty();
    //regEditor.setTCPIPValues(hostAddress, "255.255.255.0");
    // 8 Seconds to wait for adapter to restart. This will vary from machine to machine and should be re-done
    // If possible then wait for a windows event that triggers when the adapter is ready
    // std::this_thread::sleep_for(std::chrono::milliseconds(8000));
    // Wait for adapter to come back online

    // - Non persistent configuration
    WinRegEditor regEditor(adapter->ifIndex, hostAddress, "255.255.255.0");
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));

    // Attempt to connect to camera and post some info
    auto *channelPtr = crl::multisense::Channel::Create(address);
    {
        if (channelPtr != nullptr) {
            app->log("Found a MultiSense device at: ", address.c_str());
            crl::multisense::system::DeviceInfo info;
            channelPtr->getDeviceInfo(info);
            crl::multisense::Channel::Destroy(channelPtr);

            std::scoped_lock<std::mutex> lock(app->m_AdaptersMutex);
            adapter->cameraNameList.emplace_back(info.name);
            adapter->cameraIPAddresses.emplace_back(address);
            {
                std::scoped_lock<std::mutex> lock2(app->m_logQueueMutex);
                app->out["Result"].emplace_back(adapter->sendAdapterResult());
            }
        } else {
            app->log("Could not connect to camera at ", address);
        }
        adapter->searchedIPs.emplace_back(address);
        adapter->checkingForCamera = false;
    }
}

void AutoConnectWindows::cleanUp() {
    m_IsRunning = false;
    m_ListenOnAdapter = false;
    m_ScanAdapters = false;
}
