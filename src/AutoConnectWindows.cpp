//
// Created by mgjer on 14/07/2022.
//


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
    strcpy((char *) pBuf, to_string(out).c_str());
    //CopyMemory((PVOID) pBuf, szMsg, (_tcslen(szMsg) * sizeof(TCHAR)));
}


void AutoConnectWindows::getMessage(LPCTSTR pBuf) {
    std::string str(pBuf + (SharedBufferSize / 2));
    memset((char *) pBuf + (SharedBufferSize / 2), 0x00, SharedBufferSize / 2);

    if (!str.empty()) {
        auto json = nlohmann::json::parse(str);

        if (json.contains("Command")) {
            if (json["Command"] == "Stop") {
                log("Stopping auto connect");
                sendMessage(pBuf);
                cleanUp();
            }
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

        if (hMapFile == NULL) {
            _tprintf(TEXT("Could not create file mapping object (%lu).\n"),
                     GetLastError());
            return;
        }
        pBuf = (LPTSTR) MapViewOfFile(hMapFile,   // handle to map object
                                      FILE_MAP_ALL_ACCESS, // read/write permission
                                      0,
                                      0,
                                      SharedBufferSize);

        if (pBuf == NULL) {
            _tprintf(TEXT("Could not map view of file (%lu).\n"), GetLastError());
            CloseHandle(hMapFile);
            return;
        }
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

        app->sendMessage(pBuf);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        app->getMessage(pBuf);
        auto time_span = std::chrono::duration_cast<std::chrono::duration<float>>(
                std::chrono::steady_clock::now() - time);
        if (time_span.count() > 30) {
            app->log("Time limit of 30s reached. Quitting..");
            break;
        }
    }
    app->log("Exiting autoconnect");
    app->notifyStop();
    app->sendMessage(pBuf);
    if (enableIPC) {
        UnmapViewOfFile(pBuf);
        CloseHandle(hMapFile);
    }
    app->m_IsRunning = false;
}

void AutoConnectWindows::adapterScan(void *ctx) {
    auto *app = static_cast<AutoConnectWindows *>(ctx);

    while (app->m_ScanAdapters) {
        std::vector<Adapter> adapters;
        pcap_if_t *alldevs;
        pcap_if_t *d;
        char errbuf[PCAP_ERRBUF_SIZE];

        // Retrieve the device list
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            app->log("Error in pcap_findalldevs: ", errbuf);
            return;
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
                    app->log("Found adapter: ", adapter.ifName, " index: ", adapter.ifIndex, " supports: ",
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
    app->log("Configuring adapter: ", adapter->ifName);


    pcap_if_t *alldevs{};
    pcap_t *adhandle{};
    int res = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct tm *ltime{};
    char timestr[16];
    struct pcap_pkthdr *header{};
    const u_char *pkt_data{};
    time_t local_tv_sec{};
    bool adapterOpened = true;

    // Open the adapter
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
                 "'\nMake sure WinPcap is installed \nCheck the adapter connection and try again \n");

        adapterOpened = false;
    }
    auto startListenTime = std::chrono::steady_clock::now();
    float timeOut = 15.0f;
    app->log("Performing MultiSense camera search on adapter: ", adapter->ifName);
    while (app->m_ListenOnAdapter && adapterOpened) {
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
                adapter->IPAddresses.end()) {
                app->log("Address ", address.c_str(), " On adapter: ", adapter->ifName.c_str());
                adapter->IPAddresses.emplace_back(address);

            }
        }
    }
    app->log("Finished search on: ", adapter->ifName.c_str());
}

void AutoConnectWindows::checkForCamera(void *ctx, Adapter *adapter) {
    std::string address;
    std::string adapterName;
    auto *app = static_cast<AutoConnectWindows *>(ctx);
    {
        std::scoped_lock<std::mutex> lock(app->m_AdaptersMutex);
        bool searchedAll = true;
        for (const auto &item: adapter->IPAddresses) {
            if (!adapter->isSearched(item)) {
                searchedAll = false;
            }
        }
        if (searchedAll) {
            adapter->checkingForCamera = false;
            return;
        }
        address = adapter->IPAddresses.back();
        adapterName = adapter->ifName;
    }

    // Set the host ip address to the same subnet but with *.2 at the end.
    std::string hostAddress = address;
    std::string last_element(hostAddress.substr(hostAddress.rfind(".")));
    auto ptr = hostAddress.rfind('.');
    hostAddress.replace(ptr, last_element.length(), ".2");
    app->log("Checking for camera on ", address, " using: ", adapterName, " Own address is: ", hostAddress);

    //WinRegEditor regEditorStatic(adapter->ifName, adapter->description, adapter->ifIndex);
    //if (regEditorStatic.ready) {
        //str = "Configuring NetAdapter...";
        //m_EventCallback(str, m_Context, 0);
        //regEditor.readAndBackupRegisty();
        //regEditor.setTCPIPValues(hostAddress, "255.255.255.0");
        //regEditor.setJumboPacket("9014");
        //regEditor.restartNetAdapters();
        // 8 Seconds to wait for adapter to restart. This will vary from machine to machine and should be re-done
        // If possible then wait for a windows event that triggers when the adapter is ready
        // std::this_thread::sleep_for(std::chrono::milliseconds(8000));
        // Wait for adapter to come back online
    //}
    // - Non persistent configuration
    WinRegEditor regEditor(adapter->ifIndex, hostAddress, "255.255.255.0");
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    // Attempt to connect to camera and post some info
    auto* channelPtr = crl::multisense::Channel::Create(address);
    {
        std::scoped_lock<std::mutex> lock(app->m_AdaptersMutex);
        if (channelPtr != nullptr) {
            app->log("Found camera on: ", address.c_str());
            crl::multisense::system::DeviceInfo info;
            channelPtr->getDeviceInfo(info);
            adapter->cameraNameList.emplace_back(info.name);
            crl::multisense::Channel::Destroy(channelPtr);
            adapter->cameraIPAddresses.emplace_back(address);
            {
                std::scoped_lock<std::mutex> lock2(app->m_logQueueMutex);
                app->out["Result"].emplace_back(adapter->sendAdapterResult());
            }
        } else {
            app->log("No camera on ", address);
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


/*
void
AutoConnectWindows::findEthernetAdapters(void *ctx, bool logEvent, bool skipIgnored,
                                         std::vector<AutoConnect::Result> *res) {
    auto *app = static_cast<AutoConnectWindows *>(ctx);
    std::vector<AutoConnect::Result> tempList;
    if (!logEvent)
        app->shutdownT2Ready = false;

    while (app->m_RunAdapterSearch) {
        tempList.clear();
        pcap_if_t *alldevs;
        pcap_if_t *d;
        char errbuf[PCAP_ERRBUF_SIZE];

        /* Retrieve the device list
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cout << "Error in pcap_findalldevs: " << errbuf << std::endl;
            return;
        }


        // Print the list
        int i = 0;
        std::string prefix = "\\Device\\Tcpip_";
        const char *token = "{";
        // Find { token in order to find correct prefix
        for (d = alldevs; d; d = d->next) {
            Result adapter(UNNAMED_ADAPTER, 0);
            if (d->description)
                adapter.description = d->description;
            size_t found = std::string(d->name).find(token);
            if (found != std::string::npos)
                prefix = std::string(d->name).substr(0, found);
        }

        DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
        PIP_ADAPTER_INFO AdapterInfo;
        AdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
        // Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
        if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(AdapterInfo);
            AdapterInfo = (IP_ADAPTER_INFO *) malloc(dwBufLen);
            if (AdapterInfo == NULL) {
                printf("Error allocating memory needed to call GetAdaptersinfo\n");
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

                Result adapter(UNNAMED_ADAPTER, 0);
                adapter.supports = (pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET);
                adapter.description = pAdapterInfo->Description;

                /*CONCATENATE two strings safely windows workaround
                int lenA = strlen(prefix.c_str());
                int lenB = strlen(pAdapterInfo->AdapterName);
                char *con = (char *) malloc(lenA + lenB + 1);
                memcpy(con, prefix.c_str(), lenA);
                memcpy(con + lenA, pAdapterInfo->AdapterName, lenB + 1);
                adapter.networkAdapterLongName = con;
                adapter.networkAdapter = pAdapterInfo->AdapterName;
                adapter.index = pAdapterInfo->Index;
                tempList.push_back(adapter);
                free(con);

                pAdapterInfo = pAdapterInfo->Next;
            } while (pAdapterInfo);
        }
        free(AdapterInfo);

        {
            std::scoped_lock<std::mutex> lock(app->readSupportedAdaptersMutex);
            *res = tempList;
            if (!res->empty())
                app->onFoundAdapters(*res, logEvent);
        }
        if (logEvent)
            break;
    }

    if (!logEvent)
        app->shutdownT2Ready = true;
}

void AutoConnectWindows::onFoundAdapters(std::vector<Result> adapters, bool logEvent) {
}


AutoConnect::FoundCameraOnIp AutoConnectWindows::onFoundIp(std::string address, Result adapter, int camera_fd) {


    std::string hostAddress(address);

    size_t it = hostAddress.rfind('.', hostAddress.length());
    hostAddress.replace(it, hostAddress.length(), ".2");

    std::string str = "Setting host address to: " + hostAddress;
    m_EventCallback(str, m_Context, 0);

    /* STATIC CONFIGURATION
    WinRegEditor regEditorStatic(adapter.networkAdapter, adapter.description, adapter.index);
    if (regEditorStatic.ready) {
        //str = "Configuring NetAdapter...";
        //m_EventCallback(str, m_Context, 0);
        //regEditor.readAndBackupRegisty();
        //regEditor.setTCPIPValues(hostAddress, "255.255.255.0");
        //regEditor.setJumboPacket("9014");
        //regEditor.restartNetAdapters();
        // 8 Seconds to wait for adapter to restart. This will vary from machine to machine and should be re-done
        // If possible then wait for a windows event that triggers when the adapter is ready
        // std::this_thread::sleep_for(std::chrono::milliseconds(8000));
        // TODO: thread_sleep - Explanation above
        str = "Configuration...";
        m_EventCallback(str, m_Context, 0);
        // Wait for adapter to come back online
    }
    // - Non persistent configuration
    str = "Checking for camera at: " + address;
    m_EventCallback(str, m_Context, 0);
    WinRegEditor regEditor(adapter.index, hostAddress, "255.255.255.0");
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));


    if (interrupt) {
        shutdownT1Ready = true;
        return NO_CAMERA;
    }
    // Attempt to connect to camera and post some info
    cameraInterface = crl::multisense::Channel::Create(address);

    if (cameraInterface == nullptr && connectAttemptCounter >= MAX_CONNECTION_ATTEMPTS) {
        connectAttemptCounter = 0;
        return NO_CAMERA;
    } else if (cameraInterface == nullptr) {
        connectAttemptCounter++;
        return NO_CAMERA_RETRY;
    } else {
        result = adapter;
        result.cameraIpv4Address = address;
        connectAttemptCounter = 0;
        str = "Found camera at: " + address + "";
        m_EventCallback(str, m_Context, 1);
        return FOUND_CAMERA;
    }

}

void AutoConnectWindows::onFoundCamera() {
    m_Callback(result, m_Context);

    crl::multisense::Channel::Destroy(cameraInterface);
}

void AutoConnectWindows::stopAutoConnect() {
    m_LoopAdapters = false;
    m_ListenOnAdapter = false;
    m_ShouldProgramRun = false;

    if (m_TAutoConnect != nullptr && shutdownT1Ready) {
        m_TAutoConnect->join();
        delete m_TAutoConnect;
        m_TAutoConnect = nullptr;
    }
    if (m_TAdapterSearch != nullptr && shutdownT2Ready) {
        m_TAdapterSearch->join();
        delete m_TAdapterSearch;
        m_TAdapterSearch = nullptr;
    }
}

void AutoConnectWindows::start() {
    m_LoopAdapters = true;
    m_ListenOnAdapter = true;
    m_ShouldProgramRun = true;
    if (m_TAutoConnect == nullptr)
        m_TAutoConnect = new std::thread(&AutoConnectWindows::run, this);
    else {
        interrupt = true;
        stopAutoConnect();
        m_LoopAdapters = true;
        m_ListenOnAdapter = true;
        m_ShouldProgramRun = true;
        while(true){
            {
                std::scoped_lock<std::mutex> lock(readSupportedAdaptersMutex);
                if (shutdownT1Ready)
                    break;
            }
        }
        interrupt = false;
        m_TAutoConnect = new std::thread(&AutoConnectWindows::run, this);
    }
}


void AutoConnectWindows::startAdapterSearch() {
    if (m_TAdapterSearch == nullptr && m_ShouldProgramRun) {
        m_RunAdapterSearch = true;
        m_TAdapterSearch = new std::thread(&AutoConnectWindows::findEthernetAdapters, this, false, false,
                                           &supportedAdapters);
    }
}

void AutoConnectWindows::run(void *ctx) {
    std::vector<Result> adapters{};
    auto *app = (AutoConnectWindows *) ctx;
    app->m_EventCallback("Started detection service", app->m_Context, 0);

    // Get list of network adapters that are  supports our application
    std::string hostAddress;
    size_t i = 0;
    app->shutdownT1Ready = false;
    // Loop keeps retrying to connect on supported network adapters.
    while (app->m_LoopAdapters) {

        if (i >= adapters.size()) {
            i = 0;
            app->m_EventCallback("Running adapter search", app->m_Context, 0);
            adapters.clear();
            app->findEthernetAdapters(ctx, true, false, &adapters);
            if (adapters.empty())
            {
                app->m_EventCallback("No adapters found", app->m_Context, 2);
                app->m_EventCallback("Finished", app->m_Context, 0); // This nessage actually sends a stop call to the gui
                break;
            }

            bool testedAllAdapters = !app->m_IgnoreAdapters.empty();
            for (auto &a: adapters) {
                for (const auto &ignore: app->m_IgnoreAdapters) {
                    if (ignore.networkAdapter == a.networkAdapter)
                        a.searched = true;
                }
                if (!a.searched)
                    testedAllAdapters = false;
            }
            if (testedAllAdapters) {
                app->m_EventCallback(adapters.empty() ? "No adapters found" : "No other adapters found", app->m_Context,
                                     0);
                app->m_EventCallback("Finished", app->m_Context, 0); // This nessage actually sends a stop call to the gui
                break;
            }
        }

        Result adapter{};

        adapter = adapters[i];


        if (!adapter.supports) {
            continue;
        }

        // If a camera has al ready been found on the adapter then dont re-run a search on it. Remove it from adapters list
        bool isAlreadySearched = false;
        for (const auto &found: app->m_IgnoreAdapters) {
            if (found.index == adapter.index)
                isAlreadySearched = true;
        }
        if (isAlreadySearched) {
            adapters.erase(adapters.begin() + i);
            continue;
        }

        i++;

        std::string str = "Testing Adapter. Name: " + adapter.description;
        app->m_EventCallback(str, app->m_Context, 0);

        app->startTime = time(nullptr);

        pcap_if_t *alldevs{};
        pcap_t *adhandle{};
        int res = 0;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct tm *ltime{};
        char timestr[16];
        struct pcap_pkthdr *header{};
        const u_char *pkt_data{};
        time_t local_tv_sec{};

        if (app->interrupt) {
            app->shutdownT1Ready = true;
            return;
        }
        /* Open the adapter
        if ((adhandle = pcap_open_live(adapter.networkAdapterLongName.c_str(),    // name of the device
                                       65536,            // portion of the packet to capture.
                // 65536 grants that the whole packet will be captured on all the MACs.
                                       1,                // promiscuous mode (nonzero means promiscuous)
                                       1000,            // read timeout
                                       errbuf            // error buffer
        )) == NULL) {
            fprintf(stderr, "\nUnable to open the adapter. \n %s is not supported by WinPcap\n",
                    adapter.networkAdapterLongName.c_str());

            str = "WinPcap was unable to open the adapter: \n'" + adapter.description +
                  "'\nMake sure WinPcap is installed \nCheck the adapter connection and try again \n";
            app->m_EventCallback(str, app->m_Context, 2);
            app->m_IgnoreAdapters.push_back(adapter);
            /* Free the device list
            continue;
        }

        str = "Set adapter to listen for all activity";
        app->m_EventCallback(str, app->m_Context, 0);

        str = "Waiting for packet at: " + adapter.networkAdapterLongName;
        app->m_EventCallback(str, app->m_Context, 0);
        while (app->m_ListenOnAdapter) {
            if (app->interrupt) {
                app->shutdownT1Ready = true;
                return;
            }
            // Timeout handler
            // Will timeout the number of MAX_CONNECTION_ATTEMPTS. After so many timeouts we retry on a new adapter
            if ((time(nullptr) - app->startTime) > TIMEOUT_INTERVAL_SECONDS &&
                app->connectAttemptCounter < MAX_CONNECTION_ATTEMPTS) {
                app->startTime = time(nullptr);
                printf("\n");
                str = "Timeout reached. Retrying... (" + std::to_string(app->connectAttemptCounter + 1) + "/" +
                      std::to_string(MAX_CONNECTION_ATTEMPTS) + ")";
                app->m_EventCallback(str, app->m_Context, 0);
                app->connectAttemptCounter++;
                str = "Waiting for packet at: " + adapter.networkAdapter;
                app->m_EventCallback(str, app->m_Context, 0);
            } else if ((time(nullptr) - app->startTime) > TIMEOUT_INTERVAL_SECONDS &&
                       app->connectAttemptCounter >= MAX_CONNECTION_ATTEMPTS) {
                app->startTime = time(nullptr);
                printf("\n");
                str = "Timeout reached. Switching to next supported adapter";
                app->m_EventCallback(str, app->m_Context, 2);
                app->connectAttemptCounter = 0;
                app->m_IgnoreAdapters.push_back(adapter);
                break;

            }

            res = pcap_next_ex(adhandle, &header, &pkt_data);

            // Retry if no packet was received
            if (res == 0)
                continue;
            /* convert the timestamp to readable format
            local_tv_sec = header->ts.tv_sec;
            ltime = localtime(&local_tv_sec);
            strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
            if (pkt_data == nullptr) {
                continue;
            }
            if (app->interrupt) {
                app->shutdownT1Ready = true;
                return;
            }

            /* retireve the position of the ip header
            auto *ih = (iphdr *) (pkt_data + 14); //length of ethernet header

            char ips[255];
            //std::string ips;
            sprintf(ips, "%d.%d.%d.%d", (ih->saddr >> (8 * 0)) & 0xff,
                    (ih->saddr >> (8 * 1)) & 0xff,
                    (ih->saddr >> (8 * 2)) & 0xff,
                    (ih->saddr >> (8 * 3)) & 0xff);

            if (ih->protocol == 2) {

                str = "Packet found. Source address: " + std::string(ips);
                app->m_EventCallback(str, app->m_Context, 0);


                FoundCameraOnIp ret = app->onFoundIp(ips, adapter, 0);

                if (app->interrupt) {
                    app->shutdownT1Ready = true;
                    return;
                }

                if (ret == FOUND_CAMERA) {
                    app->m_IgnoreAdapters.push_back(adapter);
                    app->onFoundCamera();
                    pcap_close(adhandle);
                    break;
                } else if (ret == NO_CAMERA_RETRY) {
                    app->m_EventCallback("Did not find a camera. Retrying...", app->m_Context, 2);
                    continue;
                } else if (ret == NO_CAMERA) {
                    app->m_EventCallback("Did not find a camera on the adapter", app->m_Context, 2);
                    pcap_close(adhandle);
                    break;
                }
            }
        }
    }
    app->shutdownT1Ready = true;
}

AutoConnect::Result AutoConnectWindows::getResult() {
    return result;
}

crl::multisense::Channel *AutoConnectWindows::getCameraChannel() {
    return cameraInterface;
}


void AutoConnectWindows::setDetectedCallback(void (*param)(Result result1, void *ctx), void *m_Context) {
    m_Callback = param;
    this->m_Context = m_Context;

}

bool AutoConnectWindows::isRunning() {
    return m_ShouldProgramRun;  // Note: This is just confusing usage... future technical debt right here
}

void AutoConnectWindows::setShouldProgramRun(bool close) {
    this->m_ShouldProgramRun = close;  // Note: This is just confusing usage... future technical debt right here
}

void AutoConnectWindows::setEventCallback(void (*param)(const std::string &str, void *, int)) {
    m_EventCallback = param;

}

void AutoConnectWindows::clearSearchedAdapters() {
    m_IgnoreAdapters.clear();
}
 */
