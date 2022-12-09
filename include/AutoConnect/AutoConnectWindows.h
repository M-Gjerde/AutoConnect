//
// Created by mgjer on 14/07/2022.
//

#ifndef AUTOCONNECT_AUTOCONNECTWINDOWS_H
#define AUTOCONNECT_AUTOCONNECTWINDOWS_H

#include "AutoConnect/ThreadPool.h"
#define NUM_WORKER_THREADS 5
#include <AutoConnect/json.hpp>
#ifndef _WINDOWS_
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <iostream>

#define SharedBufferSize 65536

#include <cstdio>
#include <conio.h>
#include <tchar.h>

#pragma comment(lib, "ws2_32.lib")


class AutoConnectWindows {

public:

    struct Adapter {
        Adapter() = default;
        explicit Adapter(const char *name, uint32_t index) : ifName(name),
                                                             ifIndex(index) { // By default, we want to initialize an adapter result with a name and an index
        }

        bool supports = true;
        bool available = true;
        bool checkingForCamera = false;
        std::vector<std::string> IPAddresses;
        std::vector<std::string> searchedIPs;
        std::string description;
        std::string ifName;
        uint32_t ifIndex = 0;
        std::vector<std::string> cameraIPAddresses;
        std::vector<std::string> cameraNameList;

        bool isSearched(const std::string &ip) {
            for (const auto &searched: searchedIPs) {
                if (searched == ip)
                    return true;
            }
            return false;
        }

        nlohmann::json sendAdapterResult() {
            nlohmann::json j;
            j["Name"] = ifName;
            j["Index"] = ifIndex;
            j["Description"] = description;
            j["AddressList"] = cameraIPAddresses;
            j["CameraNameList"] = cameraNameList;

            return j;
        }
    };

    ~AutoConnectWindows() = default;

    explicit AutoConnectWindows(bool enableIPC, bool logToConsole = false) {
        out = {
                {"Name", "AutoConnect"},
                {"Log",  {""}}
        };

        if (logToConsole)
            m_LogToConsole = true;

        m_Pool = std::make_unique<AutoConnect::ThreadPool>(NUM_WORKER_THREADS);
        m_IsRunning = true;
        log("Started AutoConnect service");

        m_Pool->Push(AutoConnectWindows::adapterScan, this);
        m_Pool->Push(AutoConnectWindows::runInternal, this, enableIPC);

    }

    [[nodiscard]] bool pollEvents() const {

        return m_IsRunning;
    }

    bool m_LogToConsole = false;

    /**
     * Pushes string to message queue. Mutex protected.
     * Adds a newline character to each message
     * @param msg message to push onto queue
     */
    template<typename ...Args>
    void log(Args &&...args) {
        std::ostringstream stream;
        (stream << ... << std::forward<Args>(args)) << '\n';

        std::scoped_lock<std::mutex> lock(m_logQueueMutex);
        if (out.contains("Log"))
            out["Log"].emplace_back(stream.str());

        if (m_LogToConsole)
            std::cout << stream.str() << std::flush;
    }

    void notifyStop() {
        std::scoped_lock<std::mutex> lock(m_logQueueMutex);
        out["Command"] = "Stop";
        if (m_LogToConsole)
            std::cout << "notifyStop: " << "Stop" << std::endl;
    }

    static void adapterScan(void *ctx);

    static void listenOnAdapter(void *ctx, Adapter *adapter);

    static void checkForCamera(void *ctx, Adapter *adapter);

    void cleanUp();

private:
    nlohmann::json out;

    std::unique_ptr<AutoConnect::ThreadPool> m_Pool;
    std::vector<Adapter> m_Adapters;
    std::mutex m_AdaptersMutex;
    std::mutex m_logQueueMutex;
    bool m_IsRunning = false;
    bool m_ListenOnAdapter = true;
    bool m_ScanAdapters = true;

    static void runInternal(void *ctx, bool enableIPC);

    void reportAndExit(const char *msg);

    void sendMessage(LPCTSTR pBuf);

    void getMessage(LPCTSTR pBuf);
};


#endif //AUTOCONNECT_AUTOCONNECTWINDOWS_H
