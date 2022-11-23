//
// Created by magnus on 7/14/22.
//

#ifndef AUTOCONNECT_AUTOCONNECTLINUX_H
#define AUTOCONNECT_AUTOCONNECTLINUX_H


#include <thread>
#include <mutex>
#include "AutoConnect/ThreadPool.h"

#define NUM_WORKER_THREADS 5

class AutoConnectLinux {

public:

    struct Adapter {
        Adapter() = default;

        explicit Adapter(const char *name, uint32_t index) : ifName(name), ifIndex(index)
        { // By default, we want to initialize an adapter result with a name and support status
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

        bool isSearched(const std::string& ip){
            for (const auto &searched: searchedIPs){
                if (searched == ip)
                    return true;
            }
            return false;
        }

        std::string sendAdapterResult(){
            if (cameraIPAddresses.empty())
                return "";
            char buf[255];
            sprintf(buf, "Adapter: %s, IP:%s, ifIndex:%s", ifName.c_str(), cameraIPAddresses.back().c_str(), std::to_string(ifIndex).c_str());

            return buf;
        }

    };

    ~AutoConnectLinux() {

    }

    AutoConnectLinux(){
        m_Pool = std::make_unique<AutoConnect::ThreadPool>(NUM_WORKER_THREADS);
        m_Pool->Push(adapterScan, this);

    }

    std::unique_ptr<AutoConnect::ThreadPool> m_Pool;
    bool m_ScanAdapters = true;
    std::vector<Adapter> m_Adapters;
    std::mutex m_AdaptersMutex;
    std::queue<std::string> m_LogQueue;

    /**
     * @Brief Starts the search for camera given a list containing network adapters Search is done in another thread
    * @param vector
     */
    void run();
    /** @Brief Function to search for network adapters **/
    /** @Brief cleans up thread**/
    void stopAutoConnect();
    /** @Brief Function called after a search of adapters and at least one adapter was found **/
    /** @Brief Function called when a new IP is found. Return false if you want to keep searching or true to stop further IP searching **/
    /** @Brief Function called when a camera has been found by a successfully connection by LibMultiSense **/
    void onFoundCamera();

    static void adapterScan(void *ctx);
    static void listenOnAdapter(void* ctx, Adapter *adapter);
    static void checkForCamera(void *ctx, Adapter *adapter);

private:
    static void run(void* instance);

};


#endif //AUTOCONNECT_AUTOCONNECTLINUX_H
