cmake_minimum_required(VERSION 3.2)
project(AutoConnect LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

# Use cases:
# 1. Clone this as a standalone project
# Uses cmake-git to fetch  LibMultiSense as submodule

# 2. This is a submodule part of another project
# Enable cmake policy 0877
# Set BUILD_STANDALONE to OFF
# add this subdirectory
# Use however

include_directories("include")
option(BUILD_STANDALONE "build this executable without viewer. Manual link to LibMultiSense" ON)

if (BUILD_STANDALONE)
    message("Building standalone version")
    set(BUILD_SHARED_LIBS ON)
    include(cmake/Common.cmake)
else()
    message("Building integrated version")
endif()

if (WIN32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVK_PROTOTYPES")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVK_PROTOTYPES")

    if (MSVC)
        set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
    endif ()

    add_subdirectory(WinPcap)
    include_directories("include/WinPcap")

    add_subdirectory("getopt")

    add_library(LibAutoConnect STATIC src/AutoConnectWindows.cpp)
    target_link_libraries(LibAutoConnect MultiSense winpcap_lib packet_lib iphlpapi)

    add_executable(AutoConnect src/Main.cpp)
    target_link_libraries(AutoConnect LibAutoConnect getopt)

    add_executable(WinReader src/WinIPCReader.cpp)
    target_link_libraries(WinReader user32)

    set_target_properties(MultiSense PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
            RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin
            RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin
            )

    set_target_properties(AutoConnect PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
            RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin
            RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin
            )

    # create a list of files to copy
    if (BUILD_STANDALONE)
        set(THIRD_PARTY_DLLS
                ${CMAKE_CURRENT_SOURCE_DIR}/WinPcap/wpcap.dll
                ${CMAKE_CURRENT_SOURCE_DIR}/WinPcap/Packet.dll
                )
    endif ()
    # do the copying
    foreach (file_i ${THIRD_PARTY_DLLS})
        add_custom_command(
                TARGET AutoConnect
                POST_BUILD
                COMMAND ${CMAKE_COMMAND}
                ARGS -E copy ${file_i} ${CMAKE_BINARY_DIR}/bin
        )
    endforeach (file_i)

    if (MSVC)
        if (${CMAKE_VERSION} VERSION_LESS "3.6.0")
            message("\n\t[ WARNING ]\n\n\tCMake version lower than 3.6.\n\n\t - Please update CMake and rerun; OR\n\t - Manually set 'GLFW-CMake-starter' as StartUp Project in Visual Studio.\n")
        else ()
            set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT AutoConnect)
        endif ()
    endif ()
endif ()
if(UNIX)
    ## Linux
    add_library(LibAutoConnect STATIC src/AutoConnectLinux.cpp)
    target_link_libraries(LibAutoConnect -lpthread -ltbb MultiSense -lrt)

    add_executable(AutoConnect src/Main.cpp)
    target_link_libraries(AutoConnect LibAutoConnect)

    add_executable(reader src/LinuxIPCReader.cpp)
    target_link_libraries(reader -lpthread -lrt)

endif ()