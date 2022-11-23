# CMAKE FILE DESCRIPTION
# - Sets build type to Release if none was specified
# - Pulls submodules into /external folder
# - Adds each submodule to project add_subdirectory/include_directory
# - Adds internal library Autoconnect
# - Option to enabled all warnings when compiling with GCC

# Set a default build type if none was specified
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(
            STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE
            Release
            CACHE STRING "Choose the type of build." FORCE)
    # Set the possible values of build type for cmake-gui, ccmake
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
            "MinSizeRel" "RelWithDebInfo")
endif ()


find_package(Git QUIET)
if (GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
    # Update submodules as needed
    option(GIT_SUBMODULE "Check submodules during build" ON)
    if (GIT_SUBMODULE)
        message(STATUS "Submodule update")
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                RESULT_VARIABLE GIT_SUBMOD_RESULT)
        if (NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "git submodule update --init --recursive failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
        endif ()
    endif ()
endif ()

# Include Submodules into project.
# Check if exists or display fatal error
set(LIBMULTISENSE_DIR external/LibMultiSense)


if (NOT EXISTS "${PROJECT_SOURCE_DIR}/${LIBMULTISENSE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "The submodules ${LIBMULTISENSE_DIR} not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
else ()
    include_directories(${LIBMULTISENSE_DIR}/source/LibMultiSense)
    add_subdirectory(${LIBMULTISENSE_DIR}/source/LibMultiSense)
endif ()
