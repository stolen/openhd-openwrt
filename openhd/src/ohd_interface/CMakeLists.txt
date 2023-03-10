cmake_minimum_required(VERSION 3.16.3)
project(OpenHD-Interface)

set(CMAKE_CXX_STANDARD 17)

# Build and include wifibroadcast
include(../lib/wifibroadcast/WBLib.cmake)

add_library(OHDInterfaceLib STATIC) # initialized below
add_library(OHDInterfaceLib::OHDInterfaceLib ALIAS OHDInterfaceLib)

set(sources
    "inc/wifi_card_discovery.h"
    "inc/ohd_interface.h"
        "inc/wifi_card.hpp"
    "inc/usb_tether_listener.h"
    "inc/validate_settings_helper.h"
    "inc/wb_link.h"
    "inc/wb_link_settings.hpp"
    "inc/wifi_hotspot.h"
    inc/wifi_hotspot_settings.h
    inc/video_forwarder.h
    inc/wb_link_helper.h
    inc/wifi_channel.h
    inc/wifi_command_helper.h
    #inc/wifi_command_helper2.h

    "src/wifi_card_discovery.cpp"
    "src/ohd_interface.cpp"
        "src/usb_tether_listener.cpp"
    "src/wb_link.cpp"
    "src/wifi_hotspot.cpp"
    src/wifi_hotspot_settings.cpp
    src/video_forwarder.cpp
    src/wb_link_helper.cpp
    src/wifi_command_helper.cpp
    #src/wifi_command_helper2.cpp
)

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${sources})

include(CMakePackageConfigHelpers)
target_sources(OHDInterfaceLib PRIVATE ${sources})

target_include_directories(OHDInterfaceLib
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>")

# from https://github.com/alexott/boost-asio-examples/blob/master/CMakeLists.txt
# Find and include boost
# Changed according to https://cliutils.gitlab.io/modern-cmake/chapters/packages/Boost.html
SET(Boost_USE_STATIC_LIBS OFF)
SET(Boost_USE_MULTITHREAD ON)
FIND_PACKAGE(Boost REQUIRED COMPONENTS filesystem)
target_link_libraries(OHDInterfaceLib PUBLIC Boost::filesystem)

find_package(spdlog REQUIRED)
target_link_libraries(OHDInterfaceLib PRIVATE spdlog::spdlog)

# needed to set wifi cards to monitor mode and more
#include(cmake/FindLibNL.cmake)
#target_include_directories(OHDInterfaceLib PRIVATE ${LibNL_INCLUDE_DIR})
#target_link_libraries(OHDInterfaceLib PRIVATE ${LibNL_LIBRARIES})


target_include_directories(OHDInterfaceLib PUBLIC inc/)
target_include_directories(OHDInterfaceLib PUBLIC lib/include)
target_link_libraries(OHDInterfaceLib PUBLIC ${WB_TARGET_LINK_LIBRARIES})
#target_include_directories(OHDInterfaceLib PUBLIC ${WB_INCLUDE_DIRECTORES})

#for some reason, otherwise pi complains about threads
find_package(Threads REQUIRED)
target_link_libraries(OHDInterfaceLib PUBLIC Threads::Threads)

# this one is here but not really part of interface
add_executable(test_led test/test_led.cpp)
target_link_libraries(test_led OHDInterfaceLib)

# Custom testing
add_executable(test_interface test/test_interface.cpp)
target_link_libraries(test_interface OHDInterfaceLib)

#special, temporary
add_executable(test_common_util test/test_common_util.cpp)
target_link_libraries(test_common_util OHDInterfaceLib)

add_executable(test_usb_hotspot test/test_usb_hotspot.cpp)
target_link_libraries(test_usb_hotspot OHDInterfaceLib)

add_executable(test_wifi_hotspot test/test_wifi_hotspot.cpp)
target_link_libraries(test_wifi_hotspot OHDInterfaceLib)