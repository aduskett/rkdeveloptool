# Project name
set (PROJECT_NAME "rkDevelopTool")
cmake_minimum_required (VERSION 3.12)
set(CMAKE_CXX_FLAGS "-fpermissive -std=c++17")

# The version number.
set (RKDevelopTool_PACKAGE_VERSION "1.3")

file (GLOB LOCAL_CPP_FILES src/*.cpp)
set (SOURCE_FILES ${SOURCE_FILES} ${LOCAL_CPP_FILES})

file (GLOB LOCAL_H_FILES src/inc/*.h)
set (HEADER_FILES ${HEADER_FILES} ${LOCAL_H_FILES})

# Set your libusb path
set (libusb_INCLUDE_DIR "/usr/include/libusb-1.0/")

# Set your libiconv path
set (libiconv_INCLUDE_DIR "/usr/include/iconv_hook")

project (${PROJECT_NAME})


# Turn off build log
# set (CMAKE_VERBOSE_MAKEFILE ON)

# Configure a header file to pass some of the CMake settings
# to the source code
configure_file (
    "${PROJECT_SOURCE_DIR}/src/inc/config.h.in"
    "${PROJECT_BINARY_DIR}/config.h"
    )

# add the binary tree to the search path for include files
# so that we will find config.h
include_directories (
    "${PROJECT_BINARY_DIR}"
    "${PROJECT_SOURCE_DIR}"
    "${libusb_INCLUDE_DIR}"
    "${libiconv_INCLUDE_DIR}"
)

add_executable (${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries (
    "${PROJECT_NAME}"
    usb-1.0
)

