cmake_minimum_required(VERSION 2.8 FATAL_ERROR)
project("xenpwn")

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -O2 -g")

find_package(PkgConfig)

find_package(Threads)

add_executable(xentrace xentrace.cc state.cc events.cc traceclient.cc modules.cc utils.cc vmi_helper.cc)
add_executable(printtrace analysis/printtrace.cc traceclient.cc)
add_executable(printinstr analysis/printinstr traceclient.cc)
add_executable(doublefetch analysis/doublefetch.cc traceclient.cc)


include_directories(./external/include)
include_directories(${GLIB2_INCLUDE_DIRS})

TARGET_LINK_LIBRARIES(xentrace vmi) 
TARGET_LINK_LIBRARIES(xentrace simutrace) 
TARGET_LINK_LIBRARIES(xentrace ${CMAKE_THREAD_LIBS_INIT})
TARGET_LINK_LIBRARIES(xentrace capstone)
TARGET_LINK_LIBRARIES(printtrace simutrace)
TARGET_LINK_LIBRARIES(doublefetch simutrace)
TARGET_LINK_LIBRARIES(doublefetch capstone)
TARGET_LINK_LIBRARIES(printinstr simutrace)
TARGET_LINK_LIBRARIES(printinstr capstone)
