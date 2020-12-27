cmake_minimum_required (VERSION 2.6)
set(CMAKE_BUILD_TYPE Debug)
set(NAME test.bin)
project (${NAME})

# Update if necessary
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0")
  message(WARNING "Debug mode is activated")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif() 
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

AUX_SOURCE_DIRECTORY(./src/ CTR_SOURCES)

#include_directories(/root/projects/adition/libevent-2.1.8-stable)
#link_directories(/root/projects/adition/libevent-2.1.8-stable)

SET_SOURCE_FILES_PROPERTIES( ${CTR_SOURCES} PROPERTIES LANGUAGE CXX )
SET_SOURCE_FILES_PROPERTIES( ${C_SOURCES} PROPERTIES LANGUAGE C )

add_executable(${NAME} ${CTR_SOURCES} ${C_SOURCES})
target_link_libraries(${NAME} fmt pcre jsoncpp gtest gmock ssl crypto event event_openssl event_pthreads pthread) 
