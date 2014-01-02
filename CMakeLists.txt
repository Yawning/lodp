cmake_minimum_required(VERSION 2.8.5)
project(liblodpxx)

# Some of the crypto uses assembler files
enable_language(ASM)

# Default to debug builds
if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type selected, defaulting to Debug")
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# Tweak the compiler flags
add_definitions(-Wall -Werror -O2)
#add_definitions(-Wall -Werror)
#add_definitions(-Wall -Weffc++)
set(CMAKE_CXX_FLAGS "-std=c++11 -fno-exceptions -fno-rtti")
set(CMAKE_C_FLAGS "-std=c99")

# Need pthreads
find_package(Threads)

# CMake does not autodetect libottery
set(LIBOTTERY_PATH /opt/libottery)
add_library(libottery STATIC IMPORTED)
set_target_properties(libottery
  PROPERTIES IMPORTED_LOCATION "${LIBOTTERY_PATH}/lib/libottery.a"
)
include_directories("${LIBOTTERY_PATH}/include")

# lodp uses protobufs
include(FindProtobuf)
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIR})

# Enable ctest support
enable_testing()

# Add subdirectories
add_subdirectory(src)
add_subdirectory(doc)
