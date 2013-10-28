cmake_minimum_required(VERSION 2.8)
project(liblodp)

if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type selected, defaulting to Debug")
	set(CMAKE_BUILD_TYPE "Debug")
endif()

# Make the compiler more anal and enable support for C99.
ADD_DEFINITIONS(-Wall -Werror -std=c99)

# External libraries that we depend on.
set(LIBOTTERY_PATH /opt/libottery)
add_library(libottery STATIC IMPORTED)
set_target_properties(libottery
	PROPERTIES IMPORTED_LOCATION "${LIBOTTERY_PATH}/lib/libottery.a"
)
include_directories("${LIBOTTERY_PATH}/include")

# Use libnostd for certain BSDisms, note that this is entirely unneccecary on
# actual BSD systems.
set(LIBNOSTD_PATH /opt/libnostd)
include_directories("${LIBNOSTD_PATH}/")
include_directories("${LIBNOSTD_PATH}/bsd")

# Actual things that need to be built
add_subdirectory(src)
add_subdirectory(tests)

