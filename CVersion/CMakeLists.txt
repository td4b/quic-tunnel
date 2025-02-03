# CMakeList.txt : CMake project for ServerProj, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("CVersion")

set(CMAKE_TOOLCHAIN_FILE "/home/vagrant/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
set(CMAKE_PREFIX_PATH "/home/vagrant/vcpkg/installed/x64-linux" CACHE PATH "Prefix path for vcpkg packages")

include_directories("${CMAKE_PREFIX_PATH}/include")
link_directories("${CMAKE_PREFIX_PATH}/lib")

find_package(OpenSSL REQUIRED)
find_package(msquic CONFIG REQUIRED)

option(DEBUG_MODE "Enable Debug Mode" OFF)

# If build type is Debug, force DEBUG_MODE to true
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(DEBUG_MODE ON)
endif()

if(DEBUG_MODE)
    add_definitions(-DDEBUG_MODE=1)

else()
    add_definitions(-DDEBUG_MODE=0)
endif()

# Add source to this project's executable.
add_executable (pingpong
    "server.c" 
    "client.c"  "shared.h" "shared.c" "server.h" "main.c" "client.h" "tun.c"   "tun.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET pingpong PROPERTY CXX_STANDARD 20)
endif()

target_link_libraries(pingpong PRIVATE msquic OpenSSL::SSL OpenSSL::Crypto)
