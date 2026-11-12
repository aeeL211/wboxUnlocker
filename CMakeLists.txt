cmake_minimum_required(VERSION 3.20)

# The WorldBox APK does not ship libc++_shared.so. Keep the C++ runtime static.
set(ANDROID_STL c++_static)

project(wboxUnlocker C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(third_party/shadowhook)

add_library(aeeL SHARED hook.cpp)

target_compile_options(aeeL PRIVATE
  -O2
  -fvisibility=hidden
  -Wall
  -Wextra
  -Wno-unused-parameter
)

target_include_directories(aeeL PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/shadowhook/include"
)

target_link_libraries(aeeL PRIVATE shadowhook log dl m)

target_link_options(aeeL PRIVATE
  -static-libstdc++
  -Wl,--gc-sections
  -Wl,--exclude-libs,ALL
  -Wl,-s
  -Wl,-z,max-page-size=16384
)
