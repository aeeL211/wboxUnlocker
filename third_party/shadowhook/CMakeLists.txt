# ShadowHook 2.0.1, built as a static library and linked into libaeeL.so.
#
# Only address-based hooks on already-loaded libraries are used. The local
# sh_linker.c patch skips the linker call_constructors/call_destructors hooks
# and the libshadowhook_nothing.so soinfo scan. Do not build or package
# shadowhook_nothing.
if(ANDROID_ABI STREQUAL "arm64-v8a")
  set(SH_ARCH "arm64")
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
  set(SH_ARCH "arm")
else()
  message(FATAL_ERROR "Unsupported ANDROID_ABI for ShadowHook: ${ANDROID_ABI}")
endif()

file(GLOB SHADOWHOOK_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/arch/${SH_ARCH}/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/arch/${SH_ARCH}/*.S"
  "${CMAKE_CURRENT_SOURCE_DIR}/common/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/*/*.c"
)

# sh_jni.c provides the optional Java API. It is not needed here and would
# export a JNI_OnLoad from libaeeL.so.
list(FILTER SHADOWHOOK_SOURCES EXCLUDE REGEX "/sh_jni\\.c$")

add_library(shadowhook STATIC ${SHADOWHOOK_SOURCES})

target_compile_features(shadowhook PRIVATE c_std_11)
target_compile_options(shadowhook PRIVATE
  -Os
  -ffunction-sections
  -fdata-sections
  -fvisibility=hidden
  -Wno-unused-function
)
target_include_directories(shadowhook PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/arch/${SH_ARCH}"
  "${CMAKE_CURRENT_SOURCE_DIR}/common"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/xdl"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/bsd"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lss"
)
target_link_libraries(shadowhook PUBLIC log dl)
set_target_properties(shadowhook PROPERTIES POSITION_INDEPENDENT_CODE ON)
