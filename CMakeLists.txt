cmake_minimum_required(VERSION 3.21)

project(BW_Fetcher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------------------
# External dependency roots (override with -D... to relocate the build)
# ------------------------
if(WIN32)
    set(BORINGSSL_ROOT "D:/C++/gitclone/boringssl"
            CACHE PATH "Root of a built BoringSSL checkout (expects include/ and build/Release/)")
    set(NGHTTP2_ROOT "D:/C++/gitclone/vcpkg/packages/nghttp2_x64-windows"
            CACHE PATH "Root of an nghttp2 install (expects include/, lib/, bin/)")
else()
    set(BORINGSSL_ROOT "$ENV{HOME}/deps/boringssl"
            CACHE PATH "Root of a built BoringSSL checkout (expects include/ and build/)")
endif()

# ------------------------
# Executable target
# ------------------------
set(TARGET_NAME BW_Fetcher)

add_executable(${TARGET_NAME}
        main.cpp
        fetcher.h
        fetcher.cpp
        challenge_scripts.h
        challenge_scripts.cpp
        html_catalog.h
        html_catalog.cpp
        URL_to_DNS/URL_Parser.h
        URL_to_DNS/URL_Parser.cc
        URL_to_DNS/resolve_host.h
        URL_to_DNS/resolve_host.cpp
        decompress.h
        decompress.cpp
        platform_win.h
        HTTP2_Client/http2_client.h
        HTTP2_Client/http2_client.cpp
        BORING_SSL/Boring_SSL_Client_.h
        BORING_SSL/Boring_SSL_Client_.cpp
        BORING_SSL/compresser/brotili_cert_compress.cpp
        BORING_SSL/compresser/brotili_cert_compress.h
        BORING_SSL/Profile_Loader/tls_config.h
        BORING_SSL/Profile_Loader/tls_profiles.h
        BORING_SSL/Profile_Loader/tls_profiles.cpp
        PROXY/proxy_socket5_handshake.h
        PROXY/proxy_socket5_handshake.cpp
)

# Shipped binary filename (CMake target name stays BW_Fetcher).
if(WIN32)
    set(BW_FETCHER_OUTPUT_NAME BW-Fetcher-win64)
else()
    set(BW_FETCHER_OUTPUT_NAME BW-Fetcher-linux64)
endif()
set_target_properties(${TARGET_NAME} PROPERTIES OUTPUT_NAME ${BW_FETCHER_OUTPUT_NAME})

# ------------------------
# BoringSSL (static libs) — same headers, different lib layout per platform.
# ------------------------
target_include_directories(${TARGET_NAME} PRIVATE "${BORINGSSL_ROOT}/include")
if(WIN32)
    target_link_libraries(${TARGET_NAME} PRIVATE
            "${BORINGSSL_ROOT}/build/Release/crypto.lib"
            "${BORINGSSL_ROOT}/build/Release/ssl.lib"
            ws2_32
    )
else()
    # Link ssl before crypto (GNU ld resolves left-to-right); crypto needs pthread+dl.
    target_link_libraries(${TARGET_NAME} PRIVATE
            "${BORINGSSL_ROOT}/build/libssl.a"
            "${BORINGSSL_ROOT}/build/libcrypto.a"
            pthread
            dl
    )
endif()

# ------------------------
# nghttp2 / zlib / brotli
#   Windows: imported DLL target + vcpkg packages.
#   POSIX:   system packages discovered via pkg-config (apt: libnghttp2-dev,
#            zlib1g-dev, libbrotli-dev).
# ------------------------
find_package(ZLIB REQUIRED)
target_link_libraries(${TARGET_NAME} PRIVATE ZLIB::ZLIB)

if(WIN32)
    add_library(nghttp2::nghttp2 SHARED IMPORTED)
    set_target_properties(nghttp2::nghttp2 PROPERTIES
            IMPORTED_IMPLIB "${NGHTTP2_ROOT}/lib/nghttp2.lib"
            IMPORTED_LOCATION "${NGHTTP2_ROOT}/bin/nghttp2.dll"
            INTERFACE_INCLUDE_DIRECTORIES "${NGHTTP2_ROOT}/include"
    )
    target_link_libraries(${TARGET_NAME} PRIVATE nghttp2::nghttp2)

    find_package(unofficial-brotli CONFIG REQUIRED)
    target_link_libraries(${TARGET_NAME} PRIVATE
            unofficial::brotli::brotlidec
            unofficial::brotli::brotlicommon
    )
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2)
    pkg_check_modules(BROTLI  REQUIRED IMPORTED_TARGET libbrotlidec libbrotlicommon)
    target_link_libraries(${TARGET_NAME} PRIVATE
            PkgConfig::NGHTTP2
            PkgConfig::BROTLI
    )
endif()

# ------------------------
# Install rule: stage the exe (+ its runtime DLLs on Windows) into <prefix>/bin.
# Lets `cmake --install . --prefix <dir>` produce a self-contained folder that
# the Python package can bundle.
# ------------------------
install(TARGETS ${TARGET_NAME} RUNTIME DESTINATION bin)
if(WIN32)
    install(FILES $<TARGET_RUNTIME_DLLS:${TARGET_NAME}> DESTINATION bin)
    # ZLIB is found via module-mode FindZLIB (UNKNOWN imported lib), so its DLL
    # is not captured by TARGET_RUNTIME_DLLS. vcpkg's applocal step copies
    # zlib1.dll next to the exe during the build, so grab it from there.
    install(FILES "$<TARGET_FILE_DIR:${TARGET_NAME}>/zlib1.dll" DESTINATION bin OPTIONAL)
endif()
