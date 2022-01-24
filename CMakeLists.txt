# Copyright (c) 2022 Sebastian Pipping <sebastian@pipping.org>
# Licensed under the GPL v2 or later

cmake_minimum_required(VERSION 3.16.3)

project(axc
    VERSION
        0.3.7
    # NOTE: Because this^^ version affects shared library filenames,
    #       it needs a major version bump to 1.0.0 already at
    #       the _first ever ABI break_ despite semver rule 4
    #       (https://semver.org/#spec-item-4).
    LANGUAGES
        C
)

include(FindPkgConfig)
include(FindThreads)
include(GNUInstallDirs)


#
# Public configuration
#
option(BUILD_SHARED_LIBS "Build shared libraries (rather than static ones)" ON)
option(AXC_INSTALL "Install build artifacts" ON)
option(AXC_WITH_PTHREADS "Build with pthreads support" ON)
option(AXC_WITH_TESTS "Build test suite (depends on cmocka)" ON)
if(NOT _AXC_HELP)  # hide from "cmake -D_AXC_HELP=ON -LH ." output
    option(_AXC_WARNINGS_AS_ERRORS "(Unofficial!) Turn warnings into errors" OFF)
    option(_AXC_WITH_COVERAGE "(Unofficial!) Build with coverage" OFF)
endif()

if(NOT BUILD_SHARED_LIBS)
    # NOTE: If we don't enforce -fPIC for static(!) libraries, we may run into
    #       "[..] relocation R_X86_64_PC32 against symbol [..]" link errors
    #       in dependent projects trying to link a shared library based on
    #       our static library.
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()


#
# Global CPPFLAGS and CFLAGS
#
add_compile_definitions(
    _XOPEN_SOURCE=700
    _BSD_SOURCE
    _POSIX_SOURCE
    _GNU_SOURCE
    _DEFAULT_SOURCE
)
add_compile_options(
    -std=c99
    -Wall
    -Wextra
    -Wpedantic
    -Wstrict-overflow
    -fno-strict-aliasing
    -funsigned-char
    -fno-builtin-memset
    -Wformat
    -Werror=format-security
)

if(NOT WIN32)
    # Note: This would give link error "undefined reference to `__stack_chk_guard'"
    #       with MinGW
    add_compile_options(-fstack-protector-strong)
endif()

if(_AXC_WARNINGS_AS_ERRORS)
    add_compile_options(-Werror)
endif()

if(_AXC_WITH_COVERAGE)
    set(_AXC_COVERAGE_FLAGS -g -O0 --coverage)
    add_compile_options(${_AXC_COVERAGE_FLAGS})
    link_libraries(${_AXC_COVERAGE_FLAGS})
endif()


#
# Build dependencies
#
if(AXC_WITH_PTHREADS)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif()

# NOTE: We cannot use "pkg_check_modules([..] IMPORTED_TARGET [..])"
#       because we'd run into a (false positive) CMake error
#       "contains relative path in its INTERFACE_INCLUDE_DIRECTORIES"
#       when using "target_link_libraries([..] PkgConfig::[..])" with msys2.
if(AXC_WITH_TESTS)
    pkg_check_modules(CMOCKA REQUIRED "cmocka")
endif()
pkg_check_modules(GLIB REQUIRED "glib-2.0")
pkg_check_modules(GCRYPT REQUIRED "libgcrypt")
pkg_check_modules(SIGNAL REQUIRED "libsignal-protocol-c")
pkg_check_modules(SQLITE REQUIRED "sqlite3")


#
# C library
#
file(GLOB _AXC_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/axc*.[ch])
add_library(axc ${_AXC_SOURCES})
target_include_directories(axc PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)

if(NOT AXC_WITH_PTHREADS)
    # TODO Use target-specific function "target_compile_definitions" instead
    #      once the tests are no longer including libaxc's .c(!) files
    add_compile_definitions(NO_THREADS)
endif()

if(AXC_INSTALL)
    file(GLOB _AXC_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/src/axc*.h)
    target_include_directories(axc PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/axc>)
    install(FILES ${_AXC_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/axc)
    install(TARGETS axc EXPORT axc
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

if(NOT WIN32)
    set_property(TARGET axc PROPERTY VERSION ${PROJECT_VERSION})
    set_property(TARGET axc PROPERTY SOVERSION ${PROJECT_VERSION_MAJOR})
    set_property(TARGET axc PROPERTY NO_SONAME ${NO_SONAME})
endif()


#
# pkg-config/pkgconf file
#
set(_AXC_PKGCONF_EXEC_PREFIX ${CMAKE_INSTALL_PREFIX})
set(_AXC_PKGCONF_LIBDIR ${CMAKE_INSTALL_FULL_LIBDIR})
set(_AXC_PKGCONF_INCLUDEDIR ${CMAKE_INSTALL_FULL_INCLUDEDIR})
set(_AXC_PKGCONF_PREFIX ${CMAKE_INSTALL_PREFIX})
string(REPLACE ${CMAKE_INSTALL_PREFIX} \${exec_prefix} _AXC_PKGCONF_LIBDIR ${_AXC_PKGCONF_LIBDIR})
string(REPLACE ${CMAKE_INSTALL_PREFIX} \${prefix} _AXC_PKGCONF_EXEC_PREFIX ${_AXC_PKGCONF_EXEC_PREFIX})
string(REPLACE ${CMAKE_INSTALL_PREFIX} \${prefix} _AXC_PKGCONF_INCLUDEDIR ${_AXC_PKGCONF_INCLUDEDIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libaxc.pc.cmake ${CMAKE_CURRENT_BINARY_DIR}/libaxc.pc @ONLY)
set_target_properties(axc PROPERTIES ADDITIONAL_CLEAN_FILES ${CMAKE_CURRENT_BINARY_DIR}/libaxc.pc)

if(AXC_INSTALL)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libaxc.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    )
endif()


#
# C example app
#
if(NOT WIN32)
    # NOTE: The message client uses funtion "getline"
    #       which MinGW doesn't have out of the box.
    set(_AXC_EXAMPLE_TARGETS message_client)
    add_executable(message_client ${CMAKE_CURRENT_SOURCE_DIR}/src/message_client.c)
    target_link_libraries(message_client PRIVATE axc)
endif()


#
# C test suite
#
if(AXC_WITH_TESTS)
    set(_AXC_TEST_TARGETS test_client test_store)

    enable_testing()

    foreach(_target ${_AXC_TEST_TARGETS})
        add_executable(${_target} ${CMAKE_CURRENT_SOURCE_DIR}/test/${_target}.c)
        target_link_libraries(${_target} PRIVATE axc)
        add_test(NAME ${_target} COMMAND ${_target})

        if(BUILD_SHARED_LIBS)
            target_compile_options(${_target} PRIVATE ${CMOCKA_CFLAGS})
            target_link_libraries(${_target} PRIVATE ${CMOCKA_LIBRARIES})
        else()
            target_compile_options(${_target} PRIVATE ${CMOCKA_STATIC_CFLAGS})
            target_link_libraries(${_target} PRIVATE ${CMOCKA_STATIC_LIBRARIES})
        endif()
    endforeach()
endif()


#
# External build dependencies
#
foreach(_target axc ${_AXC_EXAMPLE_TARGETS} ${_AXC_TEST_TARGETS})
    if(BUILD_SHARED_LIBS)
        target_compile_options(${_target} PUBLIC ${SIGNAL_CFLAGS})
        target_link_libraries(${_target} PUBLIC ${SIGNAL_LIBRARIES})
    else()
        target_compile_options(${_target} PUBLIC ${SIGNAL_STATIC_CFLAGS})
        target_link_libraries(${_target} PUBLIC ${SIGNAL_STATIC_LIBRARIES})
    endif()

    if(AXC_WITH_PTHREADS)
        target_link_libraries(${_target} PRIVATE Threads::Threads)
    endif()
endforeach()

foreach(_target axc ${_AXC_TEST_TARGETS})
    if(BUILD_SHARED_LIBS)
        # TODO: Tests should stop depending on gcrypt
        #       once the tests stop including libaxc's .c(!) files
        target_compile_options(${_target} PRIVATE ${GCRYPT_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${GCRYPT_LIBRARIES})

        # TODO: Tests should stop depending on glib
        #       once the tests stop including libaxc's .c(!) files
        target_compile_options(${_target} PRIVATE ${GLIB_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${GLIB_LIBRARIES})

        target_compile_options(${_target} PRIVATE ${SQLITE_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${SQLITE_LIBRARIES})
    else()
        # TODO: Tests should stop depending on gcrypt
        #       once the tests stop including libaxc's .c(!) files
        target_compile_options(${_target} PRIVATE ${GCRYPT_STATIC_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${GCRYPT_STATIC_LIBRARIES})

        # TODO: Tests should stop depending on glib
        #       once the tests stop including libaxc's .c(!) files
        target_compile_options(${_target} PRIVATE ${GLIB_STATIC_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${GLIB_STATIC_LIBRARIES})

        target_compile_options(${_target} PRIVATE ${SQLITE_STATIC_CFLAGS})
        target_link_libraries(${_target} PRIVATE ${SQLITE_STATIC_LIBRARIES})
    endif()
endforeach()


#
# Coverage reporting
#
if(_AXC_WITH_COVERAGE)
    add_custom_target(coverage
        COMMAND gcovr -r ${CMAKE_CURRENT_SOURCE_DIR} --html --html-details -o coverage.html
        COMMAND gcovr -r ${CMAKE_CURRENT_SOURCE_DIR} -s
    )
endif()
