cmake_minimum_required(VERSION 3.10)
project(honeyd)

set(CMAKE_COLOR_MAKEFILE ON)

# Make sure we can import out CMake functions
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Read the git tags to determine the project version
include(GetGitVersion)
get_git_version(GIT_VERSION)
# Strip leading 'v' from version string for display
string(REGEX REPLACE "^v" "" VERSION ${GIT_VERSION})
message("-- Version: ${VERSION}")
# Extract semver for library versioning
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" GENERIC_LIB_VERSION ${GIT_VERSION})
string(SUBSTRING ${GENERIC_LIB_VERSION} 0 1 GENERIC_LIB_SOVERSION)

include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckFunctionExists)
include(CheckStructHasMember)
include(CheckTypeSize)
include(FindPkgConfig)
include(TestBigEndian)

find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)

#include(CheckCmakeCompat)
#include(AutoVersioning)
#include(ConfigOptions)
#include(ComplexLibrary)
include(FeatureSummary)
include(CheckCCompilerFlag)
include(GNUInstallDirs)

set(PATH_HONEYDINCLUDE "${CMAKE_INSTALL_FULL_INCLUDEDIR}/honeyd")
set(PATH_HONEYDLIB "${CMAKE_INSTALL_FULL_LIBDIR}/honeyd")
set(PATH_HONEYDDATA "${CMAKE_INSTALL_FULL_DATAROOTDIR}/honeyd")

include(FindZLIB)

# Python 3 support (optional)
find_package(Python3 COMPONENTS Interpreter Development)
if(Python3_FOUND)
    message(STATUS "Python 3 found: ${Python3_EXECUTABLE} (version ${Python3_VERSION})")
    set(HAVE_PYTHON 1)
    include_directories(${Python3_INCLUDE_DIRS})
    # Add compile definition so honeyd.c can include Python.h before config.h
    add_compile_definitions(HAVE_PYTHON=1)
else()
    message(STATUS "Python 3 not found - Python support disabled")
    set(HAVE_PYTHON 0)
endif()

# DISABLE_KQUEUE
# DISABLE_POLL
set(DLOPENLIBC "libc.so.6")
# DL_NEED_UNDERSCORE
check_struct_has_member("struct msghdr" msg_accrights sys/socket.h HAVE_ACCRIGHTS_IN_MSGHDR)
check_function_exists(asprintf HAVE_ASPRINTF)
check_include_files(assert.h HAVE_ASSERT_H)
# HAVE_BROKEN_DNET
check_struct_has_member("struct msghdr" msg_control sys/socket.h HAVE_CONTROL_IN_MSGHDR)
check_function_exists(daemon HAVE_DAEMON)
check_include_files(dlfcn.h HAVE_DLFCN_H)
# HAVE_DOPRNT

# Find libdnet/libdumbnet - Debian uses libdumbnet, others use libdnet
# Try dumbnet first (Debian), then dnet (others)
# Use find_library for better cross-platform support (handles homebrew, etc.)
find_library(DNET_LIBRARY
    NAMES dumbnet dnet
    HINTS
        /opt/homebrew/opt/libdnet/lib
        /usr/local/opt/libdnet/lib
        ENV DNET_ROOT
)

if(DNET_LIBRARY)
    get_filename_component(DNET_LIB_NAME ${DNET_LIBRARY} NAME_WE)
    if(DNET_LIB_NAME MATCHES "dumbnet")
        set(HAVE_DUMBNET 1)
        message(STATUS "Found libdumbnet: ${DNET_LIBRARY}")
    else()
        set(HAVE_DUMBNET 0)
        message(STATUS "Found libdnet: ${DNET_LIBRARY}")
    endif()

    # Find include directory
    find_path(DNET_INCLUDE_DIR
        NAMES dnet.h dumbnet.h
        HINTS
            /opt/homebrew/opt/libdnet/include
            /usr/local/opt/libdnet/include
            ENV DNET_ROOT
        PATH_SUFFIXES include
    )
    if(DNET_INCLUDE_DIR)
        include_directories(${DNET_INCLUDE_DIR})
    endif()
else()
    message(FATAL_ERROR "Neither libdnet nor libdumbnet found. "
        "Install libdumbnet-dev (Debian/Ubuntu), libdnet-dev, or 'brew install libdnet' (macOS)")
endif()

check_function_exists(dup2 HAVE_DUP2)
check_function_exists(err HAVE_ERR)
check_include_files(errno.h HAVE_ERRNO_H)
check_include_files(fcntl.h HAVE_FCNTL_H)
check_function_exists(fgetln HAVE_FGETLN)
check_function_exists(freeaddrinfo HAVE_FREEADDRINFO)
check_function_exists(getaddrinfo HAVE_GETADDRINFO)
check_function_exists(getnameinfo HAVE_GETNAMEINFO)
check_function_exists(getopt_long HAVE_GETOPT_LONG)
check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_function_exists(isblank HAVE_ISBLANK)
check_function_exists(kqueue HAVE_KQUEUE)
# libedit

# Find libevent
find_library(LIBEVENT_LIBRARY
    NAMES event
    HINTS
        /opt/homebrew/opt/libevent/lib
        /usr/local/opt/libevent/lib
        ENV LIBEVENT_ROOT
)

if(LIBEVENT_LIBRARY)
    message(STATUS "Found libevent: ${LIBEVENT_LIBRARY}")
    set(HAVE_LIBEVENT 1)

    find_path(LIBEVENT_INCLUDE_DIR
        NAMES event.h
        HINTS
            /opt/homebrew/opt/libevent/include
            /usr/local/opt/libevent/include
            ENV LIBEVENT_ROOT
        PATH_SUFFIXES include
    )
    if(LIBEVENT_INCLUDE_DIR)
        include_directories(${LIBEVENT_INCLUDE_DIR})
    endif()
else()
    message(FATAL_ERROR "libevent not found. "
        "Install libevent-dev (Debian/Ubuntu) or 'brew install libevent' (macOS)")
endif()

set(HAVE_LIBREADLINE 1)
if (ZLIB_FOUND)
  set(HAVE_LIBZ 1)
endif (ZLIB_FOUND)
# libevent
# libreadline
# libz
check_function_exists(memmove HAVE_MEMMOVE)
check_include_files(memory.h HAVE_MEMORY_H)
check_function_exists(memset HAVE_MEMSET)
check_include_files(net/bpf.h HAVE_NET_BPF_H)
check_include_files(paths.h HAVE_PATHS_H)
check_library_exists(pcap pcap_get_selectable_fd "" HAVE_PCAP_GET_SELECTABLE_FD)
# HAVE_PCAP_GET_SELECTED_FD
#set(HAVE_PCAP_GET_SELECTED_FD)
# HAVE_PYDNET
# HAVE_PYTHON
check_function_exists(recvmsg HAVE_RECVMSG)
check_function_exists(sendmsg HAVE_SENDMSG)
check_function_exists(setgroups HAVE_SETGROUPS)
check_function_exists(setregid HAVE_SETREGID)
check_function_exists(setruid HAVE_SETRUID)
check_function_exists(SHA1Update HAVE_SHA1UPDATE)
check_struct_has_member("struct sockaddr" sa_len sys/socket.h HAVE_SOCKADDR_SA_LEN)
check_include_files(stdarg.h HAVE_STDARG_H)
check_include_files(stdint.h HAVE_STDINT_H)
check_include_files(stdlib.h HAVE_STDLIB_H)
check_function_exists(strcasecmp HAVE_STRCASECMP)
check_function_exists(strchr HAVE_STRCHR)
check_function_exists(strdup HAVE_STRDUP)
check_include_files(strings.h HAVE_STRINGS_H)
check_include_files(string.h HAVE_STRING_H)
check_function_exists(strlcat HAVE_STRLCAT)
check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(strncasecmp HAVE_STRNCASECMP)
check_function_exists(strsep HAVE_STRSEP)
check_function_exists(strspn HAVE_STRSPN)
check_function_exists(strtoul HAVE_STRTOUL)
set(CMAKE_EXTRA_INCLUDE_FILES sys/socket.h)
check_type_size("struct sockaddr_storage" STRUCT_SOCKADDR_STORAGE)
set(CMAKE_EXTRA_INCLUDE_FILES)
check_struct_has_member("struct socketaddr_un" sun_len sys/socket.h HAVE_SUN_LEN)
check_include_files(syslog.h HAVE_SYSLOG_H)
check_include_files(sys/file.h HAVE_SYS_FILE_H)
check_include_files(sys/ioccom.h HAVE_SYS_IOCCOM_H)
check_include_files(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_files(sys/param.h HAVE_SYS_PARAM_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(sys/stat.h HAVE_SYS_STAT_H)
check_include_files(sys/time.h HAVE_SYS_TIME_H)
check_include_files(sys/types.h HAVE_SYS_TYPES_H)
# sys/wait.h posix.1 compatible
set(HAVE_SYS_WAIT_H 1)
set(HAVE_TIMERADD 1)
#check_function_exists(timeradd HAVE_TIMERADD)
check_include_files(time.h HAVE_TIME_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_function_exists(vprintf HAVE_VPRINTF)
# LT_OBJDIR
# NODLOPEN
# PACKAGE
# PACKGE_BUGREPORT
# PACKAGE_NAME
# PACKAGE_STRING
# PACKAGE_TARNAME
# PACKAGE_URL
# PACKAGE_VERSION
# RETSIGTYPE
# STDC_HEADERS
# TIME_WITH_SYS_TIME
# VERSION (now set from git tags via cmake/GetGitVersion.cmake)
# YYTEXT_POINTER
# const
# ...

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Configure files
add_definitions("-DHAVE_CONFIG_H")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# Compatibility sources - only compile if system doesn't have them
set(COMPAT_SOURCES "")
if(NOT HAVE_STRLCPY)
    list(APPEND COMPAT_SOURCES strlcpy.c)
endif()
if(NOT HAVE_STRLCAT)
    list(APPEND COMPAT_SOURCES strlcat.c)
endif()

add_subdirectory(pypcap)
add_subdirectory(regress)

# set the path to the library folder
link_directories(/usr/lib)
#link_directories(/usr/local/lib)

add_definitions(-DHAVE_CONFIG_H)
add_definitions(-D_GNU_SOURCE)

# On macOS, expose BSD types (u_int, u_char, etc.) needed by pcap.h
if(APPLE)
    add_definitions(-D_DARWIN_C_SOURCE)
endif()
add_definitions(-DPATH_HONEYDINCLUDE=\"${PATH_HONEYDINCLUDE}\")
add_definitions(-DPATH_HONEYDLIB=\"${PATH_HONEYDLIB}\")
add_definitions(-DPATH_HONEYDDATA=\"${PATH_HONEYDDATA}\")
add_definitions(-DPATH_RRDTOOL=\"/usr/bin/rrdtool\")
add_definitions(-DHONEYD_PLUGINS_DECLARE=)
add_definitions(-DHONEYD_PLUGINS=)

include_directories (${honeyd_SOURCE_DIR}/compat)
include_directories (${honeyd_SOURCE_DIR}/compat/libdnet)

# Enable compiler warnings
set(WARNING_FLAGS
    -Wall
    -Wextra
    -Wformat=2
    -Wstrict-prototypes
    -Wmissing-prototypes
    -Wold-style-definition
    -Wshadow
    -Wpointer-arith
    -Wcast-qual
    -Wwrite-strings
    -Wundef
    -Wmissing-declarations
    -Wredundant-decls
    -Wno-unused-parameter
)

# Check which warning flags are supported and add them
foreach(flag ${WARNING_FLAGS})
    string(REPLACE "-W" "" flag_var ${flag})
    string(REPLACE "=" "_" flag_var ${flag_var})
    check_c_compiler_flag(${flag} COMPILER_SUPPORTS_${flag_var})
    if(COMPILER_SUPPORTS_${flag_var})
        add_compile_options(${flag})
    endif()
endforeach()

add_executable(hsniff
    hsniff.c
    tagging.c
    stats.c
    util.c
    hooks.c
    interface.c
    pfctl_osfp.c
    pf_osfp.c
    osfp.c
    network.c
    sha1.c
)

# link the libraries to the executable
target_link_libraries (hsniff pcap ${DNET_LIBRARY} ${LIBEVENT_LIBRARY} z dl)

add_executable(honeydctl
    honeydctl.c
    ${COMPAT_SOURCES}
    util.c
    sha1.c
)
target_link_libraries(honeydctl readline termcap ${LIBEVENT_LIBRARY} ${DNET_LIBRARY} pcap dl)

add_library(libhoneyd
    honeyd_overload.c
    atomicio.c
    fdpass.c
)
set_target_properties(libhoneyd PROPERTIES PREFIX "")

add_executable(honeydstats
    honeydstats.c
    honeydstats_main.c
    tagging.c
    stats.c
    util.c
    histogram.c
    analyze.c
    untagging.c
    filter.c
    keycount.c
    sha1.c
)

# link the libraries to the executable
target_link_libraries (honeydstats ${DNET_LIBRARY} ${LIBEVENT_LIBRARY} z dl)

# Generate parser and lexer
BISON_TARGET(HoneydParser parse.y ${CMAKE_CURRENT_BINARY_DIR}/parse.c
    DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/parse.h)
FLEX_TARGET(HoneydLexer lex.l ${CMAKE_CURRENT_BINARY_DIR}/lex.c)
ADD_FLEX_BISON_DEPENDENCY(HoneydLexer HoneydParser)

add_executable(honeyd
    honeyd.c
    command.c
    ${BISON_HoneydParser_OUTPUTS}
    ${FLEX_HoneydLexer_OUTPUTS}
    config.c
    personality.c
    util.c
    ipfrag.c
    router.c
    tcp.c
    udp.c
    xprobe_assoc.c
    log.c
    fdpass.c
    atomicio.c
    subsystem.c
    hooks.c
    plugins.c
    plugins_config.c
    pool.c
    interface.c
    arp.c
    gre.c
    network.c
    pfctl_osfp.c
    pf_osfp.c
    condition.c
    osfp.c
    ui.c
    ethernet.c
    tagging.c
    stats.c
    dhcpclient.c
    rrdtool.c
    histogram.c
    untagging.c
    ${COMPAT_SOURCES}
    sha1.c
)

# Add Python extension sources if Python 3 is available
if(Python3_FOUND AND HAVE_PYTHON)
    target_sources(honeyd PRIVATE
        pyextend.c
        pydataprocessing.c
        pydatahoneyd.c
    )
endif()

# link the libraries to the executable
target_link_libraries (honeyd pcap ${DNET_LIBRARY} ${LIBEVENT_LIBRARY} m z dl)

# Link Python 3 libraries if available
if(Python3_FOUND AND HAVE_PYTHON)
    target_link_libraries(honeyd ${Python3_LIBRARIES})
endif()

# Installation
install(TARGETS honeyd honeydctl honeydstats hsniff
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(TARGETS libhoneyd
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/honeyd)

install(FILES
    config.sample
    nmap.assoc
    nmap-mac-prefixes
    nmap-os-db
    pf.os
    xprobe2.conf
    DESTINATION ${CMAKE_INSTALL_DATADIR}/honeyd)

install(DIRECTORY scripts/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/honeyd/scripts
    USE_SOURCE_PERMISSIONS
    PATTERN "*.pyc" EXCLUDE)

install(DIRECTORY webserver/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/honeyd/webserver
    FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    PATTERN "*.pyc" EXCLUDE
    PATTERN "*.tmplc" EXCLUDE)

# Post-install: precompile templates and set permissions
# Templates must be compiled after install so paths are correct
install(CODE "
    message(STATUS \"Precompiling webserver templates...\")
    execute_process(
        COMMAND ${Python3_EXECUTABLE} \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/honeyd/webserver/precompile_templates.py
                \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/honeyd/webserver/htdocs
        WORKING_DIRECTORY \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/honeyd/webserver
        RESULT_VARIABLE precompile_result
    )
    if(NOT precompile_result EQUAL 0)
        message(WARNING \"Template precompilation failed (error \${precompile_result})\")
    endif()
    message(STATUS \"Setting graphs directory permissions...\")
    execute_process(COMMAND chmod 1777 \${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/honeyd/webserver/htdocs/graphs)
")

install(FILES honeyd.8
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)

install(FILES honeydctl.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
