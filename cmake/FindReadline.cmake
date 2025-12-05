# ABOUTME: CMake module to find GNU Readline library
# ABOUTME: Sets READLINE_FOUND, READLINE_INCLUDE_DIR, READLINE_LIBRARY

# Find readline include directory
find_path(READLINE_INCLUDE_DIR
    NAMES readline/readline.h
    HINTS
        /usr/local/include
        /opt/homebrew/opt/readline/include
        /usr/local/opt/readline/include
    PATH_SUFFIXES readline
)

# Find readline library
find_library(READLINE_LIBRARY
    NAMES readline
    HINTS
        /usr/local/lib
        /opt/homebrew/opt/readline/lib
        /usr/local/opt/readline/lib
)

# Find termcap/ncurses/curses (readline often needs one of these)
# On FreeBSD/OpenBSD, readline is linked against ncurses
# On Linux, it may need termcap or ncurses
find_library(READLINE_TERMCAP_LIBRARY
    NAMES ncurses curses termcap tinfo
    HINTS
        /usr/local/lib
        /opt/homebrew/opt/ncurses/lib
        /usr/local/opt/ncurses/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Readline
    REQUIRED_VARS READLINE_LIBRARY READLINE_INCLUDE_DIR
)

if(READLINE_FOUND)
    set(READLINE_LIBRARIES ${READLINE_LIBRARY})
    if(READLINE_TERMCAP_LIBRARY)
        list(APPEND READLINE_LIBRARIES ${READLINE_TERMCAP_LIBRARY})
    endif()
    set(READLINE_INCLUDE_DIRS ${READLINE_INCLUDE_DIR})
endif()

mark_as_advanced(READLINE_INCLUDE_DIR READLINE_LIBRARY READLINE_TERMCAP_LIBRARY)
