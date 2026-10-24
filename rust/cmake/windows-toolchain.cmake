# The upstream legacy archive adds an unused .o symlink on Windows. A normal
# DLL/import-library build needs no symbolic-link privilege or source patch.
set(UNICORN_LEGACY_STATIC_ARCHIVE OFF CACHE BOOL "Unused legacy archive" FORCE)
set(BUILD_SHARED_LIBS ON CACHE BOOL "Native Unicorn DLL" FORCE)
set(CMAKE_PROJECT_INCLUDE "${CMAKE_CURRENT_LIST_DIR}/windows-unicorn.cmake")
