find_path(SPDLOG_INCLUDE_DIRS "spdlog/spdlog.h"
  PATHS /usr/include /usr/local/include /opt/local/include)

find_library(SPDLOG_LIBRARY NAMES spdlog libspdlog
  PATHS /usr/lib /usr/local/lib /opt/local/lib /usr/lib/x86_64-linux-gnu)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(spdlog DEFAULT_MSG
  SPDLOG_INCLUDE_DIRS SPDLOG_LIBRARY)

if(SPDLOG_FOUND)
  add_library(spdlog INTERFACE IMPORTED GLOBAL)
  target_include_directories(spdlog INTERFACE ${SPDLOG_INCLUDE_DIRS})
  target_link_libraries(spdlog INTERFACE ${SPDLOG_LIBRARY})
  add_library(spdlog::spdlog ALIAS spdlog)
  message(STATUS "Found spdlog: ${SPDLOG_INCLUDE_DIRS}, ${SPDLOG_LIBRARY}")
else()
  message(FATAL_ERROR "spdlog not found. Please install spdlog-devel or set SPDLOG_ROOT.")
endif()