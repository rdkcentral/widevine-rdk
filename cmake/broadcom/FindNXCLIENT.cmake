# - Try to find Nexus client.
# Once done this will define
#  NXCLIENT_FOUND     - System has a Nexus client
#  NXCLIENT::NXCLIENT - The Nexus client library
#
###
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2024 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###
find_path(LIBNXCLIENT_INCLUDE nexus_config.h
        PATH_SUFFIXES refsw)
find_library(LIBNXCLIENT_LIBRARY nxclient)
if(EXISTS "${LIBNXCLIENT_LIBRARY}")
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(NXCLIENT DEFAULT_MSG LIBNXCLIENT_INCLUDE LIBNXCLIENT_LIBRARY)
    mark_as_advanced(LIBNXCLIENT_LIBRARY)
    if(NXCLIENT_FOUND AND NOT TARGET NXCLIENT::NXCLIENT)
        add_library(NXCLIENT::NXCLIENT UNKNOWN IMPORTED)
        set_target_properties(NXCLIENT::NXCLIENT PROPERTIES
                IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                IMPORTED_LOCATION "${LIBNXCLIENT_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${LIBNXCLIENT_INCLUDE}"
                )
    endif()
else()
    if(NXCLIENT_FIND_REQUIRED)
        message(FATAL_ERROR "LIBNXCLIENT_LIBRARY not available")
    elseif(NOT NXCLIENT_FIND_QUIETLY)
        message(STATUS "LIBNXCLIENT_LIBRARY not available")
    endif()
endif()
