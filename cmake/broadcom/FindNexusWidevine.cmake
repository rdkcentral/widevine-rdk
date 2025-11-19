# - Try to find Broadcom Nexus Widevine.
# Once done this will define
#  NexusWidevine_FOUND     - System has a Nexus Widevine
#  NexusWidevine::NexusWidevine - The Nexus Widevine library
#
# Copyright (c) 2025 RDK Management
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1.  Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 2.  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND ITS CONTRIBUTORS ``AS
# IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR ITS
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
#
find_path(LIBNexusWidevine_INCLUDE_DIR cdm.h
        PATH_SUFFIXES widevine refsw openssl
        HINTS ${CMAKE_SYSROOT}/usr/include/widevine/cdm)

find_path(LIBNexusWidevine_INCLUDE_DIR_UTIL string_conversions.h
        PATH_SUFFIXES widevine refsw openssl
        HINTS ${CMAKE_SYSROOT}/usr/include/widevine/util)

find_path(LIBNexusSVP_INCLUDE_DIR sage_srai.h
        PATH_SUFFIXES refsw)

set(LIBNexusWidevine_DEFINITIONS "")

list(APPEND LIBNexusWidevine_INCLUDE_DIRS ${LIBNexusWidevine_INCLUDE_DIR} ${LIBNexusSVP_INCLUDE_DIR}
                                          ${LIBNexusWidevine_INCLUDE_DIR_UTIL})

# main lib
find_library(LIBNexusWidevine_LIBRARY widevine_ce_cdm_shared)
if(NOT LIBNexusWidevine_LIBRARY)
    find_library(LIBNexusWidevine_LIBRARY wvcdm)
endif()

# needed libs
if ((WIDEVINE_VERSION EQUAL 16) OR (WIDEVINE_VERSION EQUAL 17) OR (WIDEVINE_VERSION EQUAL 18))
  list(APPEND NeededLibs protobuf-lite widevine_tl crypto oemcrypto_tl)
else ()
  list(APPEND NeededLibs protobuf-lite cmndrm cmndrm_tl crypto oemcrypto_tl)
endif()
# needed svp libs
list(APPEND NeededLibs drmrootfs srai)
foreach (_library ${NeededLibs})
    find_library(LIBRARY_${_library} ${_library})
    if(NOT EXISTS "${LIBRARY_${_library}}")
        message(SEND_ERROR "Could not find mandatory library: ${_library}")
    endif()
    list(APPEND LIBNexusWidevine_LIBRARIES ${LIBRARY_${_library}})
endforeach ()
if(EXISTS "${LIBNexusWidevine_LIBRARY}")
    include(FindPackageHandleStandardArgs)
    set(NexusWidevine_FOUND TRUE)
    find_package_handle_standard_args(LIBNexusWidevine DEFAULT_MSG LIBNexusWidevine_LIBRARY LIBNEXUS_INCLUDE )
    mark_as_advanced(LIBNexusWidevine_LIBRARY)
    if(NOT TARGET NexusWidevine::NexusWidevine)
        add_library(NexusWidevine::NexusWidevine SHARED IMPORTED)

        set_target_properties(NexusWidevine::NexusWidevine PROPERTIES
                IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                IMPORTED_LOCATION "${LIBNexusWidevine_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${LIBNexusWidevine_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES "${LIBNexusWidevine_LIBRARIES}"
                INTERFACE_COMPILE_OPTIONS "${LIBNexusWidevine_DEFINITIONS}"
                IMPORTED_NO_SONAME TRUE
        )
    endif()
endif()
