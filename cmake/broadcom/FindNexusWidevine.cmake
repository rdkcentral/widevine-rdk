# ============================================================================
# RDK MANAGEMENT, LLC CONFIDENTIAL AND PROPRIETARY
# ============================================================================
# This file (and its contents) are the intellectual property of RDK Management, LLC.
# It may not be used, copied, distributed or otherwise  disclosed in whole or in
# part without the express written permission of RDK Management, LLC.
# ============================================================================
# Copyright (c) 2020 RDK Management, LLC. All rights reserved.
# ============================================================================
# Copyright (C) 2020 Broadcom. The term "Broadcom" refers to Broadcom Limited and/or its subsidiaries.
# ============================================================================
# This program is the proprietary software of Broadcom and/or its licensors,
# and may only be used, duplicated, modified or distributed pursuant to the terms and
# conditions of a separate, written license agreement executed between you and Broadcom
# (an "Authorized License").  Except as set forth in an Authorized License, Broadcom grants
# no license (express or implied), right to use, or waiver of any kind with respect to the
# Software, and Broadcom expressly reserves all rights in and to the Software and all
# intellectual property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU
# HAVE NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY
# NOTIFY BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.
# Except as expressly set forth in the Authorized License,
# 1.     This program, including its structure, sequence and organization, constitutes the valuable trade
#    1. secrets of Broadcom, and you shall use all reasonable efforts to protect the confidentiality thereof,
# and to use this information only in connection with your use of Broadcom integrated circuit products.
# 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
# AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
# WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
# THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND ALL IMPLIED WARRANTIES
# OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,
# LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION
# OR CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF
# USE OR PERFORMANCE OF THE SOFTWARE.
#
# 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR ITS
# LICENSORS BE LIABLE FOR  CONSEQUENTIAL, INCIDENTAL, SPECIAL, INDIRECT, OR
# EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY WAY RELATING TO YOUR
# USE OF OR INABILITY TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT
# ACTUALLY PAID FOR THE SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE
# LIMITATIONS SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF
# ANY LIMITED REMEDY.
###############################################################################
# - Try to find Broadcom Nexus Widevine.
# Once done this will define
#  NexusWidevine_FOUND     - System has a Nexus Widevine
#  NexusWidevine::NexusWidevine - The Nexus Widevine library
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
if (WIDEVINE_VERSION EQUAL 16)
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