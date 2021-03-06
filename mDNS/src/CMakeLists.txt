# Copyright (c) 2010-2013 GoPivotal, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

cmake_minimum_required(VERSION 2.8)

message ( "Processing Affinity services/mDNS/src ...")
message ( "processor: "  ${CMAKE_SYSTEM_PROCESSOR})
message ( "Project dir: " ${PROJECT_SOURCE_DIR})

#The following is selecting the package build type - Debug | Release:
#by default -- it will be set as Debug... 
if(NOT CMAKE_BUILD_TYPE)
set (CMAKE_BUILD_TYPE "Debug")
#SET (CMAKE_BUILD_TYPE "Release")
endif(NOT CMAKE_BUILD_TYPE)

message ("System: ${CMAKE_SYSTEM}")
message ("CPU type: ${CMAKE_SYSTEM_PROCESSOR}")
message ( "CMAKE_BUILD_TYPE: " ${CMAKE_BUILD_TYPE} )

#The line below will create ${CPUTYPE} variable, and set it 
#either to  'arm' or  to 'x86' 
STRING( REGEX MATCH "86" CPUTYPE ${CMAKE_SYSTEM_PROCESSOR})
IF(${CPUTYPE} MATCHES "86")
	SET(CPUTYPE "x86")
	message ("CPU: " ${CPUTYPE} )
ELSE (${CPUTYPE} MATCHES "86")
    STRING( REGEX REPLACE "(^.*)([0-9]+).*" "\\1" CPUTYPE  ${CMAKE_SYSTEM_PROCESSOR})
	STRING( REGEX REPLACE "(^.*)([0-9]+).*" "\\2" CPV     ${CMAKE_SYSTEM_PROCESSOR})
	message ("CPU: " ${CPUTYPE} )
	message ("CPU version: " ${CPV})
	if(${CPV} LESS 6)
	   message ("DreamPlug")
	endif(${CPV} LESS 6) 
ENDIF(${CPUTYPE} MATCHES "86")

#setting the name for source dir
SET(SERVICE_SRC_DIR ${PROJECT_SOURCE_DIR}/src)
SET(SERVICE_GLOBAL_HEADER ${PROJECT_SOURCE_DIR}/include)

INCLUDE_DIRECTORIES( "../include" "./" "../../../kernel/include" )

#specifying location of affinity lib
#for now, it is just hard coded in, assuming that both project are located side by side...
SET(AFFINITY_PRJ "${PROJECT_SOURCE_DIR}/../../kernel")

#setting the name of the output library
#since tha all applications name, it is moved `root` CMakeLists.txt...
#SET(SERVICEL_TARGET_NAME "mDNS")

#setting the output directory for the library
SET(LIBRARY_OUTPUT_PATH "${PROJECT_SOURCE_DIR}/lib")
SET(EXECUTABLE_OUTPUT_PATH "${PROJECT_SOURCE_DIR}/bin")

#adding some generic definitions and compiler flags for Windows ...
IF(CMAKE_SYSTEM_NAME MATCHES Windows)
	
	ADD_DEFINITIONS(-DWIN32)
#	ADD_DEFINITIONS(-D_DEBUG)
	ADD_DEFINITIONS(-D_WINDOWS)
	ADD_DEFINITIONS(-D_USRDLL)
	ADD_DEFINITIONS(-DPISTORE_EXPORTS)
	ADD_DEFINITIONS(-D_WINDLL)
	ADD_DEFINITIONS(-D_MBCS)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_DEPRECATE)
    ADD_DEFINITIONS(-D_CRT_NONSTDC_NO_DEPRECATE)
	
	SET( CMAKE_CXX_FLAGS  "/Gm /Zi /EHsc /GS /W3 /nologo /c /Gd /TP ")
#	SET( CMAKE_CXX_FLAGS  "/Od /Gm /EHsc /RTC1 /MDd /GS /W3 /nologo /c /ZI /Gd /TP ")

ENDIF(CMAKE_SYSTEM_NAME MATCHES Windows)


#adding some generic definitions and compiler flags for Linuxi ...
IF(CMAKE_SYSTEM_NAME MATCHES Linux)
    SET(CMAKE_CXX_FLAGS_RELEASE "-O")
    SET(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
    ADD_DEFINITIONS(-D_LINUX)
	ADD_DEFINITIONS(-DPOSIX)

#ADDING  command for 'x86' CPU families...
IF(${CPUTYPE} MATCHES "x86")
    ADD_DEFINITIONS(-DIA32)
IF(CMAKE_BUILD_TYPE MATCHES Debug)
	ADD_DEFINITIONS(-DDEBUG)
	ADD_DEFINITIONS(-D_DEBUG)
IF(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
	SET( CMAKE_CXX_FLAGS  "  -g -O0 -march=nocona -m128bit-long-double -m64 -pthread -fexceptions -fno-strict-aliasing -W -Wall -Wno-parentheses -Wno-unused-parameter -fnon-call-exceptions -Wno-non-virtual-dtor -Wno-deprecated -Wno-write-strings ")
ELSE(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
	SET( CMAKE_CXX_FLAGS  "  -g -O0 -march=i686 -m32 -pthread -fexceptions -fno-strict-aliasing -W -Wall -Wno-parentheses -Wno-unused-parameter -fnon-call-exceptions -Wno-non-virtual-dtor -Wno-deprecated -Wno-write-strings ")
ENDIF(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
ELSE(CMAKE_BUILD_TYPE MATCHES Debug)
	ADD_DEFINITIONS(-DNDEBUG)
IF(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
	SET( CMAKE_CXX_FLAGS  "  -g -O3 -march=nocona -m128bit-long-double -m64 -pthread -fexceptions -fno-strict-aliasing -W -Wall -Wno-parentheses -Wno-unused-parameter -fnon-call-exceptions -Wno-non-virtual-dtor -Wno-deprecated -Wno-write-strings ")
ELSE(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
	SET( CMAKE_CXX_FLAGS  "  -g -O3 -march=i686 -m32 -pthread -fexceptions -fno-strict-aliasing -W -Wall -Wno-parentheses -Wno-unused-parameter -fnon-call-exceptions -Wno-non-virtual-dtor -Wno-deprecated -Wno-write-strings ")
ENDIF (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
ENDIF(CMAKE_BUILD_TYPE MATCHES Debug)
ENDIF(${CPUTYPE} MATCHES "x86")

#ADDING command for 'arm' CPU familes...
IF(${CPUTYPE} MATCHES "arm")
	ADD_DEFINITIONS(-D_LSBF)
	ADD_DEFINITIONS(-D_NO_DCAS)
IF(CMAKE_BUILD_TYPE MATCHES Debug)
#The DEBUG section for the ARM gcc command line... 
	ADD_DEFINITIONS(-DDEBUG)
	ADD_DEFINITIONS(-D_DEBUG)
IF(${CPV} LESS 6)
    ADD_DEFINITIONS(-D_ARMLES6)	
	SET( CMAKE_CXX_FLAGS  "-march=armv5te -pthread -fexceptions -fno-strict-aliasing -W -Wall -Wno-parentheses -Wno-unused-parameter -fnon-call-exceptions -Wno-non-virtual-dtor -Wno-deprecated -Wno-write-strings ")
ELSE(${CPV} LESS 6)
     SET( CMAKE_CXX_FLAGS  "-mcpu=cortex-a9 -marm -pthread -fexceptions -fno-strict-aliasing -W -Wall -Wno-parentheses -Wno-unused-parameter -fnon-call-exceptions -Wno-non-virtual-dtor -Wno-deprecated -Wno-write-strings ")
ENDIF(${CPV} LESS 6)
	
ELSE(CMAKE_BUILD_TYPE MATCHES Debug)
#The RELEASE section for the ARM gcc command line... 
	ADD_DEFINITIONS(-DNDEBUG)
IF(${CPV} LESS 6)
    ADD_DEFINITIONS(-D_ARMLES6)	
	SET( CMAKE_CXX_FLAGS  "-Os -march=armv5te -pthread -fexceptions -fno-strict-aliasing -W -Wall -Wno-parentheses -Wno-unused-parameter -fnon-call-exceptions -Wno-non-virtual-dtor -Wno-deprecated -Wno-write-strings ")
ELSE(${CPV} LESS 6)	
	SET( CMAKE_CXX_FLAGS  "-mcpu=cortex-a9 -marm -pthread -fexceptions -fno-strict-aliasing -W -Wall -Wno-parentheses -Wno-unused-parameter -fnon-call-exceptions -Wno-non-virtual-dtor -Wno-deprecated -Wno-write-strings ")
ENDIF(${CPV} LESS 6)

ENDIF(CMAKE_BUILD_TYPE MATCHES Debug)
ENDIF(${CPUTYPE} MATCHES "arm")

ENDIF(CMAKE_SYSTEM_NAME MATCHES Linux)

#adding some generic definitions and compiler flags for Darwin (Mac OSX) ...
IF(CMAKE_SYSTEM_NAME MATCHES Darwin)
	ADD_DEFINITIONS(-D_LINUX)
	ADD_DEFINITIONS(-DPOSIX)
	ADD_DEFINITIONS(-DDarwin)
	ADD_DEFINITIONS(-DIA32)
	ADD_DEFINITIONS(-DDEBUG)
	ADD_DEFINITIONS(-D_DEBUG)
#ADD_DEFINITIONS(-D__x86_64__)
	   SET( CMAKE_CXX_FLAGS  "-m64  -g -O0 -pthread -fexceptions -fno-strict-aliasing -W -Wall -Wno-unused-parameter -fnon-call-exceptions -Wno-non-virtual-dtor ")
ENDIF(CMAKE_SYSTEM_NAME MATCHES Darwin)


#setting the list of sources for the SERVICE. 
# TODO:
# For now, I'm going to use GLOB to pick up all the files within directory for sources. 
# The drawback of such approach is that if a new source file is added to source directory, 
# then cmake should be re-run manually. 
# 
# Alternative is to list all the files as source files explicitely. Then, when the new file
# is added to the directory, it should be also added - manually - to the CMakeLists.txt. 
# In such scenario, the CMake will pick-up the modification of the CMakeLists.txt and run 
# cmake automatically. 
#
# For now, the first option is choossen:
FILE(GLOB SERVICE_SRCS_H   "*.h")
FILE(GLOB SERVICE_SRCS  "*.cpp")

#Important for Windows: configures how the source code should be seen 
#within the source tree: 
# commented out -> headers and source file in different dirs. 
# uncommented   -> headers and sources in the same directory...
#source_group(src FILES ${SERVICE_SRCS} FILES ${SERVICE_SRCS_H} )


##link_directories(../../kernel/lib)
link_directories(${AFFINITY_PRJ}/lib)

#adding the build  - affinity dynamic library...
add_library (${SERVICE_TARGET_NAME} SHARED ${SERVICE_SRCS_H} ${SERVICE_SRCS})

#it is possible to have no source files the first time cmake is running... 
# consequently, I can not relay on compiler/linker autodetection  and have 
# to force them to be C++... 
SET_TARGET_PROPERTIES(${SERVICE_TARGET_NAME} PROPERTIES LINKER_LANGUAGE CXX)

IF(CMAKE_SYSTEM_NAME MATCHES Linux)
#since affinity library on Linux is using librt,  the line below is essential...
target_link_libraries (${SERVICE_TARGET_NAME} "rt")
ENDIF(CMAKE_SYSTEM_NAME MATCHES Linux)

IF(CMAKE_SYSTEM_NAME MATCHES Darwin)
target_link_libraries (${SERVICE_TARGET_NAME} affinity)
ENDIF(CMAKE_SYSTEM_NAME MATCHES Darwin)


IF(CMAKE_SYSTEM_NAME MATCHES Windows)

add_custom_command(
   TARGET ${SERVICE_TARGET_NAME}
   POST_BUILD
   COMMAND ${CMAKE_COMMAND}
   ARGS -E copy ${LIBRARY_OUTPUT_PATH}/${CMAKE_CFG_INTDIR}/${SERVICE_TARGET_NAME}.dll ${EXECUTABLE_OUTPUT_PATH}/${CMAKE_CFG_INTDIR}/${SERVICE_TARGET_NAME}.dll
)
ENDIF(CMAKE_SYSTEM_NAME MATCHES Windows)
