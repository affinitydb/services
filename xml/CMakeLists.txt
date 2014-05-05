cmake_minimum_required(VERSION 2.8)
message("XML parsing/rendering service for affinity")
project(xmlservice)
SET(XMLSERVICE_TARGET_NAME "XML")
add_subdirectory(src)
include(ExternalProject)
ExternalProject_Add(
	libexpat
	DOWNLOAD_COMMAND ""
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/expat-2.1.0
	CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/expat-2.1.0/configure --prefix=${CMAKE_CURRENT_SOURCE_DIR}
	BUILD_COMMAND ${MAKE}
	BUILD_IN_SOURCE 1)
