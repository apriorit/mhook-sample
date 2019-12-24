cmake_minimum_required( VERSION 3.4.0 )
project(mhook-sample CXX)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set_property(GLOBAL PROPERTY PREDEFINED_TARGETS_FOLDER "CMake")

add_definitions(-DUNICODE -D_UNICODE)

add_subdirectory(3rd-party/mhook)

set (CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

add_library(${PROJECT_NAME} 
	SHARED
	src/targetver.h
	src/pch.h
	src/pch.cpp
	src/main.cpp
	)

set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "/Yupch.h")
set_source_files_properties(src/pch.cpp PROPERTIES COMPILE_FLAGS "/Ycpch.h")

target_link_libraries(${PROJECT_NAME} mhook)
