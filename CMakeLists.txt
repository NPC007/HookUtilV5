cmake_minimum_required(VERSION 3.10)
project(HookUtilV3 C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_BUILD_TYPE Debug)

add_executable(generate_x32 generate.c cJSON.c cJSON.h)
target_link_libraries(generate_x32 m capstone)
set_target_properties(generate_x32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

add_executable(generate_x64 generate.c cJSON.c cJSON.h)
target_link_libraries(generate_x64 m capstone)
set_target_properties(generate_x64 PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")

add_library(loader_stage_one SHARED loader_stage_one.c)
set_target_properties(loader_stage_one PROPERTIES COMPILE_FLAGS "-O0" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib")

add_library(loader_stage_two SHARED loader_stage_two.c)
set_target_properties(loader_stage_two PROPERTIES COMPILE_FLAGS "-O0" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib")

add_library(loader_stage_three SHARED loader_stage_three.c)
set_target_properties(loader_stage_three PROPERTIES COMPILE_FLAGS "-O0" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib")

