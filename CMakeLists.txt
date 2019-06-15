cmake_minimum_required(VERSION 3.10)
project(HookUtilV3 C)

set(CMAKE_C_STANDARD 11)

add_executable(generate64 generate.c cJSON.c cJSON.h)
target_link_libraries(generate64 m)
set_target_properties(generate64 PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")
add_executable(generate32 generate.c cJSON.c cJSON.h)
target_link_libraries(generate32 m)
set_target_properties(generate32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")


add_executable(generate_base64 generate_base.c cJSON.c cJSON.h)
target_link_libraries(generate_base64 m)
set_target_properties(generate_base64 PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")
add_executable(generate_base32 generate_base.c cJSON.c cJSON.h)
target_link_libraries(generate_base32 m)
set_target_properties(generate_base32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

add_library(loader_stage_one SHARED loader_stage_one.c)
add_library(loader_stage_two SHARED loader_stage_two.c)
add_library(loader_stage_three SHARED loader_stage_three.c)
add_library(loader_stage_three_base SHARED loader_stage_three_base.c)