cmake_minimum_required(VERSION 3.10)
project(HookUtilV3 C)

set(CMAKE_C_STANDARD 11)

add_executable(generate generate.c cJSON.c cJSON.h)
target_link_libraries(generate m)


add_library(loader_stage_one SHARED loader_stage_one.c)
add_library(loader_stage_two SHARED loader_stage_two.c)
add_library(loader_stage_three SHARED loader_stage_three.c)