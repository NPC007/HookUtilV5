cmake_minimum_required(VERSION 3.10)
project(HookUtilV3 C)

set(CMAKE_C_STANDARD 11)

add_library(hook SHARED hook.c)
add_executable(generate generate.c)
add_library(loader SHARED loader.c)
add_library(loader_stage_two SHARED loader_stage_two.c)