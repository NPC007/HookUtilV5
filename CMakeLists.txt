cmake_minimum_required(VERSION 3.10)
project(HookUtilV3 C ASM)
set(CMAKE_C_STANDARD 11)

include_directories(./src/)

set(CMAKE_VERBOSE_MAKEFILE ON)
#set(CMAKE_BUILD_TYPE Release)
set(CMAKE_BUILD_TYPE Debug)
set(TARGET_ARCH X86)


FILE(GLOB STAGE_TWO src/stage_two/*.c)
FILE(GLOB STAGE_THREE_NORMAL src/stage_three/normal_loader.c)
FILE(GLOB STAGE_THREE_SANDBOX src/stage_three/sandbox_loader.c)

FILE(GLOB GENERATE_BUILD_TOOLS src/build_tools/generate.c src/build_tools/elf/*.c src/build_tools/file/*.c src/build_tools/file_check/*.c src/build_tools/json/*.c)
FILE(GLOB PRE_GENERATE_TOOLS src/build_tools/pre_generate.c src/build_tools/elf/*.c src/build_tools/file/*.c src/build_tools/file_check/*.c src/build_tools/json/*.c)
FILE(GLOB DATAFILE_GENERATE_TOOLS src/build_tools/datafile_generate.c src/build_tools/elf/*.c src/build_tools/file/*.c src/build_tools/file_check/*.c src/build_tools/json/*.c)
FILE(GLOB STAGE_ONE_REGENERATE_TOOLS src/build_tools/stage_one_pre_generate.c src/build_tools/elf/*.c src/build_tools/file/*.c src/build_tools/file_check/*.c src/build_tools/json/*.c)
set(TARGET_DIR "out")


set(STAGE_LINK_FLAG "-static-pie")
set(STAGE_COMPILE_FLAG "-fno-stack-protector -O1 -fPIE -fcf-protection=none -fno-tree-scev-cprop")
if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(PATCH_DEBUG "-DPATCH_DEBUG_CONFIG=1")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(PATCH_DEBUG "-DPATCH_DEBUG_CONFIG=0")
else()
    message( SEND_ERROR "TARGET_ARCH Failed" )
endif()

if(${TARGET_ARCH} STREQUAL "X86")
    set(TARGET_ARCH_COMPILE_FLAG "-m32 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 ")
    set(TARGET_ARCH_LINKER_FLAG  "-m32 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 ")
    FILE(GLOB STAGE_ONE src/stage_one/*.c src/arch/i386/loader.s)
elseif(${TARGET_ARCH} STREQUAL "X86_64")
    set(TARGET_ARCH_COMPILE_FLAG "-m64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 ")
    set(TARGET_ARCH_LINKER_FLAG  "-m64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 ")
    FILE(GLOB STAGE_ONE src/stage_one/*.c src/arch/amd64/loader.s)
else()
    message( SEND_ERROR "TARGET_ARCH Failed" )
endif()



add_executable(pre_generate ${PRE_GENERATE_TOOLS})
target_link_libraries(pre_generate m)
set_target_properties(pre_generate PROPERTIES COMPILE_FLAGS "${PATCH_DEBUG} ${TARGET_ARCH_COMPILE_FLAG}" LINK_FLAGS  "${TARGET_ARCH_LINKER_FLAG}")
add_custom_command(TARGET pre_generate PRE_BUILD
                    COMMAND ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/clean.sh
        )
add_custom_command(TARGET pre_generate POST_BUILD
                    COMMAND cp -f  "${CMAKE_BINARY_DIR}/pre_generate" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/"
                    COMMAND ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/pre_generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/config.json"
        )

add_executable(stage_two ${STAGE_TWO})
set_target_properties(stage_two PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_COMPILE_FLAG}" LINK_FLAGS  "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_two POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_two" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/"
        )
add_dependencies(stage_two pre_generate)

add_executable(stage_three_normal ${STAGE_THREE_NORMAL})
set_target_properties(stage_three_normal PROPERTIES COMPILE_FLAGS  "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_COMPILE_FLAG} " LINK_FLAGS "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_three_normal POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_three_normal" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/"
        )
add_dependencies(stage_three_normal pre_generate)

add_executable(stage_three_sandbox  ${STAGE_THREE_SANDBOX})
set_target_properties(stage_three_sandbox PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_COMPILE_FLAG}" LINK_FLAGS "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_three_sandbox POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_three_sandbox" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/"
        )
add_dependencies(stage_three_sandbox pre_generate)

add_executable(datafile_generate ${DATAFILE_GENERATE_TOOLS})
target_link_libraries(datafile_generate m)
set_target_properties(datafile_generate PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG}" LINK_FLAGS "${TARGET_ARCH_LINKER_FLAG}")
add_custom_command(TARGET datafile_generate POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/datafile_generate" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/"
        COMMAND ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/datafile_generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/config.json"
        )
add_dependencies(datafile_generate stage_two stage_three_normal stage_three_sandbox)

add_executable(stage_one_pre_generate ${STAGE_ONE_REGENERATE_TOOLS})
target_link_libraries(stage_one_pre_generate m capstone)
set_target_properties(stage_one_pre_generate PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG}" LINK_FLAGS "${TARGET_ARCH_LINKER_FLAG}")
add_custom_command(TARGET stage_one_pre_generate POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_one_pre_generate" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/"
        COMMAND ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/stage_one_pre_generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/config.json"
        )
add_dependencies(stage_one_pre_generate datafile_generate)

add_executable(stage_one_normal ${STAGE_ONE})
set_target_properties(stage_one_normal PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_COMPILE_FLAG}  -DSTAGE_ONE_NORMAL=1" LINK_FLAGS "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_one_normal POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_one_normal" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/"
        )
add_dependencies(stage_one_normal stage_one_pre_generate)

add_executable(stage_one_sandbox ${STAGE_ONE})
set_target_properties(stage_one_sandbox PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_COMPILE_FLAG}  -DSTAGE_ONE_SANDBOX=1" LINK_FLAGS "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_one_sandbox POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_one_sandbox" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/"
        )
add_dependencies(stage_one_sandbox stage_one_pre_generate)

add_executable(generate ${GENERATE_BUILD_TOOLS})
target_link_libraries(generate m capstone)
set_target_properties(generate PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG}" LINK_FLAGS "${TARGET_ARCH_LINKER_FLAG}")
add_custom_command(TARGET generate POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/generate" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/"
        COMMAND ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/config.json"
        )
add_dependencies(generate stage_one_normal stage_one_sandbox)



#add_library(tiny_loader_shell_i386 SHARED strict_mode/tiny_loader/arch/i386/tiny_loader_shell.c)
#set_target_properties(tiny_loader_shell_i386 PROPERTIES COMPILE_FLAGS "-m32 -O0 -fno-stack-protector" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib -m32")
#add_executable(tiny_loader_shell_i386_exe strict_mode/tiny_loader/arch/i386/tiny_loader_shell.c)
#set_target_properties(tiny_loader_shell_i386_exe PROPERTIES COMPILE_FLAGS "-m32 -O0 -fno-stack-protector" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib -m32")

#add_library(tiny_loader_shell_amd64 SHARED strict_mode/tiny_loader/arch/amd64/tiny_loader_shell.c)
#set_target_properties(tiny_loader_shell_amd64 PROPERTIES COMPILE_FLAGS "-m64 -O0 -fno-stack-protector" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib -m64")
#add_executable(tiny_loader_shell_amd64_exe strict_mode/tiny_loader/arch/amd64/tiny_loader_shell.c)
#set_target_properties(tiny_loader_shell_amd64_exe PROPERTIES COMPILE_FLAGS "-m64 -O0 -fno-stack-protector" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib -m64")


#add_library(tiny_loader_filewriter_i386 SHARED strict_mode/tiny_loader/arch/i386/tiny_loader_filewriter.c)
#set_target_properties(tiny_loader_filewriter_i386 PROPERTIES COMPILE_FLAGS "-m32 -O0 -fno-stack-protector" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib -m32")
#add_executable(tiny_loader_filewriter_i386_exe strict_mode/tiny_loader/arch/i386/tiny_loader_filewriter.c)
#set_target_properties(tiny_loader_filewriter_i386_exe PROPERTIES COMPILE_FLAGS "-m32 -O0 -fno-stack-protector" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib -m32")

#add_library(tiny_loader_filewriter_amd64 SHARED strict_mode/tiny_loader/arch/amd64/tiny_loader_filewriter.c)
#set_target_properties(tiny_loader_filewriter_amd64 PROPERTIES COMPILE_FLAGS "-m64 -O0 -fno-stack-protector" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib -m64")
#add_executable(tiny_loader_filewriter_amd64_exe strict_mode/tiny_loader/arch/amd64/tiny_loader_filewriter.c)
#set_target_properties(tiny_loader_filewriter_amd64_exe PROPERTIES COMPILE_FLAGS "-m64 -O0 -fno-stack-protector" LINK_FLAGS "-nostartfiles -nodefaultlibs -nostdlib -m64")