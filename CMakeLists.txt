cmake_minimum_required(VERSION 3.10)
project(HookUtilV3 C ASM)
set(CMAKE_C_STANDARD 11)

include_directories(./src/)

set(CMAKE_VERBOSE_MAKEFILE ON)
#set(CMAKE_BUILD_TYPE Release)
#set(CMAKE_BUILD_TYPE Debug)
set(IS_V5 true)

if (NOT DEFINED TARGET_ARCH)
set(TARGET_ARCH X86_64)
endif()

MESSAGE("TARGET_ARCH IS: ${TARGET_ARCH}")

FILE(GLOB STAGE_TWO src/stage_two/*.c)
FILE(GLOB STAGE_THREE_NORMAL src/stage_three/normal_loader.c)
FILE(GLOB STAGE_THREE_SANDBOX src/stage_three/sandbox_loader.c)

FILE(GLOB TEST_SYSCALL tools/syscall_test.c)

FILE(GLOB GENERATE_BUILD_TOOLS src/build_tools/generate.c src/build_tools/elf/*.c src/build_tools/file/*.c src/build_tools/file_check/*.c src/build_tools/json/*.c)
FILE(GLOB PRE_GENERATE_TOOLS src/build_tools/pre_generate.c src/build_tools/elf/*.c src/build_tools/file/*.c src/build_tools/file_check/*.c src/build_tools/json/*.c)
FILE(GLOB DATAFILE_GENERATE_TOOLS src/build_tools/datafile_generate.c src/build_tools/elf/*.c src/build_tools/file/*.c src/build_tools/file_check/*.c src/build_tools/json/*.c)
FILE(GLOB STAGE_ONE_REGENERATE_TOOLS src/build_tools/stage_one_pre_generate.c src/build_tools/elf/*.c src/build_tools/file/*.c src/build_tools/file_check/*.c src/build_tools/json/*.c)
set(TARGET_DIR "out")

set(STAGE_LINK_FLAG "-static-pie")
if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(STAGE_ONE_COMPILE_FLAG "-fno-stack-protector  -fPIE -fcf-protection=none -fno-tree-scev-cprop")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release")
        set(STAGE_ONE_COMPILE_FLAG "-fno-stack-protector  -fPIE -fcf-protection=none -fno-tree-scev-cprop -fomit-frame-pointer")
endif()
set(STAGE_TWO_COMPILE_FLAG "-fno-stack-protector -fPIE -fcf-protection=none -fno-tree-scev-cprop")
set(STAGE_THREE_NORMAL_COMPILE_FLAG "-fno-stack-protector  -fPIE -fcf-protection=none -fno-tree-scev-cprop")
set(STAGE_THREE_SANDBOX_COMPILE_FLAG "-fno-stack-protector -fPIE -fcf-protection=none -fno-tree-scev-cprop")
set(TEST_SYSCALL_COMPILE_FLAG "-fno-stack-protector -fPIE -fcf-protection=none -fno-tree-scev-cprop")

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
    set(QEMU "")
    if(${IS_V5} STREQUAL "true")
        FILE(GLOB STAGE_ONE src/stage_one/*.c)
    else()
        FILE(GLOB STAGE_ONE src/stage_one/*.c src/arch/amd64/loader.s)
    endif()
elseif(${TARGET_ARCH} STREQUAL "X86_64")
    set(TARGET_ARCH_COMPILE_FLAG "-m64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 ")
    set(TARGET_ARCH_LINKER_FLAG  "-m64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 ")
    set(QEMU "")
    if(${IS_V5} STREQUAL "true")
        FILE(GLOB STAGE_ONE src/stage_one/*.c)
    else()
        FILE(GLOB STAGE_ONE src/stage_one/*.c src/arch/amd64/loader.s)
    endif()
elseif(${TARGET_ARCH} STREQUAL "ARM")
    set(CMAKE_SYSTEM_NAME linux)
    set(TOOLCHAIN_PATH gcc-arm-linux-gnueabi)
    set(CMAKE_C_COMPILER arm-linux-gnueabi-gcc)
    set(CMAKE_CXX_COMPILER arm-linux-gnueabi-g++)
    set(TARGET_ARCH_COMPILE_FLAG " -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -save-temps")
    set(TARGET_ARCH_LINKER_FLAG  " -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 ")
    set(QEMU "qemu-arm")
    if(${IS_V5} STREQUAL "true")
        FILE(GLOB STAGE_ONE src/stage_one/*.c)
    else()
        FILE(GLOB STAGE_ONE src/stage_one/*.c src/arch/amd64/loader.s)
    endif()
else()
    message( SEND_ERROR "TARGET_ARCH Failed" )
endif()

set(TOOLS_LINK_FLAGS "-static -L${CMAKE_SOURCE_DIR}/3rd/capstone/lib/${TARGET_ARCH}")
set(TOOLS_COMPILE_FLAGS "-I${CMAKE_SOURCE_DIR}/3rd/capstone/include")

add_executable(pre_generate ${PRE_GENERATE_TOOLS})
target_link_libraries(pre_generate m)
set_target_properties(pre_generate PROPERTIES COMPILE_FLAGS "${PATCH_DEBUG} ${TARGET_ARCH_COMPILE_FLAG} ${TOOLS_COMPILE_FLAGS}" LINK_FLAGS  "${TARGET_ARCH_LINKER_FLAG} ${TOOLS_LINK_FLAGS}")
add_custom_command(TARGET pre_generate PRE_BUILD
                    COMMAND ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/clean.sh
        )
add_custom_command(TARGET pre_generate POST_BUILD
                    COMMAND cp -f  "${CMAKE_BINARY_DIR}/pre_generate" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools"
                    COMMAND ${QEMU} ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/pre_generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/normal_config.json" "normal"
                    COMMAND ${QEMU} ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/pre_generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/sandbox_config.json" "sandbox"
        )

add_executable(stage_two_normal ${STAGE_TWO})
set_target_properties(stage_two_normal PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_TWO_COMPILE_FLAG}" LINK_FLAGS  "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_two_normal POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_two_normal" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/normal/stage_two"
        )
target_include_directories(stage_two_normal PRIVATE src/auto_generate/normal)
add_dependencies(stage_two_normal pre_generate)


add_executable(stage_two_sandbox ${STAGE_TWO})
set_target_properties(stage_two_sandbox PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_TWO_COMPILE_FLAG}" LINK_FLAGS  "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_two_sandbox POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_two_sandbox" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/sandbox/stage_two"
        )
target_include_directories(stage_two_sandbox PRIVATE src/auto_generate/sandbox)
add_dependencies(stage_two_sandbox pre_generate)


add_executable(stage_three_normal ${STAGE_THREE_NORMAL})
set_target_properties(stage_three_normal PROPERTIES COMPILE_FLAGS  "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_THREE_NORMAL_COMPILE_FLAG} " LINK_FLAGS "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_three_normal POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_three_normal" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/normal/stage_three"
        )
target_include_directories(stage_three_normal PRIVATE src/auto_generate/normal)
add_dependencies(stage_three_normal pre_generate)

add_executable(stage_three_sandbox  ${STAGE_THREE_SANDBOX})
set_target_properties(stage_three_sandbox PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_THREE_SANDBOX_COMPILE_FLAG}" LINK_FLAGS "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_three_sandbox POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_three_sandbox" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/sandbox/stage_three"
        )
target_include_directories(stage_three_sandbox PRIVATE src/auto_generate/sandbox)
add_dependencies(stage_three_sandbox pre_generate)


add_executable(datafile_generate ${DATAFILE_GENERATE_TOOLS})
target_link_libraries(datafile_generate m)
set_target_properties(datafile_generate PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${TOOLS_COMPILE_FLAGS}" LINK_FLAGS "${TARGET_ARCH_LINKER_FLAG} ${TOOLS_LINK_FLAGS}")
add_custom_command(TARGET datafile_generate POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/datafile_generate" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/"
        COMMAND ${QEMU} ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/datafile_generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/normal_config.json" "normal"
        COMMAND ${QEMU} ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/datafile_generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/sandbox_config.json" "sandbox"
        )
add_dependencies(datafile_generate stage_two_normal stage_two_sandbox stage_three_normal stage_three_sandbox)


add_executable(stage_one_pre_generate ${STAGE_ONE_REGENERATE_TOOLS})
target_link_libraries(stage_one_pre_generate m capstone)
set_target_properties(stage_one_pre_generate PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${TOOLS_COMPILE_FLAGS}" LINK_FLAGS "${TARGET_ARCH_LINKER_FLAG} ${TOOLS_LINK_FLAGS}")
add_custom_command(TARGET stage_one_pre_generate POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_one_pre_generate" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/"
        COMMAND ${QEMU} ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/stage_one_pre_generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/normal_config.json" "normal"
        COMMAND ${QEMU} ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/stage_one_pre_generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/sandbox_config.json" "sandbox"
        )


add_dependencies(stage_one_pre_generate datafile_generate)

add_executable(stage_one_normal ${STAGE_ONE})
# set_target_properties(stage_one_normal PROPERTIES LINK_DEPENDS "${CMAKE_SOURCE_DIR}/src/stage_one/loader.ld")
set_target_properties(stage_one_normal PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_ONE_COMPILE_FLAG}  -DSTAGE_ONE_NORMAL=1" LINK_FLAGS "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_one_normal POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_one_normal" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/normal/stage_one"
        )
target_include_directories(stage_one_normal PRIVATE src/auto_generate/normal)
add_dependencies(stage_one_normal stage_one_pre_generate)

add_executable(stage_one_sandbox ${STAGE_ONE})
set_target_properties(stage_one_sandbox PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${STAGE_ONE_COMPILE_FLAG}  -DSTAGE_ONE_SANDBOX=1" LINK_FLAGS "${STAGE_LINK_FLAG} ${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_custom_command(TARGET stage_one_sandbox POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_one_sandbox" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/sandbox/stage_one"
        )
target_include_directories(stage_one_sandbox PRIVATE src/auto_generate/sandbox)
add_dependencies(stage_one_sandbox stage_one_pre_generate)

add_executable(generate ${GENERATE_BUILD_TOOLS})
target_link_libraries(generate m capstone)
set_target_properties(generate PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${TOOLS_COMPILE_FLAGS}" LINK_FLAGS "${TARGET_ARCH_LINKER_FLAG} ${TOOLS_LINK_FLAGS}")
add_custom_command(TARGET generate POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/generate" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/"
        COMMAND ${QEMU} ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/normal_config.json" "normal"
        COMMAND ${QEMU} ${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/generate "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/sandbox_config.json" "sandbox"
        )
add_dependencies(generate stage_one_normal stage_one_sandbox)

add_executable(stage_share_memory_server tools/stage_share_memory_server.c)
add_custom_command(TARGET stage_share_memory_server POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_share_memory_server" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/stage_server/"
        )
add_dependencies(stage_share_memory_server generate)

add_executable(stage_socket_server tools/stage_socket_server.c)
add_custom_command(TARGET stage_socket_server POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/stage_socket_server" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/stage_server/"
        )
target_link_libraries(stage_socket_server pthread)
add_dependencies(stage_socket_server generate)

add_executable(test_syscall ${TEST_SYSCALL})
target_include_directories(test_syscall PRIVATE src/auto_generate/normal)
set_target_properties(test_syscall PROPERTIES COMPILE_FLAGS "${TARGET_ARCH_COMPILE_FLAG} ${TEST_SYSCALL_COMPILE_FLAG}" LINK_FLAGS  "${TARGET_ARCH_LINKER_FLAG} -nostartfiles -nodefaultlibs -nostdlib")
add_dependencies(test_syscall generate)
add_custom_command(TARGET test_syscall POST_BUILD
        COMMAND cp -f  "${CMAKE_BINARY_DIR}/test_syscall" "${CMAKE_SOURCE_DIR}/${TARGET_DIR}/tools/"
        )
