# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Produce verbose output by default.
VERBOSE = 1

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/CLionProjects/HookUtilV3

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build

# Include any dependencies generated for this target.
include CMakeFiles/pre_generate.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/pre_generate.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/pre_generate.dir/flags.make

CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.o: CMakeFiles/pre_generate.dir/flags.make
CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.o: ../../../../src/build_tools/elf/elf_utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.o   -c /root/CLionProjects/HookUtilV3/src/build_tools/elf/elf_utils.c

CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/CLionProjects/HookUtilV3/src/build_tools/elf/elf_utils.c > CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.i

CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/CLionProjects/HookUtilV3/src/build_tools/elf/elf_utils.c -o CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.s

CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.o: CMakeFiles/pre_generate.dir/flags.make
CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.o: ../../../../src/build_tools/file/file_utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.o   -c /root/CLionProjects/HookUtilV3/src/build_tools/file/file_utils.c

CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/CLionProjects/HookUtilV3/src/build_tools/file/file_utils.c > CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.i

CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/CLionProjects/HookUtilV3/src/build_tools/file/file_utils.c -o CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.s

CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.o: CMakeFiles/pre_generate.dir/flags.make
CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.o: ../../../../src/build_tools/file_check/checker.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.o   -c /root/CLionProjects/HookUtilV3/src/build_tools/file_check/checker.c

CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/CLionProjects/HookUtilV3/src/build_tools/file_check/checker.c > CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.i

CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/CLionProjects/HookUtilV3/src/build_tools/file_check/checker.c -o CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.s

CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.o: CMakeFiles/pre_generate.dir/flags.make
CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.o: ../../../../src/build_tools/json/cJSON.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.o   -c /root/CLionProjects/HookUtilV3/src/build_tools/json/cJSON.c

CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/CLionProjects/HookUtilV3/src/build_tools/json/cJSON.c > CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.i

CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/CLionProjects/HookUtilV3/src/build_tools/json/cJSON.c -o CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.s

CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.o: CMakeFiles/pre_generate.dir/flags.make
CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.o: ../../../../src/build_tools/pre_generate.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.o   -c /root/CLionProjects/HookUtilV3/src/build_tools/pre_generate.c

CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/CLionProjects/HookUtilV3/src/build_tools/pre_generate.c > CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.i

CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/CLionProjects/HookUtilV3/src/build_tools/pre_generate.c -o CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.s

# Object files for target pre_generate
pre_generate_OBJECTS = \
"CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.o" \
"CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.o" \
"CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.o" \
"CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.o" \
"CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.o"

# External object files for target pre_generate
pre_generate_EXTERNAL_OBJECTS =

pre_generate: CMakeFiles/pre_generate.dir/src/build_tools/elf/elf_utils.c.o
pre_generate: CMakeFiles/pre_generate.dir/src/build_tools/file/file_utils.c.o
pre_generate: CMakeFiles/pre_generate.dir/src/build_tools/file_check/checker.c.o
pre_generate: CMakeFiles/pre_generate.dir/src/build_tools/json/cJSON.c.o
pre_generate: CMakeFiles/pre_generate.dir/src/build_tools/pre_generate.c.o
pre_generate: CMakeFiles/pre_generate.dir/build.make
pre_generate: CMakeFiles/pre_generate.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking C executable pre_generate"
	../../../../out/clean.sh
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/pre_generate.dir/link.txt --verbose=$(VERBOSE)
	cp -f /root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build/pre_generate /root/CLionProjects/HookUtilV3/out/
	../../../../out/pre_generate /root/CLionProjects/HookUtilV3/out/config.json

# Rule to build all files generated by this target.
CMakeFiles/pre_generate.dir/build: pre_generate

.PHONY : CMakeFiles/pre_generate.dir/build

CMakeFiles/pre_generate.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/pre_generate.dir/cmake_clean.cmake
.PHONY : CMakeFiles/pre_generate.dir/clean

CMakeFiles/pre_generate.dir/depend:
	cd /root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/CLionProjects/HookUtilV3 /root/CLionProjects/HookUtilV3 /root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build /root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build /root/CLionProjects/HookUtilV3/test/test_out/autotest_32_nopie_dynamic_full/build/CMakeFiles/pre_generate.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/pre_generate.dir/depend

