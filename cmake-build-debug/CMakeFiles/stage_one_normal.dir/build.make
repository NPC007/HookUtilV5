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
CMAKE_COMMAND = /home/runshine/clion-2020.1.1/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/runshine/clion-2020.1.1/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/runshine/HookUtilV3

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/runshine/HookUtilV3/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/stage_one_normal.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/stage_one_normal.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/stage_one_normal.dir/flags.make

CMakeFiles/stage_one_normal.dir/src/arch/i386/loader.s.o: CMakeFiles/stage_one_normal.dir/flags.make
CMakeFiles/stage_one_normal.dir/src/arch/i386/loader.s.o: ../src/arch/i386/loader.s
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/runshine/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building ASM object CMakeFiles/stage_one_normal.dir/src/arch/i386/loader.s.o"
	/usr/bin/cc $(ASM_DEFINES) $(ASM_INCLUDES) $(ASM_FLAGS) -o CMakeFiles/stage_one_normal.dir/src/arch/i386/loader.s.o -c /home/runshine/HookUtilV3/src/arch/i386/loader.s

CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.o: CMakeFiles/stage_one_normal.dir/flags.make
CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.o: ../src/stage_one/loader.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/runshine/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.o   -c /home/runshine/HookUtilV3/src/stage_one/loader.c

CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/runshine/HookUtilV3/src/stage_one/loader.c > CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.i

CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/runshine/HookUtilV3/src/stage_one/loader.c -o CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.s

# Object files for target stage_one_normal
stage_one_normal_OBJECTS = \
"CMakeFiles/stage_one_normal.dir/src/arch/i386/loader.s.o" \
"CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.o"

# External object files for target stage_one_normal
stage_one_normal_EXTERNAL_OBJECTS =

stage_one_normal: CMakeFiles/stage_one_normal.dir/src/arch/i386/loader.s.o
stage_one_normal: CMakeFiles/stage_one_normal.dir/src/stage_one/loader.c.o
stage_one_normal: CMakeFiles/stage_one_normal.dir/build.make
stage_one_normal: CMakeFiles/stage_one_normal.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/runshine/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable stage_one_normal"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/stage_one_normal.dir/link.txt --verbose=$(VERBOSE)
	cp -f /home/runshine/HookUtilV3/cmake-build-debug/stage_one_normal /home/runshine/HookUtilV3/out/

# Rule to build all files generated by this target.
CMakeFiles/stage_one_normal.dir/build: stage_one_normal

.PHONY : CMakeFiles/stage_one_normal.dir/build

CMakeFiles/stage_one_normal.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/stage_one_normal.dir/cmake_clean.cmake
.PHONY : CMakeFiles/stage_one_normal.dir/clean

CMakeFiles/stage_one_normal.dir/depend:
	cd /home/runshine/HookUtilV3/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/runshine/HookUtilV3 /home/runshine/HookUtilV3 /home/runshine/HookUtilV3/cmake-build-debug /home/runshine/HookUtilV3/cmake-build-debug /home/runshine/HookUtilV3/cmake-build-debug/CMakeFiles/stage_one_normal.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/stage_one_normal.dir/depend

