# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

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
CMAKE_COMMAND = /opt/clion-2019.3.2/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /opt/clion-2019.3.2/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/CLionProjects/HookUtilV3

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/CLionProjects/HookUtilV3/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/stage_three.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/stage_three.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/stage_three.dir/flags.make

CMakeFiles/stage_three.dir/src/stage_three/loader.c.o: CMakeFiles/stage_three.dir/flags.make
CMakeFiles/stage_three.dir/src/stage_three/loader.c.o: ../src/stage_three/loader.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/stage_three.dir/src/stage_three/loader.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/stage_three.dir/src/stage_three/loader.c.o   -c /root/CLionProjects/HookUtilV3/src/stage_three/loader.c

CMakeFiles/stage_three.dir/src/stage_three/loader.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/stage_three.dir/src/stage_three/loader.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/CLionProjects/HookUtilV3/src/stage_three/loader.c > CMakeFiles/stage_three.dir/src/stage_three/loader.c.i

CMakeFiles/stage_three.dir/src/stage_three/loader.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/stage_three.dir/src/stage_three/loader.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/CLionProjects/HookUtilV3/src/stage_three/loader.c -o CMakeFiles/stage_three.dir/src/stage_three/loader.c.s

# Object files for target stage_three
stage_three_OBJECTS = \
"CMakeFiles/stage_three.dir/src/stage_three/loader.c.o"

# External object files for target stage_three
stage_three_EXTERNAL_OBJECTS =

stage_three: CMakeFiles/stage_three.dir/src/stage_three/loader.c.o
stage_three: CMakeFiles/stage_three.dir/build.make
stage_three: CMakeFiles/stage_three.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable stage_three"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/stage_three.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/stage_three.dir/build: stage_three

.PHONY : CMakeFiles/stage_three.dir/build

CMakeFiles/stage_three.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/stage_three.dir/cmake_clean.cmake
.PHONY : CMakeFiles/stage_three.dir/clean

CMakeFiles/stage_three.dir/depend:
	cd /root/CLionProjects/HookUtilV3/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/CLionProjects/HookUtilV3 /root/CLionProjects/HookUtilV3 /root/CLionProjects/HookUtilV3/cmake-build-debug /root/CLionProjects/HookUtilV3/cmake-build-debug /root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles/stage_three.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/stage_three.dir/depend

