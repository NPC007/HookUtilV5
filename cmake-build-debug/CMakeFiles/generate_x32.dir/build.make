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
include CMakeFiles/generate_x32.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/generate_x32.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/generate_x32.dir/flags.make

CMakeFiles/generate_x32.dir/generate.c.o: CMakeFiles/generate_x32.dir/flags.make
CMakeFiles/generate_x32.dir/generate.c.o: ../generate.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/generate_x32.dir/generate.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/generate_x32.dir/generate.c.o   -c /root/CLionProjects/HookUtilV3/generate.c

CMakeFiles/generate_x32.dir/generate.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/generate_x32.dir/generate.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/CLionProjects/HookUtilV3/generate.c > CMakeFiles/generate_x32.dir/generate.c.i

CMakeFiles/generate_x32.dir/generate.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/generate_x32.dir/generate.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/CLionProjects/HookUtilV3/generate.c -o CMakeFiles/generate_x32.dir/generate.c.s

CMakeFiles/generate_x32.dir/cJSON.c.o: CMakeFiles/generate_x32.dir/flags.make
CMakeFiles/generate_x32.dir/cJSON.c.o: ../cJSON.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/generate_x32.dir/cJSON.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/generate_x32.dir/cJSON.c.o   -c /root/CLionProjects/HookUtilV3/cJSON.c

CMakeFiles/generate_x32.dir/cJSON.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/generate_x32.dir/cJSON.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/CLionProjects/HookUtilV3/cJSON.c > CMakeFiles/generate_x32.dir/cJSON.c.i

CMakeFiles/generate_x32.dir/cJSON.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/generate_x32.dir/cJSON.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/CLionProjects/HookUtilV3/cJSON.c -o CMakeFiles/generate_x32.dir/cJSON.c.s

# Object files for target generate_x32
generate_x32_OBJECTS = \
"CMakeFiles/generate_x32.dir/generate.c.o" \
"CMakeFiles/generate_x32.dir/cJSON.c.o"

# External object files for target generate_x32
generate_x32_EXTERNAL_OBJECTS =

generate_x32: CMakeFiles/generate_x32.dir/generate.c.o
generate_x32: CMakeFiles/generate_x32.dir/cJSON.c.o
generate_x32: CMakeFiles/generate_x32.dir/build.make
generate_x32: CMakeFiles/generate_x32.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable generate_x32"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/generate_x32.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/generate_x32.dir/build: generate_x32

.PHONY : CMakeFiles/generate_x32.dir/build

CMakeFiles/generate_x32.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/generate_x32.dir/cmake_clean.cmake
.PHONY : CMakeFiles/generate_x32.dir/clean

CMakeFiles/generate_x32.dir/depend:
	cd /root/CLionProjects/HookUtilV3/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/CLionProjects/HookUtilV3 /root/CLionProjects/HookUtilV3 /root/CLionProjects/HookUtilV3/cmake-build-debug /root/CLionProjects/HookUtilV3/cmake-build-debug /root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles/generate_x32.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/generate_x32.dir/depend

