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
include CMakeFiles/loader_stage_two.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/loader_stage_two.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/loader_stage_two.dir/flags.make

CMakeFiles/loader_stage_two.dir/loader_stage_two.c.o: CMakeFiles/loader_stage_two.dir/flags.make
CMakeFiles/loader_stage_two.dir/loader_stage_two.c.o: ../loader_stage_two.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/loader_stage_two.dir/loader_stage_two.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/loader_stage_two.dir/loader_stage_two.c.o   -c /root/CLionProjects/HookUtilV3/loader_stage_two.c

CMakeFiles/loader_stage_two.dir/loader_stage_two.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/loader_stage_two.dir/loader_stage_two.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/CLionProjects/HookUtilV3/loader_stage_two.c > CMakeFiles/loader_stage_two.dir/loader_stage_two.c.i

CMakeFiles/loader_stage_two.dir/loader_stage_two.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/loader_stage_two.dir/loader_stage_two.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/CLionProjects/HookUtilV3/loader_stage_two.c -o CMakeFiles/loader_stage_two.dir/loader_stage_two.c.s

# Object files for target loader_stage_two
loader_stage_two_OBJECTS = \
"CMakeFiles/loader_stage_two.dir/loader_stage_two.c.o"

# External object files for target loader_stage_two
loader_stage_two_EXTERNAL_OBJECTS =

libloader_stage_two.so: CMakeFiles/loader_stage_two.dir/loader_stage_two.c.o
libloader_stage_two.so: CMakeFiles/loader_stage_two.dir/build.make
libloader_stage_two.so: CMakeFiles/loader_stage_two.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C shared library libloader_stage_two.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/loader_stage_two.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/loader_stage_two.dir/build: libloader_stage_two.so

.PHONY : CMakeFiles/loader_stage_two.dir/build

CMakeFiles/loader_stage_two.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/loader_stage_two.dir/cmake_clean.cmake
.PHONY : CMakeFiles/loader_stage_two.dir/clean

CMakeFiles/loader_stage_two.dir/depend:
	cd /root/CLionProjects/HookUtilV3/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/CLionProjects/HookUtilV3 /root/CLionProjects/HookUtilV3 /root/CLionProjects/HookUtilV3/cmake-build-debug /root/CLionProjects/HookUtilV3/cmake-build-debug /root/CLionProjects/HookUtilV3/cmake-build-debug/CMakeFiles/loader_stage_two.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/loader_stage_two.dir/depend

