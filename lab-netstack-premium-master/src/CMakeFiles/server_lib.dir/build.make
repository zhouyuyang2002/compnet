# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


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
CMAKE_SOURCE_DIR = /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master

# Include any dependencies generated for this target.
include src/CMakeFiles/server_lib.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/server_lib.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/server_lib.dir/flags.make

src/CMakeFiles/server_lib.dir/server.cpp.o: src/CMakeFiles/server_lib.dir/flags.make
src/CMakeFiles/server_lib.dir/server.cpp.o: src/server.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/CMakeFiles/server_lib.dir/server.cpp.o"
	cd /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/server_lib.dir/server.cpp.o -c /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src/server.cpp

src/CMakeFiles/server_lib.dir/server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/server_lib.dir/server.cpp.i"
	cd /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src/server.cpp > CMakeFiles/server_lib.dir/server.cpp.i

src/CMakeFiles/server_lib.dir/server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/server_lib.dir/server.cpp.s"
	cd /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src/server.cpp -o CMakeFiles/server_lib.dir/server.cpp.s

src/CMakeFiles/server_lib.dir/server.cpp.o.requires:

.PHONY : src/CMakeFiles/server_lib.dir/server.cpp.o.requires

src/CMakeFiles/server_lib.dir/server.cpp.o.provides: src/CMakeFiles/server_lib.dir/server.cpp.o.requires
	$(MAKE) -f src/CMakeFiles/server_lib.dir/build.make src/CMakeFiles/server_lib.dir/server.cpp.o.provides.build
.PHONY : src/CMakeFiles/server_lib.dir/server.cpp.o.provides

src/CMakeFiles/server_lib.dir/server.cpp.o.provides.build: src/CMakeFiles/server_lib.dir/server.cpp.o


# Object files for target server_lib
server_lib_OBJECTS = \
"CMakeFiles/server_lib.dir/server.cpp.o"

# External object files for target server_lib
server_lib_EXTERNAL_OBJECTS =

src/libserver_lib.a: src/CMakeFiles/server_lib.dir/server.cpp.o
src/libserver_lib.a: src/CMakeFiles/server_lib.dir/build.make
src/libserver_lib.a: src/CMakeFiles/server_lib.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libserver_lib.a"
	cd /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src && $(CMAKE_COMMAND) -P CMakeFiles/server_lib.dir/cmake_clean_target.cmake
	cd /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/server_lib.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/server_lib.dir/build: src/libserver_lib.a

.PHONY : src/CMakeFiles/server_lib.dir/build

src/CMakeFiles/server_lib.dir/requires: src/CMakeFiles/server_lib.dir/server.cpp.o.requires

.PHONY : src/CMakeFiles/server_lib.dir/requires

src/CMakeFiles/server_lib.dir/clean:
	cd /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src && $(CMAKE_COMMAND) -P CMakeFiles/server_lib.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/server_lib.dir/clean

src/CMakeFiles/server_lib.dir/depend:
	cd /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src /home/zhouyuyang/Desktop/NetLab/lab-netstack-premium-master/src/CMakeFiles/server_lib.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/server_lib.dir/depend

