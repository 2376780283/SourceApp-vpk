cmake_minimum_required(VERSION 3.10)
project(vpk_cli)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(vpk_cli main.cpp vpk.cpp)
