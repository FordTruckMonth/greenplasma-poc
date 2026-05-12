cmake_minimum_required(VERSION 3.16)
project(GreenPlasma)

add_executable(GreenPlasma GreenPlasma.cpp)
target_link_libraries(GreenPlasma ntdll advapi32 shell32)
set_property(TARGET GreenPlasma PROPERTY CXX_STANDARD 17)
