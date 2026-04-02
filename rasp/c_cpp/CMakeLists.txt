cmake_minimum_required(VERSION 3.16)
project(cyberarmor_rasp C)

set(CMAKE_C_STANDARD 11)

add_library(cyberarmor_rasp SHARED src/cyberarmor_rasp.c)
target_include_directories(cyberarmor_rasp PUBLIC include)
target_link_libraries(cyberarmor_rasp PRIVATE dl pthread)

# Install
install(TARGETS cyberarmor_rasp LIBRARY DESTINATION lib)
install(FILES include/cyberarmor_rasp.h DESTINATION include)
