cmake_minimum_required(VERSION 3.28)
project(ebpf_backdoor C)

set(CMAKE_C_COMPILER clang)
set(CMAKE_C_STANDARD 99)

execute_process(COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c OUTPUT_FILE "${CMAKE_SOURCE_DIR}/bpf/vmlinux.h")

add_library(backdoor_rwx SHARED bpf/backdoor_rwx.c)
target_compile_options(backdoor_rwx PRIVATE -target bpf -O2 -g)
SET_TARGET_PROPERTIES(backdoor_rwx PROPERTIES RULE_LAUNCH_LINK
    "${CMAKE_SOURCE_DIR}/cpo ${CMAKE_BINARY_DIR} <OBJECTS> --"
)

add_library(backdoor_rop SHARED bpf/backdoor_rop.c)
target_compile_options(backdoor_rop PRIVATE -target bpf -O2 -g)
SET_TARGET_PROPERTIES(backdoor_rop PROPERTIES RULE_LAUNCH_LINK
        "${CMAKE_SOURCE_DIR}/cpo ${CMAKE_BINARY_DIR} <OBJECTS> --"
)

add_executable(loader_rwx loader_rwx.c)
target_link_libraries(loader_rwx bpf)

add_executable(loader_rop loader_rop.c)
target_link_libraries(loader_rop bpf)
