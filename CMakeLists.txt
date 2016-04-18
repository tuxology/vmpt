# vmpt
#
# VMCS packet analysis using Intel Processor Trace
# Copyright (c) 2016, Suchakra Sharma <suchakrapani.sharma@polymtl.ca>

cmake_minimum_required(VERSION 2.6)

set(CMAKE_PREFIX_PATH /usr/lib64)

find_library( PT_LIBRARY
    NAMES libipt ipt
    HINTS "${CMAKE_PREFIX_PATH}"
    )

set(VMPT_FILES
  src/vmpt.c
)

add_executable(vmpt
    ${VMPT_FILES}
)

target_link_libraries(vmpt ${PT_LIBRARY})
