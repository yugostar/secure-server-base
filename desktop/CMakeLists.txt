cmake_minimum_required(VERSION 3.20)

project(SakuraShield LANGUAGES C CXX)

set(RPC_IDL ${CMAKE_CURRENT_SOURCE_DIR}/rpc/SakuraShieldRpc.idl)
set(RPC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(RPC_HEADER ${RPC_OUT_DIR}/SakuraShieldRpc.h)
set(RPC_CLIENT_STUB ${RPC_OUT_DIR}/SakuraShieldRpc_c.c)
set(RPC_SERVER_STUB ${RPC_OUT_DIR}/SakuraShieldRpc_s.c)

add_custom_command(
    OUTPUT ${RPC_HEADER} ${RPC_CLIENT_STUB} ${RPC_SERVER_STUB}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RPC_OUT_DIR}
    COMMAND midl /nologo /env x64 /char signed /out ${RPC_OUT_DIR} ${RPC_IDL}
    DEPENDS ${RPC_IDL}
    VERBATIM
)

add_custom_target(generate_sakura_rpc DEPENDS
    ${RPC_HEADER}
    ${RPC_CLIENT_STUB}
    ${RPC_SERVER_STUB}
)

add_executable(SakuraShield WIN32
    src/main.cpp
    src/rpc_memory.cpp
    ${RPC_CLIENT_STUB}
)

add_executable(SakuraShieldService
    service/service_main.cpp
    src/rpc_memory.cpp
    ${RPC_SERVER_STUB}
)

add_dependencies(SakuraShield generate_sakura_rpc)
add_dependencies(SakuraShieldService generate_sakura_rpc)

target_include_directories(SakuraShield PRIVATE
    ${RPC_OUT_DIR}
)

target_include_directories(SakuraShieldService PRIVATE
    ${RPC_OUT_DIR}
)

foreach(target SakuraShield SakuraShieldService)
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_compile_definitions(${target} PRIVATE
        UNICODE
        _UNICODE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0601
    )
endforeach()

target_link_libraries(SakuraShield PRIVATE
    user32
    shell32
    gdi32
    advapi32
    rpcrt4
)

target_link_libraries(SakuraShieldService PRIVATE
    advapi32
    wtsapi32
    userenv
    rpcrt4
    winhttp
)

if(MSVC)
    target_compile_options(SakuraShield PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(SakuraShieldService PRIVATE /W4 /permissive- /utf-8)
endif()

set_target_properties(SakuraShield PROPERTIES
    OUTPUT_NAME "SakuraShield"
)

set_target_properties(SakuraShieldService PROPERTIES
    OUTPUT_NAME "SakuraShieldService"
)

install(TARGETS SakuraShield SakuraShieldService RUNTIME DESTINATION .)
