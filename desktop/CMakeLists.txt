cmake_minimum_required(VERSION 3.20)

project(SakuraShield LANGUAGES CXX)

add_executable(SakuraShield WIN32
    src/main.cpp
)

target_compile_features(SakuraShield PRIVATE cxx_std_17)

target_compile_definitions(SakuraShield PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(SakuraShield PRIVATE
    user32
    shell32
    gdi32
    advapi32
)

if(MSVC)
    target_compile_options(SakuraShield PRIVATE /W4 /permissive- /utf-8)
endif()

set_target_properties(SakuraShield PROPERTIES
    OUTPUT_NAME "SakuraShield"
)

install(TARGETS SakuraShield RUNTIME DESTINATION .)
