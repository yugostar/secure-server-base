cmake_minimum_required(VERSION 3.20)

project(SecureServerTray LANGUAGES CXX)

add_executable(SecureServerTray WIN32
    src/main.cpp
)

target_compile_features(SecureServerTray PRIVATE cxx_std_17)

target_compile_definitions(SecureServerTray PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(SecureServerTray PRIVATE
    user32
    shell32
    gdi32
    advapi32
)

if(MSVC)
    target_compile_options(SecureServerTray PRIVATE /W4 /permissive- /utf-8)
endif()

set_target_properties(SecureServerTray PROPERTIES
    OUTPUT_NAME "SecureServerTray"
)

install(TARGETS SecureServerTray RUNTIME DESTINATION .)
