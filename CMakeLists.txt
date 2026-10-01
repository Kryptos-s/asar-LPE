cmake_minimum_required(VERSION 3.20)

project(discord_lpe_poc LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "discord-lpe-poc builds on Windows only")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/release/windows-x64")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/release/windows-x64")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/release/windows-x64")

add_executable(discord-lpe-poc
    src/main.cpp
    src/Poc.cpp
    src/Asar.cpp
    src/Json.cpp
)

target_compile_features(discord-lpe-poc PRIVATE cxx_std_23)
target_compile_definitions(discord-lpe-poc PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
target_include_directories(discord-lpe-poc PRIVATE "${CMAKE_SOURCE_DIR}/include")
if(MINGW)
    target_link_options(discord-lpe-poc PRIVATE -static -static-libgcc -static-libstdc++)
endif()
target_link_libraries(discord-lpe-poc PRIVATE bcrypt shell32 shlwapi advapi32 crypt32 wintrust)
