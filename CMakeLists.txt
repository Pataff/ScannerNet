cmake_minimum_required(VERSION 3.26)
project(NetworkScanner CXX)

# Richiedi C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Trova Boost 1.88.0
find_package(Boost 1.88.0 REQUIRED COMPONENTS 
    system 
    program_options 
    thread
)

# Aggiungi eseguibile
add_executable(network_scanner main.cpp)

# Include directories
target_include_directories(network_scanner PRIVATE ${Boost_INCLUDE_DIRS})

# Link libraries
target_link_libraries(network_scanner 
    PRIVATE 
        Boost::system 
        Boost::program_options
        Boost::thread
)

# Opzioni di compilazione specifiche per piattaforma
if(WIN32)
    target_link_libraries(network_scanner PRIVATE ws2_32 mswsock)
    # Su Windows potrebbe essere necessario linkare anche iphlpapi.lib
    target_link_libraries(network_scanner PRIVATE iphlpapi)
elseif(UNIX)
    target_link_libraries(network_scanner PRIVATE pthread)
endif()

# Abilita warning
if(MSVC)
    target_compile_options(network_scanner PRIVATE /W4)
else()
    target_compile_options(network_scanner PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Opzioni di ottimizzazione per release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(MSVC)
        target_compile_options(network_scanner PRIVATE /O2)
    else()
        target_compile_options(network_scanner PRIVATE -O3)
    endif()
endif()

# Messaggio informativo
message(STATUS "Configurazione Network Scanner:")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Boost Version: ${Boost_VERSION}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")