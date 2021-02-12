cmake_minimum_required(VERSION 3.17)
project(Four_in_a_Row)

set(CMAKE_CXX_STANDARD 17)
set(-DPURIFY)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})

add_executable(Four_in_a_Row_Client Client/Client.cpp
                                    Client/Client.h
                                    Client/Client_impl_utility.cpp
                                    Client/Client_impl_net.cpp
                                    Client/Client_impl_game.cpp
                                    Utility/SecureConnectionServlet.cpp
                                    Utility/SecureConnectionServlet.h
                                    Utility/utils.h
                                    Four_in_a_row_game/Four_in_a_row_game.cpp
                                    Four_in_a_row_game/Four_in_a_row_game.h Utility/Headers.h)

add_executable(Four_in_a_Row_Server Server/Server.cpp
                                    Server/Server.hpp
                                    Server/Server_impl_net.cpp
                                    Server/Server_impl_utility.cpp
                                    Utility/SecureConnectionServlet.cpp
                                    Utility/SecureConnectionServlet.h
                                    Utility/utils.h
                                    Utility/Headers.h)
#add_executable(Game Four_in_a_row_game/Four_in_a_row_game.cpp Four_in_a_row_game/Four_in_a_row_game_test.cpp)
target_link_libraries(Four_in_a_Row_Client OpenSSL::SSL )
target_link_libraries(Four_in_a_Row_Server OpenSSL::SSL )