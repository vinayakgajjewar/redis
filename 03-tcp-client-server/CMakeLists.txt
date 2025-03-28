cmake_minimum_required(VERSION 3.27)
project(03-tcp-client-server)

add_executable(client
        client.cpp
)

add_executable(server
        server.cpp
)