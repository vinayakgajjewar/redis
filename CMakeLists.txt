cmake_minimum_required(VERSION 3.27)
project(redis)

add_executable(03-client
        03-tcp-client-server/client.cpp
)

add_executable(03-server
        03-tcp-client-server/server.cpp
)