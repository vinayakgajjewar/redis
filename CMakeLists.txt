cmake_minimum_required(VERSION 3.27)
project(redis)

set(CMAKE_CXX_STANDARD 20)

add_executable(03-client
        03-tcp-client-server/client.cpp
)

add_executable(03-server
        03-tcp-client-server/server.cpp
)

add_executable(04-client
        04-request-response-protocol/client.cpp
)

add_executable(04-server
        04-request-response-protocol/server.cpp
)

add_executable(06-client
        06-event-loop/client.cpp
)

add_executable(06-server
        06-event-loop/server.cpp
)

add_executable(07-client
        07-key-value-server/client.cpp
)

add_executable(07-server
        07-key-value-server/server.cpp
)