#include <arpa/inet.h>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    int return_value;
    int domain = AF_INET;
    int type = SOCK_STREAM;
    int protocol = 0;
    int socket_descriptor = socket(domain, type, protocol);
    if (socket_descriptor == -1) {
        std::cerr << "Error: socket()" << std::endl;
    }
    struct sockaddr_in address = {};
    address.sin_family = domain;
    address.sin_port = ntohs(1234);
    address.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);
    return_value = connect(socket_descriptor, (const struct sockaddr *) &address, sizeof(address));
    if (return_value == -1) {
        std::cerr << "Error: connect()" << std::endl;
    }

    /*
     * Write something.
     */
    char message[] = "Hello from client";
    size_t message_length = strlen(message);
    write(socket_descriptor, message, message_length);

    /*
     * Read something back from the server.
     */
    char read_buffer[64] = {};
    ssize_t bytes_read = read(socket_descriptor, read_buffer, sizeof(read_buffer) - 1);
    if (bytes_read == -1) {
        std::cerr << "Error: read()" << std::endl;
    }
    printf("Server says %s\n", read_buffer);
    return_value = close(socket_descriptor);
    if (return_value == -1) {
        std::cerr << "Error: close()" << std::endl;
    }
}