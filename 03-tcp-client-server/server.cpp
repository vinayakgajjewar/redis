#include <arpa/inet.h>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

static void do_something(int connection_file_descriptor) {
    char read_buffer[64] = {};
    ssize_t bytes_read = read(connection_file_descriptor, read_buffer, sizeof(read_buffer) - 1);
    if (bytes_read == -1) {
        std::cerr << "Error: read() failed" << std::endl;
        return;
    }
    printf("Client says %s\n", read_buffer);

    /*
     * Send a message back to the client.
     */
    char write_buffer[] = "Hello from server";
    size_t write_buffer_length = strlen(write_buffer);
    write(connection_file_descriptor, write_buffer, write_buffer_length);
}

int main() {

    int return_val;

    /*
     * AF_INET is for IPv4. Use AF_INET6 for IPv6.
     */
    int domain = AF_INET;

    /*
     * SOCK_STREAM is for TCP. Use SOCK_DGRAM for UDP.
     */
    int type = SOCK_STREAM;
    int protocol = 0;
    int fd = socket(domain, type, protocol);
    if (fd == -1) {
        std::cerr << "Error: socket() failed" << std::endl;
    }

    /*
     * I don't understand what this does.
     */
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    /*
     * Bind to the wildcard address 0.0.0.0:1234.
     */
    struct sockaddr_in addr = {};
    addr.sin_family = domain;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(0);
    return_val = bind(fd, (const struct sockaddr *) &addr, sizeof(addr));
    if (return_val == -1) {
        std::cerr << "Error: bind() failed" << std::endl;
    }

    /*
     * Define the maximum size of the queue.
     */
    int backlog = SOMAXCONN;

    /*
     * Create the socket. The OS will handle TCP handshakes and place
     * established connectings in a queue, which can then be retrieved via
     * accept().
     */
    return_val = listen(fd, backlog);
    if (return_val == -1) {
        std::cerr << "Error: listen() failed" << std::endl;
    }

    /*
     * Accept and process each client connection.
     */
    while (true) {
        struct sockaddr_in client_addr = {};
        socklen_t address_length = sizeof(client_addr);
        int connection_file_descriptor = accept(fd, (struct sockaddr *) &client_addr, &address_length);
        if (connection_file_descriptor == -1) {
            std::cerr << "Error: accept() failed" << std::endl;
            continue;
        }
        do_something(connection_file_descriptor);
        close(connection_file_descriptor);
    }
}