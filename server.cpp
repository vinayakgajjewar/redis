#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include <string>
#include <vector>
#include <map>

static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

static void msg_errno(const char *msg) {
    fprintf(stderr, "[errno: %d] %s\n", errno, msg);
}

static void die(const char *msg) {
    fprintf(stderr, "[%d] %s\n", errno, msg);
    abort();
}

static void fd_set_nb(int fd) {
    errno = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if (errno) {
        die("fcntl error");
        return;
    }
    flags |= O_NONBLOCK;
    errno = 0;
    (void) fcntl(fd, F_SETFL, flags);
    if (errno) {
        die("fcntl error");
    }
}

/*
 * Likely larger than the kernel buffer.
 */
const size_t k_max_msg = 32 << 20;

struct Conn {
    int fd = -1;
    bool want_read = false;
    bool want_write = false;
    bool want_close = false;

    /*
     * Buffered input and output.
     */
    std::vector<uint8_t> incoming;
    std::vector<uint8_t> outgoing;
};

/*
 * Append to the back.
 */
static void buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

/*
 * Remove from the front.
 */
static void buf_consume(std::vector<uint8_t> &buf, size_t n) {
    buf.erase(buf.begin(), buf.begin() + n);
}

/*
 * Application callback for when the listening socket is ready.
 */
static Conn *handle_accept(int fd) {
    struct sockaddr_in client_addr = {};
    socklen_t addrlen = sizeof(client_addr);
    int connfd = accept(fd, (struct sockaddr *) &client_addr, &addrlen);
    if (connfd < 0) {
        msg_errno("accept() error");
        return NULL;
    }
    uint32_t ip = client_addr.sin_addr.s_addr;
    fprintf(stderr, "new client from %u.%u.%u.%u:%u\n", ip & 255, (ip >> 8) & 255, (ip >> 16) & 255, ip >> 24,
            ntohs(client_addr.sin_port));
    fd_set_nb(connfd);
    Conn *conn = new Conn();
    conn->fd = connfd;
    conn->want_read = true;
    return conn;
}

const size_t k_max_args = 200 * 1000;

/*
 * Read 4 bytes. cur is a pointer that's being passed by reference because we
 * adjust the pointer after consuming data from it.
 */
static bool read_u32(const uint8_t *&cur, const uint8_t *end, uint32_t &out) {
    if (cur + 4 > end) {
        return false;
    }
    memcpy(&out, cur, 4);
    cur += 4;
    return true;
}

/*
 * cur is a pointer that's being passed by reference.
 */
static bool read_str(const uint8_t *&cur, const uint8_t *end, size_t n, std::string &out) {
    if (cur + n > end) {
        return false;
    }
    out.assign(cur, cur + n);
    cur += n;
    return true;
}

static int32_t parse_req(const uint8_t *data, size_t size, std::vector<std::string> &out) {
    const uint8_t *end = data + size;
    uint32_t nstr = 0;
    if (!read_u32(data, end, nstr)) {
        return -1;
    }
    if (nstr > k_max_args) {
        return -1;
    }
    while (out.size() < nstr) {
        uint32_t len = 0;
        if (!read_u32(data, end, len)) {
            return -1;
        }
        out.push_back(std::string());
        if (!read_str(data, end, len, out.back())) {
            return -1;
        }
    }
    if (data != end) {
        return -1;
    }
    return 0;
}

enum {
    RES_OK = 0, RES_ERR = 1, RES_NX = 2
};

struct Response {
    uint32_t status = 0;
    std::vector<uint8_t> data;
};

/*
 * Fake the key-value store with a standard library map.
 */
static std::map<std::string, std::string> g_data;

static void do_request(std::vector<std::string> &cmd, Response &out) {
    if (cmd.size() == 2 && cmd[0] == "get") {

        /*
         * Handle the GET command.
         */
        auto it = g_data.find(cmd[1]);
        if (it == g_data.end()) {
            out.status = RES_NX;
            return;
        }
        const std::string &val = it->second;
        out.data.assign(val.begin(), val.end());
    } else if (cmd.size() == 3 && cmd[0] == "set") {

        /*
         * Handle the SET command.
         */
        g_data[cmd[1]].swap(cmd[2]);
    } else if (cmd.size() == 2 && cmd[0] == "del") {

        /*
         * Handle the DEL command.
         */
        g_data.erase(cmd[1]);
    } else {
        out.status = RES_ERR;
    }
}

static void make_response(const Response &resp, std::vector<uint8_t> &out) {
    uint32_t resp_len = 4 + (uint32_t) resp.data.size();
    buf_append(out, (const uint8_t *) &resp_len, 4);
    buf_append(out, (const uint8_t *) &resp.status, 4);
    buf_append(out, resp.data.data(), resp.data.size());
}

/*
 * Process a single request if there is enough data.
 */
static bool try_one_request(Conn *conn) {

    /*
     * Try to parse the message header.
     */
    if (conn->incoming.size() < 4) {
        return false;
    }
    uint32_t len = 0;
    memcpy(&len, conn->incoming.data(), 4);
    if (len > k_max_msg) {
        msg("too long");
        conn->want_close = true;
        return false;
    }

    /*
     * Parse the message body.
     */
    if (4 + len > conn->incoming.size()) {
        return false;
    }
    const uint8_t *request = &conn->incoming[4];

    /*
     * Now that we have a whole request, perform some application logic.
     */
    std::vector<std::string> cmd;
    if (parse_req(request, len, cmd) < 0) {
        msg("bad request");
        conn->want_close = true;
        return false;
    }
    Response resp;
    do_request(cmd, resp);
    make_response(resp, conn->outgoing);

    /*
     * Remove the request message from the buffer. We can't just empty the
     * buffer here because of this magical thing called "pipelining."
     */
    buf_consume(conn->incoming, 4 + len);
    return true;
}

/*
 * Application callback for when the socket is writable.
 */
static void handle_write(Conn *conn) {
    assert(conn->outgoing.size() > 0);
    ssize_t rv = write(conn->fd, &conn->outgoing[0], conn->outgoing.size());
    if (rv < 0) {
        msg_errno("write error");
        conn->want_close = true;
        return;
    }

    /*
     * Remove written data from the outgoing buffer.
     */
    buf_consume(conn->outgoing, (size_t) rv);
    if (conn->outgoing.size() == 0) {
        conn->want_read = true;
        conn->want_write = false;
    }
}

/*
 * Application callback for when the socket is readable.
 */
static void handle_read(Conn *conn) {
    uint8_t buf[64 * 1024];
    ssize_t rv = read(conn->fd, buf, sizeof(buf));
    if (rv < 0 && errno == EAGAIN) {
        return;
    }
    if (rv < 0) {
        msg_errno("read error");
        conn->want_close = true;
        return;
    }
    if (rv == 0) {
        if (conn->incoming.size() == 0) {
            msg("client closed");
        } else {
            msg("unexpected EOF");
        }
        conn->want_close = true;
        return;
    }

    /*
     * We got some new data.
     */
    buf_append(conn->incoming, buf, (size_t) rv);

    /*
     * Parse requests and generate responses. We have to call this in a loop
     * because of pipelining.
     */
    while (try_one_request(conn)) {}
    if (conn->outgoing.size() > 0) {
        conn->want_read = false;
        conn->want_write = true;
        return handle_write(conn);
    }
}

int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket");
    }
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(0);
    int rv = bind(fd, (const sockaddr *) &addr, sizeof(addr));
    if (rv) {
        die("bind");
    }

    /*
     * Set the listening file descriptor to nonblocking mode.
     */
    fd_set_nb(fd);

    /*
     * Listen.
     */
    rv = listen(fd, SOMAXCONN);
    if (rv) {
        die("listen");
    }

    /*
     * A map of all client connections, keyed by file descriptor.
     */
    std::vector<Conn *> fd2conn;

    /*
     * The event loop.
     */
    std::vector<struct pollfd> poll_args;
    while (true) {
        poll_args.clear();
        struct pollfd pfd = {fd, POLLIN, 0};
        poll_args.push_back(pfd);
        for (Conn *conn: fd2conn) {
            if (!conn) {
                continue;
            }
            struct pollfd pfd = {conn->fd, POLLERR, 0};
            if (conn->want_read) {
                pfd.events |= POLLIN;
            }
            if (conn->want_write) {
                pfd.events |= POLLOUT;
            }
            poll_args.push_back(pfd);
        }

        /*
         * Wait for readiness.
         */
        int rv = poll(poll_args.data(), (nfds_t) poll_args.size(), -1);
        if (rv < 0 && errno == EINTR) {

            /*
             * This is not an error.
             */
            continue;
        }
        if (rv < 0) {
            die("poll");
        }

        /*
         * Handle the listening socket.
         */
        if (poll_args[0].revents) {
            if (Conn *conn = handle_accept(fd)) {
                if (fd2conn.size() <= (size_t) conn->fd) {
                    fd2conn.resize(conn->fd + 1);
                }
                assert(!fd2conn[conn->fd]);
                fd2conn[conn->fd] = conn;
            }
        }

        /*
         * Handle connection sockets.
         */
        for (size_t i = 1; i < poll_args.size(); i++) {
            uint32_t ready = poll_args[i].revents;
            if (ready == 0) {
                continue;
            }
            Conn *conn = fd2conn[poll_args[i].fd];
            if (ready & POLLIN) {
                assert(conn->want_read);
                handle_read(conn);
            }
            if (ready & POLLOUT) {
                assert(conn->want_write);
                handle_write(conn);
            }

            /*
             * Close the socket if there's an error or if the application wants
             * to.
             */
            if ((ready & POLLERR) || conn->want_close) {
                (void) close(conn->fd);
                fd2conn[conn->fd] = NULL;
                delete conn;
            }
        }
    }
}