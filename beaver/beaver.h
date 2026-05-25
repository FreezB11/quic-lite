/// @file: beaver.h
#pragma once

#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "b.packet.h"
#include "b.recv.h"
#include "b.send.h"
#include "b.protocol.h"

class Beaver {
private:
    ip_version_t       __version;
    conn_state_t       __state;
    int                __fd;
    struct sockaddr_in __peer;

public:
    explicit Beaver(ip_version_t ver=IPV4);
    ~Beaver();

    // sender: set peer address (who to send to)
    int establish(int port, const char *ip);

    // receiver: bind to a local port (who to listen on)
    int listen_on(int port);

    // sender: chunk a byte stream into MAX_PAYLOAD-sized packets
    int send_stream(const byte *data, size_t len);

    // receiver: accumulate packets until a short chunk signals end-of-stream
    int recv_stream(byte *buf, size_t buf_len);

    // accessors
    int          fd()      const { return __fd;      }
    conn_state_t state()   const { return __state;   }
    ip_version_t version() const { return __version; }
};