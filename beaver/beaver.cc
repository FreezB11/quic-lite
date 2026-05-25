/// @file: beaver.cc
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "beaver.h"

Beaver::Beaver(ip_version_t ver) {
    std::memset(&__peer, 0, sizeof(__peer));
    __version = ver;
    __state   = stateless;

    int domain = (ver == IPV4) ? AF_INET : AF_INET6;
    __fd = socket(domain, SOCK_DGRAM, 0);
    if (__fd < 0) {
        perror("socket");
    }
    std::cout << "[Beaver] init OK  fd=" << __fd << "\n";
}

Beaver::~Beaver() {
    if (__fd >= 0) {
        close(__fd);
        __fd = -1;
    }
}

int Beaver::establish(int port, const char *ip) {
    __peer.sin_family = (__version == IPV4) ? AF_INET : AF_INET6;
    __peer.sin_port   = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &__peer.sin_addr) <= 0) {
        perror("inet_pton");
        return -1;
    }

    __state = statefull;
    std::cout << "[Beaver] peer set " << ip << ":" << port << "\n";
    return 0;
}

int Beaver::listen_on(int port) {
    struct sockaddr_in local{};
    local.sin_family      = (__version == IPV4) ? AF_INET : AF_INET6;
    local.sin_port        = htons((uint16_t)port);
    local.sin_addr.s_addr = INADDR_ANY;

    if (bind(__fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) < 0) {
        perror("bind");
        return -1;
    }

    __state = statefull;
    std::cout << "[Beaver] listening on port " << port << "\n";
    return 0;
}

int Beaver::send_stream(const byte *data, size_t len) {
    uint32_t seq     = 0;
    size_t   offset  = 0;
    unsigned packets = 0;

    while (offset < len) {
        size_t   remaining = len - offset;
        uint16_t chunk     = static_cast<uint16_t>(
            remaining > MAX_PAYLOAD ? MAX_PAYLOAD : remaining
        );

        if (beaver_send(__fd, &__peer, seq, 0, 0x00, data + offset, chunk) < 0)
            return -1;

        seq    += chunk;
        offset += chunk;
        packets++;
    }

    std::cout << "[Beaver] sent " << len << " byte(s) across "
              << packets << " packet(s)\n";
    return 0;
}

int Beaver::recv_stream(byte *buf, size_t buf_len) {
    header_t hdr;
    byte     payload[MAX_PAYLOAD];
    size_t   total = 0;

    while (true) {
        std::memset(payload, 0, sizeof(payload));

        if (beaver_recv(__fd, &__peer, &hdr, payload) < 0)
            return -1;

        if (total + hdr.len > buf_len) {
            std::cerr << "[Beaver] recv buffer overflow\n";
            return -1;
        }

        std::memcpy(buf + total, payload, hdr.len);
        total += hdr.len;

        if (hdr.len < MAX_PAYLOAD)
            break;
    }

    std::cout << "[Beaver] received " << total << " byte(s)\n";
    return static_cast<int>(total);
}