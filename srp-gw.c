/* srp-gw.c
 *
 * This is a DNSSD Service Registration Protocol gateway.   The purpose of this is to make it possible
 * for SRP clients to update DNS servers that don't support SRP.
 *
 * The way it works is that this gateway listens on port ANY:53 and forwards either to another port on
 * the same host (not recommended) or to any port (usually 53) on a different host.   Requests are accepted
 * over both TCP and UDP in principle, but UDP requests should be from constrained nodes, and rely on
 * network topology for authentication.
 *
 * Note that this is not a full DNS proxy, so you can't just put it in front of a DNS server.
 */

// Get DNS server IP address
// Get list of permitted source subnets for TCP updates
// Get list of permitted source subnet/interface tuples for UDP updates
// Set up UDP listener
// Set up TCP listener (no TCP Fast Open)
// Event loop
// Transaction processing:
//   1. If UDP, validate that it's from a subnet that is valid for the interface on which it was received.
//   2. If TCP, validate that it's from a permitted subnet
//   3. Check that the message is a valid SRP update according to the rules
//   4. Check the signature
//   5. Do a DNS Update with prerequisites to prevent overwriting a host record with the same owner name but
//      a different key.
//   6. Send back the response

#define __APPLE_USE_RFC_3542

#include "dns-msg.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/event.h>

#pragma mark structures

typedef struct addr addr_t;
struct addr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

typedef struct subnet subnet_t;
struct subnet {
    subnet_t *NULLABLE next;
    uint8_t preflen;
    uint8_t family;
    char bytes[8];
};

typedef struct udp_validator udp_validator_t;
struct udp_validator {
    udp_validator_t *NULLABLE next;
    char *NONNULL ifname;
    int ifindex;
    subnet_t *subnets;
};

typedef struct message message_t;
struct message {
    addr_t src;
    size_t len;
    int ifindex;
    size_t length;
    dns_wire_t wire;
};

typedef struct comm comm_t;
typedef void (*read_callback_t)(comm_t *comm);
typedef void (*write_callback_t)(comm_t *comm);
typedef void (*datagram_callback_t)(comm_t *comm);
typedef void (*close_callback_t)(comm_t *comm);
struct comm {
    comm_t *next;
    const char *name;
    read_callback_t read_callback;
    write_callback_t write_callback;
    datagram_callback_t datagram_callback;
    datagram_callback_t close_callback;
    message_t *message;
    uint8_t *buf;
    addr_t address;
    size_t message_length_len;
    size_t message_length, message_cur;
    int sock;
    uint8_t message_length_bytes[2];
};
    

#pragma mark Globals
comm_t *comms;
int kq;

static int
usage(const char *progname)
{
    fprintf(stderr, "usage: %s -s <addr> <port> -t <subnet> ... -u <ifname> <subnet> ...\n", progname);
    fprintf(stderr, "  -s can only appear once.\n");
    fprintf(stderr, "  -t can only appear once, and is followed by one or more subnets.\n");
    fprintf(stderr, "  -u can appear more than once, is followed by one interface name, and\n");
    fprintf(stderr, "     one or more subnets.\n");
    fprintf(stderr, "  <addr> is an IPv4 address or IPv6 address.\n");
    fprintf(stderr, "  <port> is a UDP port number.\n");
    fprintf(stderr, "  <subnet> is an IP address followed by a slash followed by the prefix width.\n");
    fprintf(stderr, "  <ifname> is the printable name of the interface.\n");
    fprintf(stderr, "ex: srp-gw -s 2001:DB8::1 53 -t 2001:DB8:1300::/48 -u en0 2001:DB8:1300:1100::/56\n");
    return 1;
}

int
getipaddr(addr_t *addr, const char *p)
{
    if (inet_pton(AF_INET, p, &addr->sin.sin_addr)) {
        addr->sa.sa_family = AF_INET;
        return sizeof addr->sin;
    }  else if (inet_pton(AF_INET6, p, &addr->sin6.sin6_addr)) {
        addr->sa.sa_family = AF_INET6;
        return sizeof addr->sin6;
    } else {
        return 0;
    }
}                

message_t *
message_allocate(size_t message_size)
{
    message_t *message = (message_t *)malloc(message_size + (sizeof (message_t)) - (sizeof (dns_wire_t)));
    if (message)
        memset(message, 0, (sizeof (message_t)) - (sizeof (dns_wire_t)));
    return message;
}



void
add_reader(comm_t *comm, read_callback_t callback)
{
#ifdef USE_EPOLL
#else // use kqueue
    struct kevent ev;
    int rv;
    EV_SET(&ev, (uintptr_t)&comm->sock, EV_ADD, EVFILT_READ, 0, 0, comm);
    rv = kevent(kq, &ev, 1, NULL, 0, NULL);
    if (rv < 0) {
        fprintf(stderr, "kevent: %s\n", strerror(errno));
        return;
    }
#endif // USE_EPOLL

    comm->read_callback = callback;
}

void dispatch_events(struct timespec *timeout)
{
#ifdef USE_EPOLL
#else // use kqueue
#define KEV_MAX 1
    struct kevent evs[KEV_MAX];
    comm_t *comm;
    int nev, i;
    nev = kevent(kq, NULL, 0, evs, KEV_MAX, timeout);
    if (nev < 0) {
        fprintf(stderr, "kevent: %s\n", strerror(errno));
        exit(1);
    }
    for (i = 0; i < nev; i++) {
        comm = evs[i].udata;

        if (evs[i].fflags & EVFILT_WRITE) {
            comm->write_callback(comm);
        } else
            // We process read events only if there was no write event because the write event could
            // cause a change that would result in the data structure going away.
            if (evs[i].fflags & EVFILT_READ) {
                comm->read_callback(comm);
            }
    }
#endif
}

void
udp_read_callback(comm_t *connection)
{
    addr_t src;
    int rv;
    struct msghdr msg;
    struct iovec bufp;
    uint8_t msgbuf[DNS_MAX_UDP_PAYLOAD];
    char cmsgbuf[128];
    struct cmsghdr *cmh;
    message_t *message;

    bufp.iov_base = msgbuf;
    bufp.iov_len = DNS_MAX_UDP_PAYLOAD;
    msg.msg_iov = &bufp;
    msg.msg_iovlen = 1;
    msg.msg_name = &src;
    msg.msg_namelen = sizeof src;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof cmsgbuf;
    
    rv = recvmsg(connection->sock, &msg, 0);
    if (rv < 0) {
        fprintf(stderr, "udp_read_callback: %s\n", strerror(errno));
        return;
    }
    message = message_allocate(rv);
    if (!message) {
        fprintf(stderr, "udp_read_callback: out of memory\n");
        return;
    }
    memcpy(&message->src, &src, sizeof src);
    message->length = rv;
    memcpy(&message->wire, msgbuf, rv);
    
    // For UDP, we use the interface index as part of the validation strategy, so go get
    // the interface index.
    for (cmh = CMSG_FIRSTHDR(&msg); cmh; cmh = CMSG_NXTHDR(&msg, cmh)) {
        if (cmh->cmsg_level == IPPROTO_IPV6 && cmh->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo pktinfo;    

            memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
            message->ifindex = pktinfo.ipi6_ifindex;
        } else if (cmh->cmsg_level == IPPROTO_IP && cmh->cmsg_type == IP_PKTINFO) { 
            struct in_pktinfo pktinfo;
          
            memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
            message->ifindex = pktinfo.ipi_ifindex;
        }
    }

    connection->datagram_callback(connection);
}

void
tcp_read_callback(comm_t *connection)
{
    int rv;
    if (connection->message_length_len < 2) {
        rv = read(connection->sock, &connection->message_length_bytes[connection->message_length_len],
                  2 - connection->message_length_len);
        if (rv < 0) {
        read_error:
            fprintf(stderr, "tcp_read_callback: %s\n", strerror(errno));
            close(connection->sock);
            connection->sock = -1;
            if (connection->close_callback) {
                connection->close_callback(connection);
            }
            return;
        }
        // If we read zero here, the remote endpoint has closed or shutdown the connection.  Either case is
        // effectively the same--if we are sensitive to read events, that means that we are done processing
        // the previous message.
        if (rv == 0) {
        eof:
            fprintf(stderr, "tcp_read_callback: remote end (%s) closed connection\n", connection->name);
            close(connection->sock);
            connection->sock = -1;
            if (connection->close_callback) {
                connection->close_callback(connection);
            }
            return;
        }
        connection->message_length_len += rv;
        if (connection->message_length_len == 2) {
            connection->message_length = (((uint16_t)connection->message_length_bytes[0] << 8) |
                                          ((uint16_t)connection->message_length_bytes[1]));
        }
        return;
    }

    // If we only just got the length, we need to allocate a message
    if (connection->message == NULL) {
        connection->message = message_allocate(rv);
        if (!connection->message) {
            fprintf(stderr, "udp_read_callback: out of memory\n");
            return;
        }
        connection->buf = (uint8_t *)&connection->message->wire;
        connection->message->length = connection->message_length;
        memset(&connection->message->src, 0, sizeof connection->message->src);
    }

    rv = read(connection->sock, &connection->buf[connection->message_cur],
              connection->message_length - connection->message_cur);
    if (rv < 0) {
        goto read_error;
    }
    if (rv == 0) {
        goto eof;
    }

    connection->message_cur += rv;
    if (connection->message_cur == connection->message_length) {
        connection->datagram_callback(connection);
        // Caller is expected to consume the message, we are immediately ready for the next read.
        connection->message_length = connection->message_length_len = 0;
    }
}

void
listen_callback(comm_t *listener)
{
    int rv;
    addr_t addr;
    socklen_t addr_len = sizeof addr;
    comm_t *comm;

    rv = accept(listener->sock, &addr.sa, &addr_len);
    if (rv < 0) {
        fprintf(stderr, "accept: %s\n", strerror(errno));
        close(listener->sock);
        listener->sock = -1;
        return;
    }
    comm = calloc(1, sizeof *comm);
    comm->sock = rv;
    comm->address = addr;
    comm->next = comms;
    comms = comm;
    add_reader(comm, tcp_callback);
}


comm_t *
setup_listener_socket(int family, int protocol, const char *name)
{
    addr_t addr;
    comm_t *listener;
    socklen_t sl;
    
    listener = calloc(1, sizeof *listener);
    if (listener == NULL) {
        return listener;
    }
    listener->name = strdup(name);
    if (!listener->name) {
        free(listener);
        return NULL;
    }
    listener->sock = socket(family, protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM, protocol);
    if (listener->sock < 0) {
        fprintf(stderr, "Can't get socket: %s\n", strerror(errno));
        comm_free(listener);
        return NULL;
    }
    memset(&addr, 0, sizeof addr);
    if (family == AF_INET) {
        sl = sizeof addr.sin;
        addr.sin.sin_port = htons(53);
    } else {
        sl = sizeof addr.sin6;
        addr.sin6.sin6_port = htons(53);
    }
    addr.sin.sa_family = family;
    addr.sin.sa_len = sizeof addr.sin;
    if (bind(listener->sock, &addr.sa, sizeof addr.sin)) {
        fprintf(stderr, "Can't bind to 0#53/%s%s.\n",
                protocol == IPPROTO_UDP ? "udp" : "tcp", family == AF_INET ? "v4" : "v6");
    out:
        close(listener->sock);
        free(listener);
        return NULL;
    }

    if (protocol == IPPROTO_TCP) {
        if (listen(listener->sock, 5 /* xxx */)  0) {
            fprintf(stderr, "Can't listen on 0#53/%s%s.\n",
                    protocol == IPPROTO_UDP ? "udp" : "tcp", family == AF_INET ? "v4" : "v6");
            goto out;
        }                
        add_reader(comm, listen_callback);
    } else {
        int rv;
        int flag = 1;
        rv = setsockopt(comm->sock, IPPROTO_IP,
                        family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO, &flag, sizeof flag);
        add_reader(comm, udp_read_callback);
    }

    return listener;
}

int
main(int argc, char **argv)
{
    int i;
    subnet_t *tcp_validators = NULL;
    udp_validator_t *udp_validators = NULL;
    udp_validator_t *NULLABLE *NONNULL up = &udp_validataors;
    subnet_t *NULLABLE *NONNULL nt = &tcp_validators;
    subnet_t *NULLABLE *NONNULL sp;
    addr_t server, pref, ipv4src, ipv6src;
    uint16_t port;
    socklen_t len, prefalen;
    char *s, *p;
    int width;
    comm_t *listener;

    // Read the configuration from the command line.
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-s")) {
            if (i++ == argc) {
                fprintf(stderr, "-s is missing server IP address.\n");
                return usage(argv[0]);
            }
            len = getipaddr(&server, argv[i]);
            if (!len) {
                fprintf(stderr, "Invalid IP address: %s.\n", argv[i]);
                return usage(argv[0]);
            }
            addr.sa.sa_len = len;
            if (i++ == argc) {
                fprintf(stderr, "-s is missing server port.\n");
                return usage(argv[0]);
            }
            port = strtol(10, argv[i], &s);
            if (s == argv[i] || s[0] != '\0') {
                fprintf(stderr, "Invalid port number: %s\n", argv[i]);
                return usage(argv[0]);
            }
            i += 2;
        } else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "-u")) {
            if (!strcmp(argv[i], "-u")) {
                if (i++ == argc) {
                    fprintf("-u is missing interface name.\n");
                    return usage(argv[0]);
                }
                *up = calloc(1, sizeof **up);
                if (*up == NULL) {
                    fprintf("out of memory.\n");
                 	return usage(argv[0]);
                }
                (*up)->ifname = strdup(argv[i]);
                if ((*up)->ifname == NULL) {
                    fprintf("out of memory.\n");
                    return usage(argv[0]);
                }
                sp = &((*up)->subnets);
            } else {
                sp = nt;
            }

            if (i++ == argc) {
                fprintf(stderr, "%s requires at least one prefix.\n");
                return usage(argv[0]);
            }
            s = strchr(argv[i], '/');
            if (p == NULL) {
                fprintf(stderr, "%s is not a prefix.\n", argv[i]);
                return usage(argv[0]);
            }
            *p = 0;
            ++p;
            prefalen = getipaddr(&pref, argv[i]);
            if (!prefalen) {
                fprintf(stderr, "%s is not a valid prefix address.\n", argv[i]);
                return usage(argv[0]);
            }
            width = strtol(10, p, &s);
            if (s == p || s[0] != '\0') {
                fprintf(stderr, "%s (prefix width) is not a number.\n", p);
                return usage(argv[0]);
            }
            if (width < 0 ||
                (pref.sa.sa_family == AF_INET && width > 32) ||
                (pref.sa.sa_family == AF_INET6 && width > 64)) {
                fprintf(stderr, "%s is not a valid prefix length for %s\n", p,
                        pref.sa.sa_family == AF_INET ? "IPv4" : "IPv6");
                return usage(argv[0]);
            }

            *nt = calloc(1, sizeof **nt);
            if (!*nt) {
            oom:
                fprintf(stderr, "out of memory.\n");
                return 1;
            }

            (*nt)->preflen = width;
            (*nt)->family = pref.sa.sa_family;
            if (pref.sa.sa_family == AF_INET) {
                memcpy((*nt)->bytes, &pref.sin.sin_addr, 4);
            } else {
                memcpy((*nt)->bytes, &pref.sin6.sin6_addr, 8);
            }

            // *up will be non-null for -u and null for -t.
            if (*up) {
                up = &((*up)->next);
            } else {
                nt = sp;
            }
        }
    }

    kq = kqueue();
    if (kq < 0) {
        fprintf(stderr, "kqueue(): %s\n", strerror(errno));
        return 1;
    }

    // Set up listeners
    listener = setup_listener_sock(AF_INET, IPPROTO_UDP, "UDPv4 listener");
    if (!listener) {
        goto oom;
    }
    listener->next = comms;
    comms = listener;
    
    listener = setup_listener_sock(AF_INET6, IPPROTO_UDP, "UDPv6 listener");
    if (!listener) {
        goto oom;
    }
    listener->next = comms;
    comms = listener;

    listener = setup_listener_sock(AF_INET, IPPROTO_TCP, "TCPv4 listener");
    if (!listener) {
        goto oom;
    }
    listener->next = comms;
    comms = listener;

    listener = setup_listener_sock(AF_INET6, IPPROTO_TCP, "TCPv6 listener");
    if (!listener) {
        goto oom;
    }
    listener->next = comms;
    comms = listener;

    

}


// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
