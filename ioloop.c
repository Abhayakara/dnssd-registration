/* dispatch.c
 *
 * Copyright (c) 2018 Apple Computer, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Simple event dispatcher for DNS.
 */

#define __APPLE_USE_RFC_3542

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/event.h>
#include <fcntl.h>
#include <sys/time.h>

#include "srp.h"
#include "dns-msg.h"
#include "srp-crypto.h"
#include "ioloop.h"
#include "dnssd-proxy.h"

#define USE_KQUEUE // XXX

#pragma mark Globals
comm_t *comms;
int kq;

message_t *
message_allocate(size_t message_size)
{
    message_t *message = (message_t *)malloc(message_size + (sizeof (message_t)) - (sizeof (dns_wire_t)));
    if (message)
        memset(message, 0, (sizeof (message_t)) - (sizeof (dns_wire_t)));
    return message;
}

void
message_free(message_t *message)
{
    free(message);
}

void
comm_free(comm_t *comm)
{
    if (comm->name) {
        free(comm->name);
        comm->name = NULL;
    }
    if (comm->message) {
        free(comm->message);
        comm->message = NULL;
        comm->buf = NULL;
    }
    free(comm);
}

void
add_reader(comm_t *comm, read_callback_t callback)
{
#ifdef USE_SELECT
    comm->want_read = true;
#endif
#ifdef USE_EPOLL
#endif
#ifdef USE_KQUEUE
    struct kevent ev;
    int rv;
    EV_SET(&ev, comm->sock, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, comm);
    rv = kevent(kq, &ev, 1, NULL, 0, NULL);
    if (rv < 0) {
        ERROR("kevent add: %s", strerror(errno));
        return;
    }
#endif // USE_EPOLL
    comm->read_callback = callback;
}

bool
dispatch_init(void)
{
    kq = kqueue();
    if (kq < 0) {
        ERROR("kqueue(): %s", strerror(errno));
        return false;
    }
    return true;
}

int
dispatch_events(struct timespec *timeout)
{
#ifdef USE_SELECT
    comm_t *comm, **cp;
    int rv, nfds = 0;
    fd_set reads, writes, errors;
    struct timeval tv;

    FD_ZERO(&reads);
    FD_ZERO(&writes);
    FD_ZERO(&errors);
    tv.tv_sec = timeout->tv_sec;
    tv.tv_usec = timeout->tv_nsec / 1000;
    
    cp = &comms;
    while (*cp) {
        comm = *cp;
        if (comm->sock == -1) {
            *cp = comm->next;
            free(comm);
            continue;
        }
        if (comm->want_read || comm->want_write) {
            if (comm->sock >= nfds) {
                nfds = comm->sock + 1;
            }
            if (comm->want_read) {
                FD_SET(comm->sock, &reads);
            }
            if (comm->want_write) {
                FD_SET(comm->sock, &writes);
            }
        }
        cp = &comm->next;
    }
    rv = select(nfds, &reads, &writes, &writes, &tv);
    if (rv < 0) {
        ERROR("select: %s", strerror(errno));
        exit(1);
    }
    for (comm = comms; comm; comm = comm->next) {
        if (FD_ISSET(comm->sock, &reads)) {
            comm->read_callback(comm);
        } else {
            if (FD_ISSET(comm->sock, &writes)) {
                comm->write_callback(comm);
            }
        }
    }
    return rv;
#endif
#ifdef USE_KQUEUE
#define KEV_MAX 1
    struct kevent evs[KEV_MAX];
    comm_t *comm;
    int nev, i;

    nev = kevent(kq, NULL, 0, evs, KEV_MAX, timeout);
    if (nev < 0) {
        ERROR("kevent poll: %s", strerror(errno));
        exit(1);
    }
    for (i = 0; i < nev; i++) {
        comm = evs[i].udata;

        if (evs[i].filter == EVFILT_WRITE) {
            comm->write_callback(comm);
        } else if (evs[i].filter == EVFILT_READ) {
            comm->read_callback(comm);
        }
    }
    return nev;
#endif
}

static void
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
        ERROR("udp_read_callback: %s", strerror(errno));
        return;
    }
    message = message_allocate(rv);
    if (!message) {
        ERROR("udp_read_callback: out of memory");
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
    connection->message = message;
    connection->datagram_callback(connection);
}

static void
tcp_read_callback(comm_t *connection)
{
    int rv;
    if (connection->message_length_len < 2) {
        rv = read(connection->sock, &connection->message_length_bytes[connection->message_length_len],
                  2 - connection->message_length_len);
        if (rv < 0) {
        read_error:
            ERROR("tcp_read_callback: %s", strerror(errno));
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
            ERROR("tcp_read_callback: remote end (%s) closed connection", connection->name);
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
        connection->message = message_allocate(connection->message_length);
        if (!connection->message) {
            ERROR("udp_read_callback: out of memory");
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

static void
listen_callback(comm_t *listener)
{
    int rv;
    addr_t addr;
    socklen_t addr_len = sizeof addr;
    comm_t *comm;

    rv = accept(listener->sock, &addr.sa, &addr_len);
    if (rv < 0) {
        ERROR("accept: %s", strerror(errno));
        close(listener->sock);
        listener->sock = -1;
        return;
    }
    comm = calloc(1, sizeof *comm);
    comm->sock = rv;
    comm->address = addr;
    comm->next = comms;
    comms = comm;
    add_reader(comm, tcp_read_callback);
    comm->datagram_callback = listener->datagram_callback;
}


bool
setup_listener_socket(int family, int protocol, const char *name, datagram_callback_t datagram_callback)
{
    comm_t *listener;
    socklen_t sl;
    int rv;
    int flag = 1;
    
    listener = calloc(1, sizeof *listener);
    if (listener == NULL) {
        return false;
    }
    listener->name = strdup(name);
    if (!listener->name) {
        free(listener);
        return false;
    }
    listener->sock = socket(family, protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM, protocol);
    if (listener->sock < 0) {
        ERROR("Can't get socket: %s", strerror(errno));
        comm_free(listener);
        return false;
    }
    rv = setsockopt(listener->sock, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof flag);
    if (rv < 0) {
        ERROR("SO_REUSEPORT failed: %s", strerror(errno));
        comm_free(listener);
        return false;
    }

    if (family == AF_INET) {
        sl = sizeof listener->address.sin;
        listener->address.sin.sin_port = htons(53);
    } else {
        sl = sizeof listener->address.sin6;
        listener->address.sin6.sin6_port = htons(53);
    }
    listener->address.sa.sa_family = family;
    listener->address.sa.sa_len = sl;
    if (bind(listener->sock, &listener->address.sa, sl) < 0) {
        ERROR("Can't bind to 0#53/%s%s: %s",
                protocol == IPPROTO_UDP ? "udp" : "tcp", family == AF_INET ? "v4" : "v6",
                strerror(errno));
    out:
        close(listener->sock);
        free(listener);
        return false;
    }

    if (protocol == IPPROTO_TCP) {
        if (listen(listener->sock, 5 /* xxx */) < 0) {
            ERROR("Can't listen on 0#53/%s%s: %s.",
                    protocol == IPPROTO_UDP ? "udp" : "tcp", family == AF_INET ? "v4" : "v6",
                    strerror(errno));
            goto out;
        }                
        add_reader(listener, listen_callback);
    } else {
        rv = setsockopt(listener->sock, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                        family == AF_INET ? IP_PKTINFO : IPV6_RECVPKTINFO, &flag, sizeof flag);
        if (rv < 0) {
            ERROR("Can't set %s: %s.", family == AF_INET ? "IP_PKTINFO" : "IPV6_RECVPKTINFO",
                    strerror(errno));
            goto out;
        }
        add_reader(listener, udp_read_callback);
    }
    listener->datagram_callback = datagram_callback;
    listener->next = comms;
    comms = listener;
    return true;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
