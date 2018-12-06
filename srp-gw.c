/* srp-gw.c
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

#define USE_KQUEUE // XXX

#pragma mark structures

typedef union addr addr_t;
union addr {
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
    char *name;
    read_callback_t read_callback;
    write_callback_t write_callback;
    datagram_callback_t datagram_callback;
    close_callback_t close_callback;
    message_t *message;
    uint8_t *buf;
    addr_t address;
    size_t message_length_len;
    size_t message_length, message_cur;
    int sock;
    uint8_t message_length_bytes[2];
    bool want_read : 1;
    bool want_write : 1;
};
    

#pragma mark Globals
comm_t *comms;
int kq;

static int
usage(const char *progname)
{
    ERROR("usage: %s -s <addr> <port> -t <subnet> ... -u <ifname> <subnet> ...", progname);
    ERROR("  -s can only appear once.");
    ERROR("  -t can only appear once, and is followed by one or more subnets.");
    ERROR("  -u can appear more than once, is followed by one interface name, and");
    ERROR("     one or more subnets.");
    ERROR("  <addr> is an IPv4 address or IPv6 address.");
    ERROR("  <port> is a UDP port number.");
    ERROR("  <subnet> is an IP address followed by a slash followed by the prefix width.");
    ERROR("  <ifname> is the printable name of the interface.");
    ERROR("ex: srp-gw -s 2001:DB8::1 53 -t 2001:DB8:1300::/48 -u en0 2001:DB8:1300:1100::/56");
    return 1;
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

typedef struct delete delete_t;
struct delete {
    delete_t *next;
    dns_name_t *name;
};

typedef struct dns_host_description dns_host_description_t;
struct dns_host_description {
    dns_name_t *name;
    dns_rr_t *a, *aaaa, *key;
    delete_t *delete;
    int num_instances;
};

typedef struct service_instance service_instance_t;
struct service_instance {
    service_instance_t *next;
    dns_host_description_t *host_description;
    dns_name_t *name;
    delete_t *delete;
    int num_instances;
    dns_rr_t *srv, *txt;
};

typedef struct service service_t;
struct service {
    service_t *next;
    service_instance_t *instance;
    dns_name_t *name;
    dns_rr_t *rr;
};

bool
srp_relay(comm_t *comm, dns_message_t *message)
{
    dns_name_t *update_zone;
    bool updating_services_dot_arpa = false;
    int i;
    dns_host_description_t *host_description = NULL;
    delete_t *deletes = NULL, *dp, **dpp = &deletes;
    service_instance_t *service_instances = NULL, *sip, **sipp = &service_instances;
    service_t *services = NULL, *sp, **spp = &services;
    dns_rr_t *signature;
    char namebuf[DNS_MAX_NAME_SIZE + 1], namebuf1[DNS_MAX_NAME_SIZE + 1];
    bool ret = false;
    struct timeval now;

    // Update requires a single SOA record as the question
    if (message->qdcount != 1) {
        ERROR("srp_relay: update received with qdcount > 1");
        return false;
    }

    // Update should contain zero answers.
    if (message->ancount != 0) {
        ERROR("srp_relay: update received with ancount > 0");
        return false;
    }

    if (message->questions[0].type != dns_rrtype_soa) {
        ERROR("srp_relay: update received with rrtype %d instead of SOA in question section.",
              message->questions[0].type);
        return false;
    }
    update_zone = message->questions[0].name;

    // What zone are we updating?
    if (dns_names_equal_text(update_zone, "services.arpa")) {
        updating_services_dot_arpa = true;
    }

    // Scan over the authority RRs; do the delete consistency check.  We can't do other consistency checks
    // because we can't assume a particular order to the records other than that deletes have to come before
    // adds.
    for (i = 0; i < message->nscount; i++) {
        dns_rr_t *rr = &message->authority[i];

        // If this is a delete for all the RRs on a name, record it in the list of deletes.
        if (rr->type == dns_rrtype_any && rr->qclass == dns_qclass_any && rr->ttl == 0) {
            for (dp = deletes; dp; dp = dp->next) {
                if (dns_names_equal(dp->name, rr->name)) {
                    ERROR("srp_relay: two deletes for the same name: %s",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                    goto out;
                }
            }
            dp = calloc(sizeof *dp, 1);
            if (!dp) {
                ERROR("srp_relay: no memory.");
                goto out;
            }
            dp->name = rr->name;
            *dpp = dp;
            dpp = &dp->next;
        }

        // Otherwise if it's an A or AAAA record, it's part of a hostname entry.
        else if (rr->type == dns_rrtype_a || rr->type == dns_rrtype_aaaa || rr->type == dns_rrtype_key) {
            // Allocate the hostname record
            if (!host_description) {
                host_description = calloc(sizeof *host_description, 1);
                if (!host_description) {
                    ERROR("srp_relay: no memory");
                    goto out;
                }
            }

            // Make sure it's preceded by a deletion of all the RRs on the name.
            if (!host_description->delete) {
                for (dp = deletes; dp; dp = dp->next) {
                    if (dns_names_equal(dp->name, rr->name)) {
                        break;
                    }
                }
                if (dp == NULL) {
                    ERROR("srp_relay: ADD for hostname %s without a preceding delete.",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                    goto out;
                }
                host_description->delete = dp;
                host_description->name = dp->name;
            }
                          
            if (rr->type == dns_rrtype_a) {
                if (host_description->a != NULL) {
                    ERROR("srp_relay: more than one A rrset received for name: %s",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                    goto out;
                }
                host_description->a = rr;
            } else if (rr->type == dns_rrtype_aaaa) {
                if (host_description->aaaa != NULL) {
                    ERROR("srp_relay: more than one AAAA rrset received for name: %s",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                    goto out;
                }
                host_description->aaaa = rr;
            } else if (rr->type == dns_rrtype_key) {
                if (host_description->key != NULL) {
                    ERROR("srp_relay: more than one KEY rrset received for name: %s",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                    goto out;
                }
                host_description->key =  rr;
            }
        }

        // Otherwise if it's an SRV entry, that should be a service instance name.
        else if (rr->type == dns_rrtype_srv || rr->type == dns_rrtype_txt) {
            // Should be a delete that precedes this service instance.
            for (dp = deletes; dp; dp = dp->next) {
                if (dns_names_equal(dp->name, rr->name)) {
                    break;
                }
            }
            if (dp == NULL) {
                ERROR("srp_relay: ADD for service instance not preceded by delete: %s",
                      dns_name_print(rr->name, namebuf, sizeof namebuf));
                goto out;
            }
            for (sip = service_instances; sip; sip = sip->next) {
                if (dns_names_equal(sip->name, rr->name)) {
                    break;
                }
            }
            if (!sip) {
                sip = calloc(sizeof *sip, 1);
                if (sip == NULL) {
                    ERROR("srp_relay: no memory");
                    goto out;
                }
                sip->delete = dp;
                sip->name = dp->name;
                *sipp = sip;
                sipp = &sip->next;
            }
            if (rr->type == dns_rrtype_srv) {
                if (sip->srv != NULL) {
                    ERROR("srp_relay: more than one SRV rr received for service instance: %s",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                    goto out;
                }
                sip->srv = rr;
            } else if (rr->type == dns_rrtype_txt) {
                if (sip->txt != NULL) {
                    ERROR("srp_relay: more than one SRV rr received for service instance: %s",
                          dns_name_print(rr->name, namebuf, sizeof namebuf));
                }
                sip->txt = rr;
            }
        }

        // Otherwise if it's a PTR entry, that should be a service name
        else if (rr->type == dns_rrtype_ptr) {
            sp = calloc(sizeof *sp, 1);
            if (sp == NULL) {
                ERROR("srp_relay: no memory");
                goto out;
            }
            sp->rr = rr;
            *spp = sp;
            spp = &sp->next;
        }            

        // Otherwise it's not a valid update
        else {
            ERROR("srp_relay: unexpected rrtype %d on %s in update.", rr->type,
                      dns_name_print(rr->name, namebuf, sizeof namebuf));
            goto out;
        }
    }

    // Now that we've scanned the whole update, do the consistency checks for updates that might
    // not have come in order.
    
    // First, make sure there's a host description.
    if (host_description == NULL) {
        ERROR("srp_relay: SRP update does not include a host description.");
        goto out;
    }

    // Make sure that each service add references a service instance that's in the same update.
    for (sp = services; sp; sp = sp->next) {
        for (sip = service_instances; sip; sip = sip->next) {
            if (dns_names_equal(sip->name, sp->rr->data.ptr.name)) {
                // Note that we have already verified that there is only one service instance
                // with this name, so this could only ever happen once in this loop even without
                // the break statement.
                sp->instance = sip;
                sip->num_instances++;
                break;
            }
        }
        // If this service doesn't point to a service instance that's in the update, then the
        // update fails validation.
        if (sip == NULL) {
            ERROR("srp_relay: service %s points to an instance that's not included: %s",
                  dns_name_print(sp->name, namebuf, sizeof namebuf),
                  dns_name_print(sip->name, namebuf1, sizeof namebuf1));
            goto out;
        }
    }

    for (sip = service_instances; sip; sip = sip->next) {
        // For each service instance, make sure that at least one service references it
        if (sip->num_instances == 0) {
            ERROR("srp_relay: service instance update for %s is not referenced by a service update.",
                  dns_name_print(sip->name, namebuf, sizeof namebuf));
            goto out;
        }

        // For each service instance, make sure that it references the host description
        if (dns_names_equal(host_description->name, sip->srv->data.srv.name)) {
            sip->host_description = host_description;
            host_description->num_instances++;
        }
    }

    // Make sure that at least one service instance references the host description
    if (host_description->num_instances == 0) {
        ERROR("srp_relay: host description %s is not referenced by any service instances.",
              dns_name_print(host_description->name, namebuf, sizeof namebuf));
        goto out;
    }

    // Make sure the host description has at least one address record.
    if (host_description->a == NULL && host_description->aaaa == NULL) {
        ERROR("srp_relay: host description %s doesn't contain any IP addresses.",
              dns_name_print(host_description->name, namebuf, sizeof namebuf));
        goto out;
    }
    // And make sure it has a key record
    if (host_description->key == NULL) {
        ERROR("srp_relay: host description %s doesn't contain a key.",
              dns_name_print(host_description->name, namebuf, sizeof namebuf));
        goto out;
    }

    // The signature should be the last thing in the additional section.   Even if the signature
    // is valid, if it's not at the end we reject it.   Note that we are just checking for SIG(0)
    // so if we don't find what we're looking for, we forward it to the DNS auth server which
    // will either accept or reject it.
    if (message->arcount < 1) {
        ERROR("srp_relay: signature not present");
        goto out;
    }
    signature = &message->additional[message->arcount -1];
    if (signature->type != dns_rrtype_sig) {
        ERROR("srp_relay: signature is not at the end or is not present");
        goto out;
    }

    // Make sure that the signer name is the hostname.   If it's not, it could be a legitimate
    // update with a different key, but it's not an SRP update, so we pass it on.
    if (!dns_names_equal(signature->data.sig.signer, host_description->name)) {
        ERROR("srp_relay: signer %s doesn't match host %s", 
              dns_name_print(signature->data.sig.signer, namebuf, sizeof namebuf),
              dns_name_print(host_description->name, namebuf1, sizeof namebuf1));
        goto out;
    }
    
    // Make sure we're in the time limit for the signature.   Zeroes for the inception and expiry times
    // mean the host that send this doesn't have a working clock.   One being zero and the other not isn't
    // valid unless it's 1970.
    if (signature->data.sig.inception != 0 || signature->data.sig.expiry != 0) {
        gettimeofday(&now, NULL);
        // The sender does the bracketing, so we can just do a simple comparison.
        if (now.tv_sec > signature->data.sig.expiry || now.tv_sec < signature->data.sig.inception) {
            ERROR("signature is not timely: %lu < %lu < %lu does not hold",
                  (unsigned long)signature->data.sig.inception, (unsigned long)now.tv_sec,
                  (unsigned long)signature->data.sig.expiry);
            goto badsig;
        }
    }

    // Now that we have the key, we can validate the signature.   If the signature doesn't validate,
    // there is no need to pass the message on.
    if (!srp_sig0_verify(message->wire, host_description->key, signature)) {
        ERROR("signature is not valid");
        goto badsig;
    }

badsig:
    // True means we consumed it, not that it was valid.
    ret = true;

out:
    // free everything we allocated but (it turns out) aren't going to use
    for (dp = deletes; dp; ) {
        delete_t *next = dp->next;
        free(dp);
        dp = next;
    }
    for (sip = service_instances; sip; ) {
        service_instance_t *next = sip->next;
        free(sip);
        sip = next;
    }
    for (sp = services; sp; ) {
        service_t *next = sp->next;
        free(sp);
        sp = next;
    }
    if (host_description != NULL) {
        free(host_description);
    }
    return ret;
}

void
dns_evaluate(comm_t *comm)
{
    dns_message_t *message;

    // Drop incoming responses--we're a server, so we only accept queries.
    if (dns_qr_get(&comm->message->wire) == dns_qr_response) {
        return;
    }

    // Forward incoming messages that are queries but not updates.
    // XXX do this later--for now we operate only as a translator, not a proxy.
    if (dns_opcode_get(&comm->message->wire) != dns_opcode_update) {
        // dns_forward(comm);
        return;
    }
    
    // Parse the UPDATE message.
    if (!dns_wire_parse(&message, &comm->message->wire, comm->message->length)) {
        ERROR("dns_wire_parse failed.");
        return;
    }
    
    // We need the wire message to validate the signature...
    message->wire = &comm->message->wire;
    if (!srp_relay(comm, message)) {
        // The message wasn't invalid, but wasn't an SRP message.
        // dns_forward(comm)
    }
    // But we don't save it.
    message->wire = NULL;

    //dns_message_free(message);
}

void dns_input(comm_t *comm)
{
    dns_evaluate(comm);
    message_free(comm->message);
    comm->message = NULL;
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

int dispatch_events(struct timespec *timeout)
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

void
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

void
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


comm_t *
setup_listener_socket(int family, int protocol, const char *name)
{
    comm_t *listener;
    socklen_t sl;
    int rv;
    int flag = 1;
    
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
        ERROR("Can't get socket: %s", strerror(errno));
        comm_free(listener);
        return NULL;
    }
    rv = setsockopt(listener->sock, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof flag);
    if (rv < 0) {
        ERROR("SO_REUSEPORT failed: %s", strerror(errno));
        comm_free(listener);
        return NULL;
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
        return NULL;
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
    listener->datagram_callback = dns_input;

    return listener;
}

int
main(int argc, char **argv)
{
    int i;
    subnet_t *tcp_validators = NULL;
    udp_validator_t *udp_validators = NULL;
    udp_validator_t *NULLABLE *NONNULL up = &udp_validators;
    subnet_t *NULLABLE *NONNULL nt = &tcp_validators;
    subnet_t *NULLABLE *NONNULL sp;
    addr_t server, pref;
    uint16_t port;
    socklen_t len, prefalen;
    char *s, *p;
    int width;
    comm_t *listener;
    struct timespec to;
    int sock, result;

    // Read the configuration from the command line.
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-s")) {
            if (i++ == argc) {
                ERROR("-s is missing server IP address.");
                return usage(argv[0]);
            }
            len = getipaddr(&server, argv[i]);
            if (!len) {
                ERROR("Invalid IP address: %s.", argv[i]);
                return usage(argv[0]);
            }
            server.sa.sa_len = len;
            if (i++ == argc) {
                ERROR("-s is missing server port.");
                return usage(argv[0]);
            }
            port = strtol(argv[i], &s, 10);
            if (s == argv[i] || s[0] != '\0') {
                ERROR("Invalid port number: %s", argv[i]);
                return usage(argv[0]);
            }
            if (server.sa.sa_family == AF_INET) {
                server.sin.sin_port = htons(port);
            } else {
                server.sin6.sin6_port = htons(port);
            }
            i += 2;
        } else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "-u")) {
            if (!strcmp(argv[i], "-u")) {
                if (i++ == argc) {
                    ERROR("-u is missing interface name.");
                    return usage(argv[0]);
                }
                *up = calloc(1, sizeof **up);
                if (*up == NULL) {
                    ERROR("udp_validators: out of memory.");
                    return usage(argv[0]);
                }
                (*up)->ifname = strdup(argv[i]);
                if ((*up)->ifname == NULL) {
                    ERROR("udp validators: ifname: out of memory.");
                    return usage(argv[0]);
                }
                sp = &((*up)->subnets);
            } else {
                sp = nt;
            }

            if (i++ == argc) {
                ERROR("%s requires at least one prefix.", argv[i - 1]);
                return usage(argv[0]);
            }
            s = strchr(argv[i], '/');
            if (s == NULL) {
                ERROR("%s is not a prefix.", argv[i]);
                return usage(argv[0]);
            }
            *s = 0;
            ++s;
            prefalen = getipaddr(&pref, argv[i]);
            if (!prefalen) {
                ERROR("%s is not a valid prefix address.", argv[i]);
                return usage(argv[0]);
            }
            width = strtol(s, &p, 10);
            if (s == p || p[0] != '\0') {
                ERROR("%s (prefix width) is not a number.", p);
                return usage(argv[0]);
            }
            if (width < 0 ||
                (pref.sa.sa_family == AF_INET && width > 32) ||
                (pref.sa.sa_family == AF_INET6 && width > 64)) {
                ERROR("%s is not a valid prefix length for %s", p,
                        pref.sa.sa_family == AF_INET ? "IPv4" : "IPv6");
                return usage(argv[0]);
            }

            *nt = calloc(1, sizeof **nt);
            if (!*nt) {
                ERROR("tcp_validators: out of memory.");
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
        ERROR("kqueue(): %s", strerror(errno));
        return 1;
    }

    // Set up listeners
    listener = setup_listener_socket(AF_INET, IPPROTO_UDP, "UDPv4 listener");
    if (!listener) {
        ERROR("UDPv4 listener: fail.");
        return 1;
    }
    listener->next = comms;
    comms = listener;
    
    listener = setup_listener_socket(AF_INET6, IPPROTO_UDP, "UDPv6 listener");
    if (!listener) {
        ERROR("UDPv6 listener: fail.");
        return 1;
    }
    listener->next = comms;
    comms = listener;

    listener = setup_listener_socket(AF_INET, IPPROTO_TCP, "TCPv4 listener");
    if (!listener) {
        ERROR("TCPv4 listener: fail.");
        return 1;
    }
    listener->next = comms;
    comms = listener;

    listener = setup_listener_socket(AF_INET6, IPPROTO_TCP, "TCPv6 listener");
    if (!listener) {
        ERROR("TCPv4 listener: fail.");
        return 1;
    }
    listener->next = comms;
    comms = listener;
    
    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    result = fcntl(sock, F_GETFL, 0);
    if (result < 0) {
        INFO("F_GETFL failed: %s", strerror(errno));
        goto skip;
    }
    result = fcntl(sock, F_SETFL, result | O_NONBLOCK);
    if (result < 0) {
        ERROR("F_SETFL failed: %s", strerror(errno));
        goto skip;
    }

skip:
    do {
        int something = 0;
        to.tv_sec = 1;
        to.tv_nsec = 0;
        something = dispatch_events(&to);
        INFO("dispatched %d events.", something);
    } while (1);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
