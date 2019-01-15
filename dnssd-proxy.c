/* dnssd-proxy.c
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
 * This is a Discovery Proxy module for the SRP gateway.
 *
 * The motivation here is that it makes sense to co-locate the SRP relay and the Discovery Proxy because
 * these functions are likely to co-exist on the same node, listening on the same port.  For homenet-style
 * name resolution, we need a DNS proxy that implements DNSSD Discovery Proxy for local queries, but
 * forwards other queries to an ISP resolver.  The SRP gateway is already expecting to do this.
 * This module implements the functions required to allow the SRP gateway to also do Discovery Relay.
 * 
 * The Discovery Proxy relies on Apple's DNS-SD library and the mDNSResponder DNSSD server, which is included
 * in Apple's open source mDNSResponder package, available here:
 *
 *            https://opensource.apple.com/tarballs/mDNSResponder/
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

// Enumerate the list of interfaces, map them to interface indexes, give each one a name
// Have a tree of subdomains for matching

// Parse a NUL-terminated text string into a sequence of labels.
dns_name_t *
dns_pres_name_parse(const char *pname)
{
    const char *dot = strchr(pname, '.');
    dns_label_t *ret;
    if (dot == NULL) {
        dot = pname + strlen(pname);
    }
    ret = calloc((dot - pname) + 1 - DNS_MAX_LABEL_SIZE + sizeof *ret, 1);
    if (ret == NULL) {
        return NULL;
    }
    ret->len = dot - pname;
    if (ret->len > 0) {
        memcpy(ret->data, pname, ret->len);
    }
    ret->data[ret->len] = 0;
    if (dot[0] == '.') {
        ret->next = dns_pres_name_parse(dot + 1);
    }
    return ret;
}

bool
dns_subdomain_of(dns_name_t *name, dns_name_t *domain)
{
    int dnum = 0, nnum = 0;
    dns_name_t *np, *dp;

    for (dp = domain; dp; dp = dp->next) {
        dnum++;
    }
    for (np = name; np; np = np->next) {
        nnum++;
    }
    if (nnum < dnum) {
        return false;
    }
    for (np = name; np; np = np->next) {
        if (nnum-- == dnum) {
            break;
        }
    }
    return dns_names_equal(np, domain);
}

void
dp_formerr(comm_t *comm)
{
    dns_wire_t response;
    memset(&response, 0, DNS_HEADER_SIZE);
    // We take the ID and the rcode from the incoming message, because if the
    // header has been mangled, we (a) wouldn't have gotten here and (b) don't
    // have any better choice anyway.
    response.id = comm->message->wire.id;
    dns_qr_set(&response, dns_qr_response);
    dns_opcode_set(&response, dns_opcode_get(&comm->message->wire));
    dns_rcode_set(&response, dns_rcode_formerr);
    //comm->send_response(comm, &response, DNS_HEADER_SIZE); // No RRs
}

bool
dp_served(dns_name_t *name)
{
    static dns_name_t *home_dot_arpa = NULL;
    if (home_dot_arpa == NULL) {
        home_dot_arpa = dns_pres_name_parse("home.arpa.");
        if (home_dot_arpa == NULL) {
            ERROR("Unable to parse home.arpa!");
            return false;
        }
    }

    // For now we treat any query to home.arpa as local.
    return dns_subdomain_of(name, home_dot_arpa);
}

void
dp_query(comm_t *comm, unsigned offset, dns_rr_t *question)
{
    // Convert the question name to presentation format; we can't support names that have special
    // characters in them.
    // Issue a DNSServiceQueryRecord call
    // Create a comm_t for the query
    // The callback builds a response hanging off of the query_state_t.
    // When we get the "no more" flag, send a response
    // If we are not doing DNS push, we're done
    // Otherwise, we can continue to send responses as they come in.
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
