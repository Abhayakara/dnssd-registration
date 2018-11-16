/* fromwire.c
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
 * DNS wire-format functions.
 *
 * These are really simple functions for constructing DNS messages wire format.
 * The flow is that there is a transaction structure which contains pointers to both
 * a message output buffer and a response input buffer.   The structure is initialized,
 * and then the various wire format functions are called repeatedly to store data.
 * If an error occurs during this process, it's okay to just keep going, because the
 * error is recorded in the transaction; once all of the copy-in functions have been
 * called, the error status can be checked once at the end.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include "dns-msg.h"

#define DEBUG(...) fprintf(stderr, ##__VA_ARGS__)

bool
dns_opt_parse(dns_edns0_t *NONNULL *NULLABLE ret, dns_rrset_t *rrset)
{
    return true;
}

dns_label_t * NULLABLE
dns_label_parse(dns_wire_t *NONNULL message, unsigned mlen, unsigned *NONNULL offp)
{
    uint8_t llen = message->data[*offp];
    dns_label_t *rv;

    // Make sure that we got the data this label claims to encompass.
    if (*offp + llen + 1 > mlen) {
        DEBUG("claimed length of label is too long: %u > %u.\n", *offp + llen + 1, mlen);
        return NULL;
    }

    rv = calloc(llen + 1 - DNS_MAX_LABEL_SIZE + sizeof *rv, 1);
    if (rv == NULL) {
        DEBUG("memory allocation for %u byte label (%.*s) failed.\n",
              *offp + llen + 1, *offp + llen + 1, &message->data[*offp + 1]);
        return NULL;
    }

    rv->len = llen;
    memcpy(rv->data, &message->data[*offp + 1], llen);
    rv->data[llen] = 0; // We NUL-terminate the label for convenience
    *offp += llen + 1;
    return rv;
}

bool
dns_name_parse(dns_label_t *NONNULL *NULLABLE ret, dns_wire_t *NONNULL message, unsigned len,
               unsigned *NONNULL offp, unsigned base)
{
    dns_label_t *rv;

    if (*offp == len) {
        return false;
    }

    // A pointer?
    if ((message->data[*offp] & 0xC0) == 0xC0) {
        unsigned pointer;
        if (*offp + 2 > len) {
            DEBUG("incomplete compression pointer: %u > %u", *offp + 2, len);
            return false;
        }
        pointer = (((unsigned)message->data[*offp] & 0x3f) << 8) | (unsigned)message->data[*offp + 1];
        *offp += 2;
        if (pointer >= base) {
            // Don't allow a pointer forward, or to a pointer we've already visited.
            DEBUG("compression pointer points forward: %u >= %u.\n", pointer, base);
            return false;
        }
        if (pointer < DNS_HEADER_SIZE) {
            // Don't allow pointers into the header.
            DEBUG("compression pointer points into header: %u.\n", pointer);
            return false;
        }
        pointer -= DNS_HEADER_SIZE;
        if (message->data[pointer] & 0xC0) {
            // If this is a pointer to a pointer, it's not valid.
            DEBUG("compression pointer points into pointer: %u %02x%02x.\n", pointer,
                  message->data[pointer], pointer + 1 < len ? message->data[pointer + 1] : 0xFF);
            return false;
        }
        if (message->data[pointer] + pointer >= base || message->data[pointer] + pointer >= *offp) {
            // Possibly this isn't worth checking.
            DEBUG("compression pointer points to something that goes past current position: %u %u\n",
                  pointer, message->data[pointer]);
            return false;
        }
        return dns_name_parse(ret, message, len, &pointer, pointer);
    }
    // We don't support binary labels, which are historical, and at this time there are no other valid
    // DNS label types.
    if (message->data[*offp] & 0xC0) {
        DEBUG("invalid label type: %x\n", message->data[*offp]);
        return false;
    }
    
    rv = dns_label_parse(message, len, offp);
    if (rv == NULL) {
        return false;
    }

    *ret = rv;

    if (rv->len == 0) {
        return true;
    }
    return dns_name_parse(&rv->next, message, len, offp, base);
}

bool
dns_u16_parse(dns_wire_t *NONNULL message, unsigned len, unsigned *NONNULL offp, uint16_t *NONNULL ret)
{
    uint16_t rv;
    if (*offp + 2 > len) {
        DEBUG("dns_u16_parse: not enough room: %u > %u.\n", *offp + 2, len);
        return false;
    }

    rv = ((uint16_t)(message->data[*offp]) << 8) | (uint16_t)(message->data[*offp + 1]);
    *offp += 2;
    *ret = rv;
    return true;
}

bool
dns_u32_parse(dns_wire_t *NONNULL message, unsigned len, unsigned *NONNULL offp, uint32_t *NONNULL ret)
{
    uint32_t rv;
    if (*offp + 4 > len) {
        DEBUG("dns_u32_parse: not enough room: %u > %u.\n", *offp + 4, len);
        return false;
    }

    rv = (((uint32_t)(message->data[*offp]) << 24) | ((uint32_t)(message->data[*offp + 1]) << 16) |
          ((uint32_t)(message->data[*offp + 2]) << 8) | (uint32_t)(message->data[*offp + 3]));
    *offp += 4;
    *ret = rv;
    return true;
}

static void
dns_name_dump(FILE *outfile, dns_label_t *name)
{
    char *prev = "";
    dns_label_t *lp;
    
    for (lp = name; lp; lp = lp->next) {
        fprintf(outfile, "%s%s", prev, lp->data);
        prev = ".";
    }
}

static void
dns_rrdata_dump(FILE *outfile, dns_rrset_t *rrset)
{
    int i;
    char nbuf[80];
    dns_txt_element_t *txt;

    switch(rrset->type) {
    case dns_rrtype_srv:
        fprintf(outfile, "SRV %d %d %d ", rrset->data.srv.priority, rrset->data.srv.weight, rrset->data.srv.port);
        dns_name_dump(outfile, rrset->data.ptr.name);
        break;

    case dns_rrtype_ptr:
        fputs("PTR ", outfile);
        dns_name_dump(outfile, rrset->data.ptr.name);
        break;

    case dns_rrtype_cname:
        fputs("CNAME ", outfile);
        dns_name_dump(outfile, rrset->data.ptr.name);
        break;

    case dns_rrtype_a:
        for (i = 0; i < rrset->data.a.num; i++) {
            inet_ntop(AF_INET, &rrset->data.a.addrs[i], nbuf, sizeof nbuf);
            fputs(nbuf, outfile);
            putc(' ', outfile);
        }
        break;
        
    case dns_rrtype_aaaa:
        for (i = 0; i < rrset->data.aaaa.num; i++) {
            inet_ntop(AF_INET6, &rrset->data.aaaa.addrs[i], nbuf, sizeof nbuf);
            fputs(nbuf, outfile);
            putc(' ', outfile);
        }
        break;

    case dns_rrtype_txt:
        for (txt = rrset->data.txt; txt; txt = txt->next) {
            if (txt == rrset->data.txt) {
                putc(' ', outfile);
            }
            putc('"', outfile);
            for (i = 0; i < txt->len; i++) {
                if (isascii(txt->data[i]) && isprint(txt->data[i])) {
                    putc(txt->data[i], outfile);
                } else {
                    fprintf(outfile, "<%x>", txt->data[i]);
                }
            }
            putc('"', outfile);
        }
        break;

    default:
        if (rrset->data.unparsed.len == 0) {
            fprintf(outfile, " <none>");
        } else {
            fprintf(outfile, "%02x", rrset->data.unparsed.data[0]);
            for (i = 1; i < rrset->data.unparsed.len; i++) {
                printf(" %02x", rrset->data.unparsed.data[i]);
            }
        }
        break;
    }
}

static bool
dns_rdata_parse(dns_rrset_t *NONNULL rrset,
                dns_wire_t *NONNULL message, unsigned len, unsigned *NONNULL offp)
{
    uint16_t rdlen;
    unsigned target;
    uint16_t addrlen;
    dns_txt_element_t *txt, **ptxt;
    
    if (!dns_u16_parse(message, len, offp, &rdlen)) {
        return false;
    }
    target = *offp + rdlen;
    if (target > len) {
        return false;
    }

    switch(rrset->type) {
    case dns_rrtype_srv:
        if (!dns_u16_parse(message, len, offp, &rrset->data.srv.priority)) {
            return false;
        }
        if (!dns_u16_parse(message, len, offp, &rrset->data.srv.weight)) {
            return false;
        }
        if (!dns_u16_parse(message, len, offp, &rrset->data.srv.port)) {
            return false;
        }
        // This fallthrough assumes that the first element in the srv, ptr and cname structs is
        // a pointer to a domain name.

    case dns_rrtype_ptr:
    case dns_rrtype_cname:
        if (!dns_name_parse(&rrset->data.ptr.name, message, len, offp, *offp)) {
            return false;
        }
        break;

        // We assume below that the a and aaaa structures in the data union are exact aliases of
        // each another.
    case dns_rrtype_a:
        addrlen = 4;
        goto addr_parse;
        
    case dns_rrtype_aaaa:
        addrlen = 16;
    addr_parse:
        if (rdlen & (addrlen - 1)) {
            DEBUG("dns_rdata_parse: %s rdlen not an even multiple of %u: %u",
                  addrlen == 4 ? "A" : "AAAA", addrlen, rdlen);
            return false;
        }
        rrset->data.a.addrs = malloc(rdlen);
        if (rrset->data.a.addrs == NULL) {
            return false;
        }
        rrset->data.a.num = rdlen /  addrlen;
        memcpy(rrset->data.a.addrs, &message->data[*offp], rdlen);
        *offp = target;
        break;
        
    case dns_rrtype_txt:
        ptxt = &rrset->data.txt;
        while (*offp < target) {
            unsigned tlen = message->data[*offp];
            if (*offp + tlen + 1 > target) {
                DEBUG("dns_rdata_parse: TXT RR length is larger than available space: %u %u",
                      *offp + tlen + 1, target);
                *ptxt = NULL;
                return false;
            }
            txt = malloc(tlen + 1 + sizeof *txt);
            if (txt == NULL) {
                DEBUG("dns_rdata_parse: no memory for TXT RR");
                return false;
            }
            txt->len = tlen;
            ++*offp;
            memcpy(txt->data, &message->data[*offp], tlen);
            *offp += tlen;
            txt->data[tlen] = 0;
            *ptxt = txt;
            ptxt = &txt->next;
        }
        break;

    default:
        if (rdlen > 0) {
            rrset->data.unparsed.data = malloc(rdlen);
            if (rrset->data.unparsed.data == NULL) {
                return false;
            }
            memcpy(rrset->data.unparsed.data, &message->data[*offp], rdlen);
        }
        rrset->data.unparsed.len = rdlen;
        *offp = target;
        break;
    }
    if (*offp != target) {
        DEBUG("dns_rdata_parse: parse for rrtype %d not fully contained: %u %u", rrset->type, target, *offp);
        return false;
    }
    return true;
}

bool
dns_rr_parse(dns_rrset_t *NONNULL rrset,
             dns_wire_t *NONNULL message, unsigned len, unsigned *NONNULL offp, bool rrdata_expected)
{
    if (!dns_name_parse(&rrset->name, message, len, offp, *offp)) {
        return false;
    }
    
    if (!dns_u16_parse(message, len, offp, &rrset->type)) {
        return false;
    }

    if (!dns_u16_parse(message, len, offp, &rrset->qclass)) {
        return false;
    }
    
    if (rrdata_expected) {
        if (!dns_u32_parse(message, len, offp, &rrset->ttl)) {
            return false;
        }
        if (!dns_rdata_parse(rrset, message, len, offp)) {
            return false;
        }
    }
        
    printf("rrtype: %u  qclass: %u  name: ", rrset->type, rrset->qclass);
    dns_name_dump(stdout, rrset->name);
    if (rrdata_expected) {
        printf("  rrdata: ");
        dns_rrdata_dump(stdout, rrset);
    }
    printf("\n");
    return true;
}

void dns_name_free(dns_label_t *name)
{
    dns_label_t *next;
    if (name == NULL) {
        return;
    }
    next = name->next;
    free(name);
    return dns_name_free(next);
}    

static void
dns_rrdata_free(dns_rrset_t *rrset)
{
    switch(rrset->type) {
    case dns_rrtype_srv:
    case dns_rrtype_ptr:
    case dns_rrtype_cname:
        dns_name_free(rrset->data.ptr.name);
        rrset->data.ptr.name = NULL;
        break;

    case dns_rrtype_a:
    case dns_rrtype_aaaa:
        free(rrset->data.a.addrs);
        rrset->data.a.addrs = NULL;
        break;
        
    case dns_rrtype_txt:
    default:
        free(rrset->data.unparsed.data);
        rrset->data.unparsed.data = NULL;
        break;
    }
}

void
dns_message_free(dns_message_t *message)
{
    int i;

#define FREE(count, sets)                           \
    for (i = 0; i < message->count; i++) {          \
        dns_rrset_t *set = &message->sets[i];   	\
        if (set->name) {							\
            dns_name_free(set->name);				\
            set->name = NULL;						\
        }											\
        dns_rrdata_free(set);                       \
    }												\
    if (message->sets) {    						\
        free(message->sets);						\
    }
    FREE(qdcount, questions);
    FREE(ancount, answers);
    FREE(nscount, authority);
    FREE(arcount, additional);
#undef FREE
}

bool
dns_wire_parse(dns_message_t *NONNULL *NULLABLE ret, dns_wire_t *NONNULL message, unsigned len)
{
    unsigned offset = 0;
    dns_message_t *rv = calloc(sizeof *rv, 1);
    int i;
    
    if (rv == NULL) {
        return false;
    }
    
#define PARSE(count, sets, name, rrdata_expected)                                   \
    rv->count = htons(message->count);                                              \
    if (rv->count > 50) {                                                           \
        dns_message_free(rv);                                                       \
        return false;                                                               \
    }                                                                               \
                                                                                    \
    if (rv->qdcount != 0) {                                                         \
        rv->sets = calloc(sizeof *rv->sets, rv->count);                             \
        if (rv->sets == NULL) {                                                     \
            dns_message_free(rv);                                                   \
            return false;                                                           \
        }                                                                           \
    }                                                                               \
                                                                                    \
    for (i = 0; i < rv->count; i++) {                                               \
        if (!dns_rr_parse(&rv->sets[i], message, len, &offset, rrdata_expected)) {  \
            dns_message_free(rv);                                                   \
            fprintf(stderr, name " %d RR parse failed.\n", i);                      \
            return false;                                                           \
        }                                                                           \
    }
    PARSE(qdcount,  questions, "question", false);
    PARSE(ancount,    answers, "answers", true);
    PARSE(nscount,  authority, "authority", true);
    PARSE(arcount, additional, "additional", true);
#undef PARSE
    
    for (i = 0; i < rv->ancount; i++) {
        // Parse EDNS(0)
        if (rv->additional[i].type == dns_rrtype_opt) {
            if (!dns_opt_parse(&rv->edns0, &rv->additional[i])) {
                dns_message_free(rv);
                return false;
            }
        }
    }
    *ret = rv;
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
