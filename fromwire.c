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
dns_name_parse(dns_wire_t *NONNULL message, unsigned len,
               unsigned *NONNULL offp, unsigned base, dns_label_t *NONNULL *NULLABLE prev)
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
        return dns_name_parse(message, len, &pointer, pointer, prev);
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

    *prev = rv;

    if (rv->len == 0) {
        return true;
    }
    return dns_name_parse(message, len, offp, base, &rv->next);
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

bool
dns_rr_parse(dns_rrset_t *NONNULL rrset,
             dns_wire_t *NONNULL message, unsigned len, unsigned *NONNULL offp, bool rrdata_expected)
{
    dns_label_t *lp;
    char *prev = "";
    int i;

    if (!dns_name_parse(message, len, offp, *offp, &rrset->name)) {
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
        if (!dns_u16_parse(message, len, offp, &rrset->rdlen)) {
            return false;
        }
        if (*offp + rrset->rdlen > len) {
            return false;
        }
        rrset->data = malloc(rrset->rdlen + 1);
        if (rrset->data == NULL) {
            return false;
        }
        memcpy(rrset->data, &message->data[*offp], rrset->rdlen);
        rrset->data[rrset->rdlen + 1] = 0; // For text-format RRs
        *offp += rrset->rdlen;
    }
        
    printf("rrtype: %u  qclass: %u  name: ", rrset->type, rrset->qclass);
    for (lp = rrset->name; lp; lp = lp->next) {
        printf("%s%s", prev, lp->data);
        prev = ".";
    }
    if (rrdata_expected) {
        printf("  rrdata:");
        for (i = 0; i < rrset->rdlen; i++) {
            printf(" %02x", rrset->data[i]);
        }
        if (rrset->rdlen == 0) {
            printf(" <none>");
        }
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
        if (set->data) {							\
            free(set->data);						\
            set->data = NULL;						\
        }											\
    }												\
    if (message->questions) {						\
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
    
#define PARSE(count, sets, name)                                                    \
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
        if (!dns_rr_parse(&rv->sets[i], message, len, &offset, false)) {		    \
            dns_message_free(rv);                                                   \
            fprintf(stderr, name " %d RR parse failed.\n", i);                      \
            return false;                                                           \
        }                                                                           \
    }
    PARSE(qdcount,  questions, "question");
    PARSE(ancount,    answers, "answers");
    PARSE(nscount,  authority, "authority");
    PARSE(arcount, additional, "additional");
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
