/* wire.c
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
#include "dns-msg.h"

// Convert a name to wire format.   Does not store the root label (0) at the end.
void
dns_name_to_wire(dns_name_pointer_t *NULLABLE r_pointer,
                 dns_transaction_t *NONNULL txn,
                 const char *NONNULL name)
{
    const char *next, *cur, *end;
    dns_name_pointer_t np;
    if (!txn->error) {
        memset(&np, 0, sizeof np);
        np.message_start = (u_int8_t *)txn->message;
        np.name_start = txn->p;

        cur = name;
        do {
            end = strchr(cur, '.');
            if (end == NULL) {
                end = cur + strlen(cur);
                if (end == cur) {
                    break;
                }
                next = NULL;
            } else {
                if (end == cur) {
                    break;
                }
                next = end + 1;
            }

            // Is there no space?
            if (txn->p + (1 + end - cur) >= txn->lim) {
                txn->error = ENOBUFS;
                return;
            }

            // Is the label too long?
            if (end - cur > DNS_MAX_LABEL_SIZE) {
                txn->error = ENAMETOOLONG;
                return;
            }

            // Store the label length
            *txn->p++ = (uint8_t)(end - cur);

            // Store the label.
            memcpy(txn->p, cur, end - cur);
            txn->p += (end - cur);
            np.num_labels++;
            np.length += 1 + (end - cur);

            cur = next;
        } while (next != NULL);

        if (np.length > DNS_MAX_NAME_SIZE) {
            txn->error = ENAMETOOLONG;
            return;
        }
        if (r_pointer != NULL) {
            *r_pointer = np;
        }
    }
}

// Like dns_name_to_wire, but includes the root label at the end.
void
dns_full_name_to_wire(dns_name_pointer_t *NULLABLE r_pointer,
                      dns_transaction_t *NONNULL txn,
                      const char *NONNULL name)
{
    dns_name_pointer_t np;
    if (!txn->error) {
        memset(&np, 0, sizeof np);
        dns_name_to_wire(&np, txn, name);
        if (!txn->error) {
            if (txn->p + 1 >= txn->lim) {
                txn->error = ENOBUFS;
                return;
            }
            *txn->p++ = 0;
            np.num_labels++;
            np.length += 1;
            if (np.length > DNS_MAX_NAME_SIZE) {
                txn->error = ENAMETOOLONG;
                return;
            }
            if (r_pointer) {
                *r_pointer = np;
            }
        }
    }
}

// Store a pointer to a name that's already in the message.
void
dns_ptr_to_wire(dns_name_pointer_t *NULLABLE r_pointer,
                dns_transaction_t *NONNULL txn,
                dns_name_pointer_t *NONNULL pointer)
{
    if (!txn->error) {
        u_int16_t offset = pointer->name_start - pointer->message_start;
        if (offset > DNS_MAX_POINTER) {
            txn->error = ETOOMANYREFS;
            return;
        }
        if (txn->p + 2 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        *txn->p++ = 0xc0 | (offset >> 8);
        *txn->p++ = offset & 0xff;
        if (r_pointer) {
            r_pointer->num_labels += pointer->num_labels;
            r_pointer->length += pointer->length + 1;
            if (r_pointer->length > DNS_MAX_NAME_SIZE) {
                txn->error = ENAMETOOLONG;
                return;
            }
        }
    }
}

// Store a 16-bit integer in network byte order
void
dns_ui16_to_wire(dns_transaction_t *NONNULL txn,
                 uint16_t val)
{
    if (!txn->error) {
        if (txn->p + 2 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        *txn->p++ = val >> 8;
        *txn->p++ = val & 0xff;
    }
}

void
dns_ui32_to_wire(dns_transaction_t *NONNULL txn,
                 uint32_t val)
{
    if (!txn->error) {
        if (txn->p + 4 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        *txn->p++ = val >> 24;
        *txn->p++ = (val >> 16) & 0xff;
        *txn->p++ = (val >> 8) & 0xff;
        *txn->p++ = val & 0xff;
    }
}

void
dns_ttl_to_wire(dns_transaction_t *NONNULL txn,
                int32_t val)
{
    if (!txn->error) {
        if (val < 0) {
            txn->error = EINVAL;
            return;
        }
        dns_ui32_to_wire(txn, (uint32_t)val);
    }
}

void
dns_rdlength_begin(dns_transaction_t *NONNULL txn)
{
    if (!txn->error) {
        if (txn->p + 2 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        if (txn->p_rdlength != NULL) {
            txn->error = EINVAL;
            return;
        }
        txn->p_rdlength = txn->p;
        txn->p += 2;
    }
}

void
dns_rdlength_end(dns_transaction_t *NONNULL txn)
{
    int rdlength;
    if (!txn->error) {
        if (txn->p_rdlength == NULL) {
            txn->error = EINVAL;
            return;
        }
        rdlength = txn->p - txn->p_rdlength - 2;
        txn->p_rdlength[0] = rdlength >> 8;
        txn->p_rdlength[1] = rdlength & 0xff;
        txn->p_rdlength = NULL;
    }
}

void
dns_rdata_a_to_wire(dns_transaction_t *NONNULL txn,
                    const char *NONNULL ip_address)
{
    if (!txn->error) {
        if (txn->p + 4 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        if (!inet_pton(AF_INET, ip_address, txn->p)) {
            txn->error = EINVAL;
        }
        txn->p += 4;
    }
}

void
dns_rdata_aaaa_to_wire(dns_transaction_t *NONNULL txn,
                       const char *NONNULL ip_address)
{
    if (!txn->error) {
        if (txn->p + 16 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        if (!inet_pton(AF_INET6, ip_address, txn->p)) {
            txn->error = EINVAL;
        }
        txn->p += 16;
    }
}

void
dns_rdata_key_to_wire(dns_transaction_t *NONNULL txn,
                      unsigned key_type,
                      unsigned name_type,
                      unsigned signatory,
                      unsigned protocol,
                      unsigned algorithm,
                      uint8_t *NONNULL key,
                      int key_len)
{
    if (!txn->error) {
        if (key_type > 3 || name_type > 3 || signatory > 15 || protocol > 255 || algorithm > 255) {
            txn->error = EINVAL;
            return;
        }
        if (txn->p + key_len + 4 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        *txn->p++ = (key_type << 6) | name_type;
        *txn->p++ = signatory;
        *txn->p++ = protocol;
        *txn->p++ = algorithm;
        memcpy(txn->p, key, key_len);
        txn->p += key_len;
    }
}

void
dns_rdata_txt_to_wire(dns_transaction_t *NONNULL txn,
                      const char *NONNULL txt_record)
{
    if (!txn->error) {
        unsigned len = strlen(txt_record);
        if (txn->p + len + 1 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        if (len > 255) {
            txn->error = ENAMETOOLONG;
            return;
        }
        *txn->p++ = (u_int8_t)len;
        memcpy(txn->p, txt_record, len);
        txn->p += len;
    }
}

void
dns_edns0_header_to_wire(dns_transaction_t *NONNULL txn,
                         int mtu,
                         int xrcode,
                         int version,
                         int DO)
{
    if (!txn->error) {
        if (txn->p + 9 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        *txn->p++ = 0; // root label
        dns_ui16_to_wire(txn, dns_rrtype_opt);
        dns_ui16_to_wire(txn, mtu);
        *txn->p++ = xrcode;
        *txn->p++ = version;
        *txn->p++ = DO << 7;	// flags (usb)
        *txn->p++ = 0;			// flags (lsb, mbz)
    }
}

void
dns_edns0_option_begin(dns_transaction_t *NONNULL txn)
{
    if (!txn->error) {
        if (txn->p + 2 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        if (txn->p_opt != NULL) {
            txn->error = EINVAL;
            return;
        }
        txn->p_opt = txn->p;
        txn->p += 2;
    }
}

void
dns_edns0_option_end(dns_transaction_t *NONNULL txn)
{
    int opt_length;
    if (!txn->error) {
        if (txn->p_opt == NULL) {
            txn->error = EINVAL;
            return;
        }
        opt_length = txn->p - txn->p_opt - 2;
        txn->p_opt[0] = opt_length >> 8;
        txn->p_opt[1] = opt_length & 0xff;
        txn->p_opt = NULL;
    }
}

void
dns_sig0_signature_to_wire(dns_transaction_t *NONNULL txn,
                           unsigned algorithm,
                           const uint8_t *NONNULL private_key,
                           int private_key_len,
                           dns_name_pointer_t *NONNULL signer)
{
    // 1 name (root)
    // 2 type (SIG)
    // 2 class (0)
    // 4 TTL (0)
    // 18 SIG RDATA up to signer name
    // 2 signer name
    // 64 signature data (depends on algorithm, we're assuming a 256-bit hash until actual code is written)
    // 93 bytes total
    
    if (!txn->error) {
        if (txn->p + 93 >= txn->lim) {
            txn->error = ENOBUFS;
            return;
        }
        *txn->p++ = 0;	// root label
        dns_ui16_to_wire(txn, dns_rrtype_sig);
        dns_ui16_to_wire(txn, 0); // class
        dns_ttl_to_wire(txn, 0); // SIG RR TTL
        dns_rdlength_begin(txn);
        dns_ui16_to_wire(txn, 0); // type = 0 for transaction signature
        *txn->p++ = algorithm;
        *txn->p++ = 0; // labels field doesn't apply for transaction signature
        dns_ttl_to_wire(txn, 0); // ttl doesn't apply
        dns_ui32_to_wire(txn, 0); // signature inception time is problematic
        dns_ui32_to_wire(txn, 0); // signature
        dns_ui16_to_wire(txn, 0); // key tag
        dns_ptr_to_wire(NULL, txn, signer); // Pointer to the owner name the key is attached to
        memset(txn->p, 0xFA, 64); // XXX generate a signature! :)
        txn->p += 64;
        dns_rdlength_end(txn);
    }
}

int
dns_send_to_server(dns_transaction_t *NONNULL txn,
                   const char *NONNULL anycast_address,
                   dns_response_callback_t NONNULL callback)
{
    union {
        struct sockaddr_storage s;
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } addr, myaddr, from;
    socklen_t len, fromlen;
    ssize_t rv, datasize;

    if (!txn->error) {
        memset(&addr, 0, sizeof addr);

        // Try IPv4 first because IPv6 addresses are never valid IPv4 addresses
        if (inet_pton(AF_INET, anycast_address, &addr.sin.sin_addr)) {
            addr.sin.sin_family = AF_INET;
            addr.sin.sin_port = htons(53);
            len = sizeof addr.sin;
        } else if (inet_pton(AF_INET6, anycast_address, &addr.sin6.sin6_addr)) {
            addr.sin6.sin6_family = AF_INET6;
            addr.sin6.sin6_port = htons(53);
            len = sizeof addr.sin6;
        } else {
            txn->error = EPROTONOSUPPORT;
            return -1;
        }
//#ifdef HAVE_SA_LEN
        addr.sa.sa_len = len;
//#endif

        txn->sock = socket(addr.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
        if (txn->sock < 0) {
            txn->error = errno;
            return -1;
        }

        memset(&myaddr, 0, sizeof myaddr);
        myaddr.sin.sin_port = htons(9999);
        myaddr.sa.sa_len = len;
        myaddr.sa.sa_family = addr.sa.sa_family;
        rv = bind(txn->sock, &myaddr.sa, len);
        if (rv < 0) {
            txn->error = errno;
            return -1;
        }

        datasize = txn->p - ((u_int8_t *)txn->message);
        rv = sendto(txn->sock, txn->message, datasize, 0, &addr.sa, len);
        if (rv < 0) {
            txn->error = errno;
            goto out;
        }
        if (rv != datasize) {
            txn->error = EMSGSIZE;
            goto out;
        }
        fromlen = sizeof from;
        rv = recvfrom(txn->sock, txn->response, sizeof *txn->response, 0, &from.sa, &fromlen);
        if (rv < 0) {
            txn->error = errno;
            goto out;
        }
        txn->response_length = rv;
    }
out:
    close(txn->sock);
    txn->sock = 0;

    if (txn->error) {
        return -1;
    }
    return 0;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
