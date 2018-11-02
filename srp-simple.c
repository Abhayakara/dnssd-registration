/* srp-simple.c
 *
 * Simple Service Registration Protocol Client
 *
 * This is intended for the constrained node solution for SRP.   It's intended to be flexible and
 * understandable while linking in the minimum possible support code to reduce code size.  It does
 * no mallocs, does not put anything big on the stack, and doesn't require an event loop.
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "dns-msg.h"

static void
dns_response_callback(dns_transaction_t *txn)
{
}

int
main(int argc, char **argv)
{
    const char *host_name = "thread-demo";
    const char *service_type = "_printer._tcp";
    const char *a_record = "127.0.0.1";
    const char *aaaa_record = "::1";
    const char *txt_record = "0";
    const char *anycast_address = "10.0.10.1";
    int port;
    int private_key_len = 0;
    int public_key_len = 0;
    uint8_t *private_key = NULL;
    uint8_t *public_key = NULL;
    dns_wire_t message, response;
    static dns_transaction_t txn;
    dns_name_pointer_t p_host_name;
    dns_name_pointer_t p_zone_name;
    dns_name_pointer_t p_service_name;
    dns_name_pointer_t p_service_instance_name;
    int line;

#define CH if (txn.error) goto fail;

    // Generate a random UUID.
#ifdef NOTYET
    message.id = srp_random16();
#else
    srandomdev();
    message.id = (uint32_t)(random()) & 65535;
#endif
    message.bitfield = 0;
    dns_qr_set(message, dns_qr_query);
    dns_opcode_set(message, dns_opcode_update);
    message.bitfield = htons(message.bitfield);

    // Message data...
    memset(&txn, 0, sizeof txn);
    txn.p = &message.data[0];  // We start storing RR data here.
    txn.lim = &message.data[DNS_DATA_SIZE]; // This is the limit to how much we can store.
    txn.message = &message;
    txn.response = &response;
    txn.response_length = (int)(sizeof response);

    message.qdcount = htons(1); // ZOCOUNT = 1
    // Copy in Zone name (and save pointer)
    // ZTYPE = SOA
    // ZCLASS = IN
    dns_full_name_to_wire(&p_zone_name, &txn, "service.arpa"); CH;
    dns_ui16_to_wire(&txn, dns_rrtype_soa); CH;
    dns_ui16_to_wire(&txn, dns_qclass_in); CH;

    message.ancount = 0;
    // PRCOUNT = 0

    message.nscount = 0;
    // UPCOUNT = ...

    // Host Description:
    //  * Delete all RRsets from <hostname>; remember the pointer to hostname
    //      NAME = hostname label followed by pointer to SOA name.
    //      TYPE = ANY
    //      CLASS = ANY
    //      TTL = 0
    //      RDLENGTH = 0
    dns_name_to_wire(&p_host_name, &txn, host_name); CH;
    dns_ptr_to_wire(&p_host_name, &txn, &p_zone_name); CH;
    dns_ui16_to_wire(&txn, dns_rrtype_any); CH;
    dns_ui16_to_wire(&txn, dns_qclass_none); CH;
    dns_ttl_to_wire(&txn, 0); CH;
    dns_ui16_to_wire(&txn, 0); CH;
    message.nscount++;
    //  * Add either or both of an A or AAAA RRset, each of which contains one
    //    or more A or AAAA RRs.
    //      NAME = pointer to hostname from Delete (above)
    //      TYPE = A or AAAA
    //      CLASS = IN
    //      TTL = 3600 ?
    //      RDLENGTH = number of RRs * RR length (4 or 16)
    //      RDATA = <the data>
    dns_ptr_to_wire(NULL, &txn, &p_host_name); CH;
    dns_ui16_to_wire(&txn, dns_rrtype_a); CH;
    dns_ui16_to_wire(&txn, dns_qclass_in); CH;
    dns_ttl_to_wire(&txn, 3600); CH;
    dns_rdlength_begin(&txn); CH;
    dns_rdata_a_to_wire(&txn, a_record); CH;
    dns_rdlength_end(&txn); CH;
    message.nscount++;
    
    dns_ptr_to_wire(NULL, &txn, &p_host_name); CH;
    dns_ui16_to_wire(&txn, dns_rrtype_aaaa); CH;
    dns_ui16_to_wire(&txn, dns_qclass_in); CH;
    dns_ttl_to_wire(&txn, 3600); CH;
    dns_rdlength_begin(&txn); CH;
    dns_rdata_aaaa_to_wire(&txn, aaaa_record); CH;
    dns_rdlength_end(&txn); CH;
    message.nscount++;
    
    //  * Exactly one KEY RR:
    //      NAME = pointer to hostname from Delete (above)
    //      TYPE = KEY
    //      CLASS = IN
    //      TTL = 3600
    //      RDLENGTH = length of key + 4 (32 bits)
    //      RDATA = <flags(16) = 0000 0010 0000 0001, protocol(8) = 3, algorithm(8) = 8?, public key(variable)>
    dns_ptr_to_wire(NULL, &txn, &p_host_name); CH;
    dns_ui16_to_wire(&txn, dns_rrtype_key); CH;
    dns_ui16_to_wire(&txn, dns_qclass_in); CH;
    dns_ttl_to_wire(&txn, 3600); CH;
    dns_rdlength_begin(&txn); CH;
    dns_rdata_key_to_wire(&txn, 0, 2, 1, 3, 8, public_key, public_key_len); CH;
    dns_rdlength_end(&txn); CH;
    message.nscount++;

    // Service Discovery:
    //   * Update PTR RR
    //     NAME = service name (_a._b.service.arpa)
    //     TYPE = PTR
    //     CLASS = IN
    //     TTL = 3600
    //     RDLENGTH = 2
    //     RDATA = service instance name
    dns_name_to_wire(&p_service_name, &txn, service_type); CH;
    dns_ptr_to_wire(&p_service_name, &txn, &p_zone_name); CH;
    dns_ui16_to_wire(&txn, dns_rrtype_ptr); CH;
    dns_ui16_to_wire(&txn, dns_qclass_in); CH;
    dns_ttl_to_wire(&txn, 3600); CH;
    dns_rdlength_begin(&txn); CH;
    dns_name_to_wire(&p_service_instance_name, &txn, host_name); CH;
    dns_ptr_to_wire(&p_service_instance_name, &txn, &p_service_name); CH;
    dns_rdlength_end(&txn); CH;
    message.nscount++;

    // Service Description:
    //   * Delete all RRsets from service instance name
    //      NAME = service instance name (save pointer to service name, which is the second label)
    //      TYPE = ANY
    //      CLASS = ANY
    //      TTL = 0
    //      RDLENGTH = 0
    dns_ptr_to_wire(NULL, &txn, &p_service_instance_name); CH;
    dns_ui16_to_wire(&txn, dns_rrtype_any); CH;
    dns_ui16_to_wire(&txn, dns_qclass_none); CH;
    dns_ttl_to_wire(&txn, 0); CH;
    dns_ui16_to_wire(&txn, 0); CH;
    message.nscount++;

    //   * Add one SRV RRset pointing to Host Description
    //      NAME = pointer to service instance name from above
    //      TYPE = SRV
    //      CLASS = IN
    //      TTL = 3600
    //      RDLENGTH = 8
    //      RDATA = <priority(16) = 0, weight(16) = 0, port(16) = service port, target = pointer to hostname>
    dns_ptr_to_wire(NULL, &txn, &p_service_instance_name); CH;
    dns_ui16_to_wire(&txn, dns_rrtype_srv); CH;
    dns_ui16_to_wire(&txn, dns_qclass_in); CH;
    dns_ttl_to_wire(&txn, 3600); CH;
    dns_rdlength_begin(&txn); CH;
    dns_ui16_to_wire(&txn, 0); // priority CH;
    dns_ui16_to_wire(&txn, 0); // weight CH;
    dns_ui16_to_wire(&txn, port); // port CH;
    dns_ptr_to_wire(NULL, &txn, &p_host_name); CH;
    dns_rdlength_end(&txn); CH;
    message.nscount++;

    //   * Add one or more TXT records
    //      NAME = pointer to service instance name from above
    //      TYPE = TXT
    //      CLASS = IN
    //      TTL = 3600
    //      RDLENGTH = <length of text>
    //      RDATA = <text>
    dns_ptr_to_wire(NULL, &txn, &p_service_instance_name); CH;
    dns_ui16_to_wire(&txn, dns_rrtype_txt); CH;
    dns_ui16_to_wire(&txn, dns_qclass_in); CH;
    dns_ttl_to_wire(&txn, 3600); CH;
    dns_rdlength_begin(&txn); CH;
    dns_rdata_txt_to_wire(&txn, txt_record); CH;
    dns_rdlength_end(&txn); CH;
    message.nscount++;
    message.nscount = htons(message.nscount);
    
    // What about services with more than one name?   Are these multiple service descriptions?

    // ADCOUNT = 2
    //   EDNS(0) options
    //     ...
    //   SIG(0)
    
    message.adcount = htons(1);
    dns_edns0_header_to_wire(&txn, DNS_MAX_UDP_PAYLOAD, 0, 0, 1); CH;	// XRCODE = 0; VERSION = 0; DO=1
    dns_rdlength_begin(&txn); CH;
    dns_ui16_to_wire(&txn, dns_opt_update_lease); CH;  // OPTION-CODE
    dns_edns0_option_begin(&txn); CH;                 // OPTION-LENGTH
    dns_ui32_to_wire(&txn, 3600); CH;                  // LEASE (1 hour)
    dns_ui32_to_wire(&txn, 604800); CH;                // KEY-LEASE (7 days)
    dns_edns0_option_end(&txn); CH;                   // Now we know OPTION-LENGTH
    dns_rdlength_end(&txn); CH;

    dns_sig0_signature_to_wire(&txn, 8, private_key, private_key_len, &p_host_name); CH;

    // Send the update
    if (dns_send_to_server(&txn, anycast_address, dns_response_callback) < 0) {
    fail:
        printf("dns_send_to_server failed: %s at line %d\n", strerror(txn.error), line);
    }
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
