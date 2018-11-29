/* sign.c
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
 * DNS SIG(0) signature generation for DNSSD SRP using mbedtls.
 *
 * Functions required for loading, saving, and generating public/private keypairs, extracting the public key
 * into KEY RR data, and computing signatures.
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "dns-msg.h"

// Key is stored in an opaque data structure, for mbedtls this is an mbedtls_pk_context.
// Function to generate a key
// Function to write a keypair to a file
// Function to copy out the public key as binary data
// Function to get the length of the public key
// Function to generate a signature given some data and a public key
// Function to read a public key from a KEY record
// Function to validate a signature given some data and a public key (not required on client)

typedef mbedtls_pk_context srp_key_t;

// Function to free a key
void
free_keypair(srp_key_t *context)
{
    mbedtls_pk_free(context);
    free(context);
}

// Function to read a keypair from a file
srp_key_t *
load_keypair(const char *file)
{
    int fd = open("srp.key", O_RDONLY);
    unsigned char buf[256];
    ssize_t rv;
    mbedtls_pk_context *context;
    int status;

    if (fd < 0) {
        if (errno != ENOENT) {
            ERROR("Unable to open srp.key: %s", strerror(errno));
            return NULL;
        }
    }        

    // The key is of limited size, so there's no reason to get fancy.
    rv = read(fd, buf, sizeof buf);
    close(fd);
    if (rv == sizeof buf) {
        ERROR("key file is unreasonably large.");
        return NULL;
    }

    context = calloc(sizeof *context, 1);
    if (context == NULL) {
        ERROR("no memory for key.");
        return NULL;
    }

    status = mbedtls_pk_init(ctx);
    if (status != 0) {
        ERROR("mbedtls_pk_init failed: %d", status);
        free(context);
        return NULL;
    }

    status = mbedtls_pk_parse_key(context, buf, rv, NULL, 0);
    if (status != 0) {
        ERROR("mbedtls_pk_parse_key failed: %d", status);
        free_keypair(context);
        return NULL;
    }

    if (!mbedtls_pk_can_do(context, MBEDTLS_PK_ECDSA)) {
        ERROR("%s does not contain a usable ECDSA key.", file);
        mbedtls_pk_free(context);
        free(context);
        return NULL;
    }
    return context;
}



// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
