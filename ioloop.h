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
 * Definitions for simple dispatch implementation.
 */

typedef union addr addr_t;
union addr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

typedef struct message message_t;
struct message {
    addr_t src;
    int ifindex;
    size_t length;
    dns_wire_t wire;
};

typedef struct comm comm_t;
typedef void (*read_callback_t)(comm_t *NONNULL comm);
typedef void (*write_callback_t)(comm_t *NONNULL comm);
typedef void (*datagram_callback_t)(comm_t *NONNULL comm);
typedef void (*close_callback_t)(comm_t *NONNULL comm);
struct comm {
    comm_t *NULLABLE next;
    char *NONNULL name;
    read_callback_t NONNULL read_callback;
    write_callback_t NULLABLE write_callback;
    datagram_callback_t NONNULL datagram_callback;
    close_callback_t NULLABLE close_callback;
    message_t *NULLABLE message;
    uint8_t *NULLABLE buf;
    addr_t address;
    size_t message_length_len;
    size_t message_length, message_cur;
    int sock;
    uint8_t message_length_bytes[2];
    bool want_read : 1;
    bool want_write : 1;
};

message_t *NULLABLE message_allocate(size_t message_size);
void message_free(message_t *NONNULL message);
void comm_free(comm_t *NONNULL comm);
void add_reader(comm_t *NONNULL comm, read_callback_t NONNULL callback);
bool dispatch_init(void);
int dispatch_events(struct timespec *NONNULL timeout);
bool setup_listener_socket(int family, int protocol, const char *NONNULL name,
			   datagram_callback_t NONNULL datagram_callback);

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
