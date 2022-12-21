/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2018-2020 Andreas Sandberg <andreas@sandberg.pp.se>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_PINA_PROTOCOL_H
#define LIBSIGROK_HARDWARE_PINA_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "pina"

#define TCP_BUFFER_SIZE         (16 * 16)

struct dev_context {
        /* Operations */
        const struct pina_ops *pina;

        /* TCP Settings */
        char *address;
        char *port;
        int socket;
        unsigned int read_timeout;
        unsigned char *tcp_buffer;

        /* Buffers: size of each buffer block and the total buffer area */
        uint32_t bufunitsize;
        uint32_t buffersize;

        /* Acquisition settings */
        uint64_t cur_samplerate;
        uint64_t limit_samples;
	uint32_t sampleunit;

        int fd;
        GPollFD pollfd;
        int last_error;

        uint64_t bytes_read;
        uint64_t sent_samples;
        uint32_t offset;
        uint8_t *sample_buf;    /* mmap'd kernel buffer here */

        gboolean trigger_fired;
};

SR_PRIV int pina_tcp_receive_data(int fd, int revents, void *cb_data);

#endif
