/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2014-2017 Kumar Abhishek <abhishek@theembeddedkitchen.net>
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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef _WIN32
#define _WIN32_WINNT 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif
#include <errno.h>
#include "protocol.h"
#include "pina.h"

SR_PRIV int pina_tcp_receive_data(int fd, int revents, void *cb_data)
{
        const struct sr_dev_inst *sdi;
        struct dev_context *devc;
        struct sr_datafeed_packet packet;
        struct sr_datafeed_analog analog;
        struct sr_analog_encoding encoding;
        struct sr_analog_meaning meaning;
        struct sr_analog_spec spec;
        float data = 0.0f;

        int len;

        if (!(sdi = cb_data) || !(devc = sdi->priv))
                return TRUE;


        if (revents == G_IO_IN) {


                printf("RX DATA\n");

                sr_info("In callback G_IO_IN");

                len = recv(fd, devc->tcp_buffer, TCP_BUFFER_SIZE, 0);
                if (len < 0) {
                        sr_err("Receive error: %s", g_strerror(errno));
                        return SR_ERR;
                }
                else if (len == 4) {
		    data = *(float *)(devc->tcp_buffer);
		}

                sr_analog_init(&analog, &encoding, &meaning, &spec, 4);

                /* Configure data packet */
                packet.type = SR_DF_ANALOG;
                packet.payload = &analog;

                analog.data = &data;
                analog.num_samples = 1;
                analog.encoding = &encoding;
                analog.spec = &spec;
                analog.meaning = &meaning;

                // encoding
                encoding.unitsize = sizeof(float);
                encoding.is_float = TRUE;
                encoding.digits = 4;

                // meaning
                meaning.mq = SR_MQ_CURRENT;
                meaning.unit = SR_UNIT_AMPERE;
                meaning.mqflags = SR_MQFLAG_DC;
                meaning.channels = sdi->channels;

                // spec
                spec.spec_digits = 4;


               /* Send the incoming transfer to the session bus. */
               sr_session_send(sdi, &packet);

        }

std_session_send_df_end(sdi);
                devc->pina->stop(devc);

        return TRUE;
}
