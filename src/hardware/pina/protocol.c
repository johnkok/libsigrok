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

static const struct binary_analog_channel pina_default_channels[] = {
        { "I",     { 4, BVT_LE_FLOAT, 1.0, }, 6, SR_MQ_CURRENT, SR_UNIT_AMPERE },
	{ "Vbus",  { 8, BVT_LE_FLOAT, 1.0, }, 4, SR_MQ_VOLTAGE, SR_UNIT_VOLT },
        ALL_ZERO,
};

SR_PRIV int pina_tcp_receive_data(int fd, int revents, void *cb_data)
{
        const struct sr_dev_inst *sdi;
        struct dev_context *devc;
        struct sr_datafeed_packet packet;
	struct sr_datafeed_logic logic;
        int len;
        GSList *ch;

        if (!(sdi = cb_data) || !(devc = sdi->priv))
                return TRUE;


        if (revents == G_IO_IN) {
                sr_info("In callback G_IO_IN");

                len = recv(fd, devc->tcp_buffer, TCP_BUFFER_SIZE, 0);
                if (len < 0) {
                        sr_err("Receive error: %s", g_strerror(errno));
                        return SR_ERR;
                }
                else if (len == 16) {
                    ch = sdi->channels;
                    bv_send_analog_channel(sdi, ch->data,
                                       &pina_default_channels[0],
				       devc->tcp_buffer, 16);
                    ch = g_slist_next(ch);
	            bv_send_analog_channel(sdi, ch->data,
                                       &pina_default_channels[1],
				       devc->tcp_buffer, 16);

		    // Send logic channel
                    packet.type = SR_DF_LOGIC;
                    packet.payload = &logic;
		    logic.unitsize = 1;
                    logic.data = &devc->tcp_buffer[12];
		    logic.length = 1;
		    sr_session_send(sdi, &packet);
//		    devc->offset++;
//		    std_session_send_df_end(sdi);

		}
	}
        
	return TRUE;
}
