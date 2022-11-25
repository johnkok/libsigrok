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


#include <config.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"
#include "protocol.h"
#include "pina.h"

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
};

static const uint32_t drvopts[] = {
	SR_CONF_ENERGYMETER,
};

static const uint32_t devopts[] = {
	SR_CONF_CONTINUOUS,
};

static GSList *pina_scan(struct sr_dev_driver *di, GSList *options)
{
	GSList *l = NULL;
        const char *conn;
        gchar **params;
        struct sr_config *src;
	struct dev_context *devc = NULL;
	struct sr_dev_inst *sdi = NULL;

        for (l = options; l; l = l->next) {
                src = l->data;
                if (src->key == SR_CONF_CONN)
                        conn = g_variant_get_string(src->data, NULL);
        }


	devc = g_malloc0(sizeof(struct dev_context));
	sdi = g_malloc0(sizeof(struct sr_dev_inst));

        devc->fd = -1;
        devc->tcp_buffer = 0;
        devc->pina = &pina_tcp_ops;

        if (conn)
        {
            params = g_strsplit(conn, "/", 0);
            if (!params || !params[1] || !params[2]) {
                sr_err("Invalid Parameters.");
                g_strfreev(params);
                return NULL;
            }
            if (g_ascii_strncasecmp(params[0], "tcp", 3)) {
                sr_err("Only TCP (tcp-raw) protocol is currently supported.");
                g_strfreev(params);
                return NULL;
            }
        }

        sdi->status = SR_ST_INACTIVE;
        sdi->vendor = g_strdup("ioko");
        sdi->model = g_strdup("INA228");
        sdi->version = g_strdup("1.0");

        if (conn)
        {
            devc->read_timeout = 1000*1000;
            devc->address = g_strdup(params[1]);
            devc->port = g_strdup(params[2]);
            g_strfreev(params);

            if (devc->pina->open(devc) != SR_OK)
                goto err_free;
            if (pina_tcp_detect(devc) != SR_OK)
                goto err_free;
            if (devc->pina->close(devc) != SR_OK)
                goto err_free;
            sr_info("Pina device found at %s : %s",
                devc->address, devc->port);
        }

        sr_channel_new(sdi, 0, SR_CHANNEL_ANALOG, TRUE, "CH1");

        sdi->priv = devc;

        printf("Scan done!");

	return std_scan_complete(di, g_slist_append(NULL, sdi));

err_free:
        g_free(devc);
        g_free(sdi);

	return NULL;
}

static int pina_dev_config_get(uint32_t key, GVariant **data,
        const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
        struct dev_context *devc = sdi->priv;

        printf("Get config called %X\n", key);
        return SR_OK;
}

static int pina_dev_config_set(uint32_t key, GVariant **data,
        const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
        struct dev_context *devc = sdi->priv;

        return SR_OK;
}

static int pina_dev_acquisition_start(struct sr_dev_inst *sdi)
{
        struct dev_context *devc = sdi->priv;
        GSList *l;

        /* Clear capture state */
        devc->bytes_read = 0;
        devc->offset = 0;

        std_session_send_df_header(sdi);

        /* Trigger and add poll on file */
        devc->pina->start(devc);


        sr_session_source_add_pollfd(sdi->session, &devc->pollfd,
            1, pina_tcp_receive_data,
            (void *)sdi);

        return SR_OK;
}

static int pina_dev_acquisition_stop(struct sr_dev_inst *sdi)
{
        struct dev_context *devc = sdi->priv;

        devc->pina->stop(devc);
        pina_tcp_drain(devc);

        sr_session_source_remove_pollfd(sdi->session, &devc->pollfd);
        std_session_send_df_end(sdi);

        return SR_OK;
}

static int config_list(uint32_t key, GVariant **data,
		       const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
}

static int dev_open(struct sr_dev_inst *sdi)
{
        struct dev_context *devc = sdi->priv;

        if (devc->pina->open(devc))
                return SR_ERR;

        /* Set fd and local attributes */
        devc->pollfd.fd = devc->socket;
        devc->pollfd.events = G_IO_IN;
        devc->pollfd.revents = 0;

        /* Map the kernel capture FIFO for reads, saves 1 level of memcpy */
        devc->tcp_buffer = g_malloc(TCP_BUFFER_SIZE);

        return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
        struct dev_context *devc = sdi->priv;

        /* Close the memory mapping and the file */
        devc->pina->close(devc);

        return SR_OK;
}

static struct sr_dev_driver pina_driver_info = {
	.name = "pina",
	.longname = "Rasberry pico w INA228 power meter",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = pina_scan,
	.dev_list = std_dev_list,
	.dev_clear = std_dev_clear,
	.config_get = pina_dev_config_get,
	.config_set = pina_dev_config_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
        .dev_acquisition_start = pina_dev_acquisition_start,
        .dev_acquisition_stop = pina_dev_acquisition_stop,
	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(pina_driver_info);
