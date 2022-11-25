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

#ifndef BEAGLELOGIC_H_
#define BEAGLELOGIC_H_

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>

/* For all the functions below:
 * Parameters:
 * 	devc : Device context structure to operate on
 * Returns:
 * 	SR_OK or SR_ERR
 */

struct pina_ops {
        /* Open and close device */
	int (*open)(struct dev_context *devc);
	int (*close)(struct dev_context *devc);

        /* Start and stop the capture operation */
        int (*start)(struct dev_context *devc);
        int (*stop)(struct dev_context *devc);

	int (*mmap)(struct dev_context *devc);
	int (*munmap)(struct dev_context *devc);
};

SR_PRIV extern const struct pina_ops pina_tcp_ops;

SR_PRIV int pina_tcp_detect(struct dev_context *devc);
SR_PRIV int pina_tcp_drain(struct dev_context *devc);

#endif
