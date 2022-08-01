// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2022 Intel Corporation. All rights reserved.
//
// Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>

#include <stdio.h>
#include <sys/poll.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <mqueue.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <assert.h>
#include <errno.h>

#include <alsa/asoundlib.h>

#include <sof/sof.h>
#include <sof/audio/pipeline.h>
#include <sof/audio/component.h>
#include <ipc/stream.h>
#include <tplg_parser/topology.h>
#include <alsa/control_external.h>

#include "plugin.h"

typedef struct snd_sof_ctl {
	struct plug_ctl ctls;
	snd_ctl_ext_t ext;
	struct plug_mq ipc;
	struct plug_shm_context shm_ctx;
} snd_sof_ctl_t;

static int sof_update_volume(snd_sof_ctl_t *ctl)
{
	int err;

	printf("%s %d\n", __func__, __LINE__);

	return 0;
}

static int plug_ctl_elem_count(snd_ctl_ext_t *ext)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	int count = 0, err;
	printf("%s %d\n", __func__, __LINE__);

	/* TODO: get count of elems from topology */
	return count;
}

static int plug_ctl_elem_list(snd_ctl_ext_t * ext, unsigned int offset,
			   snd_ctl_elem_id_t * id)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	int err;
	printf("%s %d\n", __func__, __LINE__);


	snd_ctl_elem_id_set_interface(id, SND_CTL_ELEM_IFACE_MIXER);
	snd_ctl_elem_id_set_name(id, "Name from topology");

	return err;
}

static snd_ctl_ext_key_t plug_ctl_find_elem(snd_ctl_ext_t * ext,
					 const snd_ctl_elem_id_t * id)
{
	const char *name;
	unsigned int numid;

	printf("%s %d\n", __func__, __LINE__);

	numid = snd_ctl_elem_id_get_numid(id);
	name = snd_ctl_elem_id_get_name(id);

	if (strcmp(name, "sof_name") == 0)
		return 1;

	return SND_CTL_EXT_KEY_NOT_FOUND;
}

static int plug_ctl_get_attribute(snd_ctl_ext_t * ext, snd_ctl_ext_key_t key,
			       int *type, unsigned int *acc,
			       unsigned int *count)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	int err = 0;
	printf("%s %d\n", __func__, __LINE__);


	if (key & 1)
		*type = SND_CTL_ELEM_TYPE_BOOLEAN;
	else
		*type = SND_CTL_ELEM_TYPE_INTEGER;

	*acc = SND_CTL_EXT_ACCESS_READWRITE;

//	if (key == 0)
//		*count = ctl->source_volume.channels;

	return err;
}

static int plug_ctl_get_integer_info(snd_ctl_ext_t * ext,
				  snd_ctl_ext_key_t key, long *imin,
				  long *imax, long *istep)
{
	printf("%s %d\n", __func__, __LINE__);
	*istep = 1;
	*imin = 0;
	*imax = 0;

	return 0;
}

static int plug_ctl_read_integer(snd_ctl_ext_t * ext, snd_ctl_ext_key_t key,
			      long *value)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	int err = 0, i;

	printf("%s %d\n", __func__, __LINE__);

	return err;
}

static int plug_ctl_write_integer(snd_ctl_ext_t * ext, snd_ctl_ext_key_t key,
			       long *value)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	int err = 0, i;

	printf("%s %d\n", __func__, __LINE__);

	return err;
}

static void plug_ctl_subscribe_events(snd_ctl_ext_t * ext, int subscribe)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	printf("%s %d\n", __func__, __LINE__);

	//ctl->subscribed = !!(subscribe & SND_CTL_EVENT_MASK_VALUE);
}

static int plug_ctl_read_event(snd_ctl_ext_t * ext, snd_ctl_elem_id_t * id,
			    unsigned int *event_mask)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	int offset;
	int err;
	printf("%s %d\n", __func__, __LINE__);

	*event_mask = SND_CTL_EVENT_MASK_VALUE;

	return err;
}

static int plug_ctl_poll_revents(snd_ctl_ext_t * ext, struct pollfd *pfd,
				  unsigned int nfds,
				  unsigned short *revents)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	int err;
	printf("%s %d\n", __func__, __LINE__);

#if 0
	if (ctl->updated)
		*revents = POLLIN;
	else
		*revents = 0;
#endif
	return 0;
}

static void plug_ctl_close(snd_ctl_ext_t * ext)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	printf("%s %d\n", __func__, __LINE__);

	free(ctl);
}

static const snd_ctl_ext_callback_t sof_ext_callback = {
	.elem_count = plug_ctl_elem_count,
	.elem_list = plug_ctl_elem_list,
	.find_elem = plug_ctl_find_elem,
	.get_attribute = plug_ctl_get_attribute,
	.get_integer_info = plug_ctl_get_integer_info,
	.read_integer = plug_ctl_read_integer,
	.write_integer = plug_ctl_write_integer,
	.subscribe_events = plug_ctl_subscribe_events,
	.read_event = plug_ctl_read_event,
	.poll_revents = plug_ctl_poll_revents,
	.close = plug_ctl_close,
};

SND_CTL_PLUGIN_DEFINE_FUNC(sof)
{
	snd_sof_plug_t *plug;
	snd_config_iterator_t i, next;
	int err;
	snd_sof_ctl_t *ctl;

	/* create context */
	plug = calloc(1, sizeof(*plug));
	if (!plug)
		return -ENOMEM;

	ctl = calloc(1, sizeof(*ctl));
	if (!ctl)
		return -ENOMEM;
	plug->module_prv = ctl;

	/* parse the ALSA configuration file for sof plugin */
	err = plug_parse_conf(plug, name, root, conf);
	if (err < 0) {
		SNDERR("failed to parse config: %s", strerror(err));
		goto error;
	}

	/* create message queue for IPC */
	err = plug_ipc_init_queue(&ctl->ipc, plug->tplg.tplg_file, "ctl");
	if (err < 0)
		goto error;

	/* open message queue for IPC */
	err = plug_open_ipc_queue(&ctl->ipc);
	if (err < 0) {
		SNDERR("failed to open IPC message queue: %s", strerror(err));
		SNDERR("The PCM needs to be open for mixers to connect to pipeline");
		goto error;
	}

	/* create a SHM mapping for low latency stream position */
	err = plug_ipc_init_shm(&ctl->shm_ctx, plug->tplg.tplg_file, "ctx");
	if (err < 0)
		goto error;

	/* create a SHM mapping for low latency stream position */
	err = plug_open_mmap_regions(&ctl->shm_ctx);
	if (err < 0)
		goto error;

	ctl->ext.version = SND_CTL_EXT_VERSION;
	ctl->ext.card_idx = 0;
	strncpy(ctl->ext.id, "sof", sizeof(ctl->ext.id) - 1);
	strncpy(ctl->ext.driver, "SOF plugin",
		sizeof(ctl->ext.driver) - 1);
	strncpy(ctl->ext.name, "SOF", sizeof(ctl->ext.name) - 1);
	strncpy(ctl->ext.longname, "SOF",
		sizeof(ctl->ext.longname) - 1);
	strncpy(ctl->ext.mixername, "SOF",
		sizeof(ctl->ext.mixername) - 1);
//	ctl->ext.poll_fd = ctl->p->main_fd;

	ctl->ext.callback = &sof_ext_callback;
	ctl->ext.private_data = ctl;
	printf("%s %d\n", __func__, __LINE__);
	err = snd_ctl_ext_create(&ctl->ext, name, mode);
	if (err < 0)
		goto error;
	printf("%s %d\n", __func__, __LINE__);
	*handlep = ctl->ext.handle;

	return 0;

error:
	free(ctl);

	return err;
}

SND_CTL_PLUGIN_SYMBOL(sof);
