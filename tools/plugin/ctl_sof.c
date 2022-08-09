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
	int subscribed;

} snd_sof_ctl_t;

/* number of ctls */
static int plug_ctl_elem_count(snd_ctl_ext_t *ext)
{
	snd_sof_ctl_t *ctl = ext->private_data;

	/* TODO: get count of elems from topology */
	return ctl->ctls.count;
}

static int plug_ctl_elem_list(snd_ctl_ext_t * ext, unsigned int offset,
			   snd_ctl_elem_id_t * id)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	struct snd_soc_tplg_ctl_hdr *hdr;

	printf("%s %d\n", __func__, __LINE__);

	if (offset >= ctls->count)
		return -EINVAL;

	hdr = ctls->tplg[offset];

	snd_ctl_elem_id_set_interface(id, SND_CTL_ELEM_IFACE_MIXER);
	snd_ctl_elem_id_set_name(id, hdr->name);

	return 0;
}

static snd_ctl_ext_key_t plug_ctl_find_elem(snd_ctl_ext_t * ext,
					 const snd_ctl_elem_id_t * id)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	const char *name;
	unsigned int numid;

	numid = snd_ctl_elem_id_get_numid(id);
	name = snd_ctl_elem_id_get_name(id);

	if (numid > ctls->count)
		return SND_CTL_EXT_KEY_NOT_FOUND;

	return numid - 1;
}

static int plug_ctl_get_attribute(snd_ctl_ext_t * ext, snd_ctl_ext_key_t key,
			       int *type, unsigned int *acc,
			       unsigned int *count)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	struct snd_soc_tplg_ctl_hdr *hdr = ctls->tplg[key];
	struct snd_soc_tplg_mixer_control *mixer_ctl;
	struct snd_soc_tplg_enum_control *enum_ctl;
	struct snd_soc_tplg_bytes_control *bytes_ctl;
	int err = 0;

	switch (hdr->type) {
	case SND_SOC_TPLG_CTL_VOLSW:
	case SND_SOC_TPLG_CTL_VOLSW_SX:
	case SND_SOC_TPLG_CTL_VOLSW_XR_SX:
		mixer_ctl = (struct snd_soc_tplg_mixer_control *)hdr;

		/* check for type - boolean should be binary values */
		if (mixer_ctl->max == 1 && mixer_ctl->min == 0)
			*type = SND_CTL_ELEM_TYPE_BOOLEAN;
		else
			*type = SND_CTL_ELEM_TYPE_INTEGER;
		*count = 2;//mixer_ctl->num_channels; ///// WRONG is 0 !!!

		//printf("mixer %d %d\n", __LINE__, mixer_ctl->num_channels);
		break;
	case SND_SOC_TPLG_CTL_ENUM:
	case SND_SOC_TPLG_CTL_ENUM_VALUE:
		enum_ctl = (struct snd_soc_tplg_enum_control *)hdr;
		*type = SND_CTL_ELEM_TYPE_ENUMERATED;
		*count = enum_ctl->num_channels;
		break;
	case SND_SOC_TPLG_CTL_RANGE:
	case SND_SOC_TPLG_CTL_STROBE:
		// TODO: ??
		break;
	case SND_SOC_TPLG_CTL_BYTES:
		printf("%s %d\n", __func__, __LINE__);
		bytes_ctl = (struct snd_soc_tplg_bytes_control *)hdr;
		*type = SND_CTL_ELEM_TYPE_BYTES;
		*count = 1;  //TODO - size ?
		break;
	}

	*acc = hdr->access;

	/* access needs the callback to decode the data */
	if (hdr->access & SND_CTL_EXT_ACCESS_TLV_READ ||
	    hdr->access & SND_CTL_EXT_ACCESS_TLV_WRITE)
		*acc |= SND_CTL_EXT_ACCESS_TLV_CALLBACK;
	return err;
}

/*
 * Integer ops
 */
static int plug_ctl_get_integer_info(snd_ctl_ext_t * ext,
				  snd_ctl_ext_key_t key, long *imin,
				  long *imax, long *istep)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	struct snd_soc_tplg_ctl_hdr *hdr = ctls->tplg[key];
	struct snd_soc_tplg_mixer_control *mixer_ctl =
			(struct snd_soc_tplg_mixer_control *)hdr;
	int err = 0;

	//printf("%s %d\n", __func__, __LINE__);

	switch (hdr->type) {
	case SND_SOC_TPLG_CTL_VOLSW:
	case SND_SOC_TPLG_CTL_VOLSW_SX:
	case SND_SOC_TPLG_CTL_VOLSW_XR_SX:
		/* TLV uses the fields differently */
		if (hdr->access & SND_CTL_EXT_ACCESS_TLV_READ ||
		    hdr->access & SND_CTL_EXT_ACCESS_TLV_WRITE) {
			*istep = mixer_ctl->hdr.tlv.scale.step;
			*imin = (int32_t)mixer_ctl->hdr.tlv.scale.min;
			*imax = mixer_ctl->max;
		} else {
			*istep = 1;
			*imin = mixer_ctl->min;
			*imax = mixer_ctl->max;
		}
		break;
	default:
		SNDERR("invalid ctl type for integer using key %d", key);
		err = -EINVAL;
		break;
	}

	return err;
}

static int plug_ctl_read_integer(snd_ctl_ext_t * ext, snd_ctl_ext_key_t key,
			      long *value)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct sof_ipc_ctrl_data ctl_data = {0};
	int err;

	//printf("%s %d\n", __func__, __LINE__);

	err = plug_ipc_cmd(&ctl->ipc, &ctl_data, sizeof(ctl_data),
			   &ctl_data, sizeof(ctl_data));
	if (err < 0) {
		SNDERR("error: can't read CTL\n");
		return err;
	}

	*value = 0; // TODO array based on channels;

	return err;
}

static int plug_ctl_write_integer(snd_ctl_ext_t * ext, snd_ctl_ext_key_t key,
			       long *value)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct sof_ipc_ctrl_data ctl_data = {0};
	int err;

	//printf("%s %d\n", __func__, __LINE__);
	err = plug_ipc_cmd(&ctl->ipc, &ctl_data, sizeof(ctl_data),
			   &ctl_data, sizeof(ctl_data));
	if (err < 0) {
		SNDERR("error: can't write CTL\n");
		return err;
	}

	return err;
}

/*
 * Enum ops
 */
static int plug_ctl_get_enumerated_info(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
		unsigned int *items)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	struct snd_soc_tplg_ctl_hdr *hdr = ctls->tplg[key];
	struct snd_soc_tplg_enum_control *enum_ctl =
			(struct snd_soc_tplg_enum_control *)hdr;
	int err = 0;

	//printf("%s %d\n", __func__, __LINE__);

	switch (hdr->type) {
	case SND_SOC_TPLG_CTL_ENUM:
	case SND_SOC_TPLG_CTL_ENUM_VALUE:
		*items = enum_ctl->items;
		break;
	default:
		SNDERR("invalid ctl type for enum using key %d", key);
		err = -EINVAL;
		break;
	}

	return err;
}

static int plug_ctl_get_enumerated_name(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
					unsigned int item, char *name, size_t name_max_len)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	struct snd_soc_tplg_ctl_hdr *hdr = ctls->tplg[key];
	struct snd_soc_tplg_enum_control *enum_ctl =
			(struct snd_soc_tplg_enum_control *)hdr;
	int err = 0;

	//printf("%s %d\n", __func__, __LINE__);

	if (item >= enum_ctl->count) {
		SNDERR("invalid item %d for enum using key %d", item, key);
		return -EINVAL;
	}

	strncpy(name, enum_ctl->texts[item], name_max_len);
	return 0;
}

static int plug_ctl_read_enumerated(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
				    unsigned int *items)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct sof_ipc_ctrl_data ctl_data = {0};
	int err;

	//printf("%s %d\n", __func__, __LINE__);
	err = plug_ipc_cmd(&ctl->ipc, &ctl_data, sizeof(ctl_data),
			   &ctl_data, sizeof(ctl_data));
	if (err < 0) {
		SNDERR("error: can't write CTL\n");
		return err;
	}

	return err;
}

static int plug_ctl_write_enumerated(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
				     unsigned int *items)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct sof_ipc_ctrl_data ctl_data = {0};
	int err;

	//printf("%s %d\n", __func__, __LINE__);
	err = plug_ipc_cmd(&ctl->ipc, &ctl_data, sizeof(ctl_data),
			   &ctl_data, sizeof(ctl_data));
	if (err < 0) {
		SNDERR("error: can't write CTL\n");
		return err;
	}

	return err;
}

/*
 * Bytes ops
 */

static int plug_ctl_read_bytes(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
			       unsigned char *data, size_t max_bytes)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	struct snd_soc_tplg_ctl_hdr *hdr;
	struct snd_soc_tplg_bytes_control *bytes = (struct snd_soc_tplg_bytes_control *)hdr;
	struct sof_ipc_ctrl_data ctl_data = {0};
	int err;

	//printf("%s %d\n", __func__, __LINE__);
	err = plug_ipc_cmd(&ctl->ipc, &ctl_data, sizeof(ctl_data),
			   &ctl_data, sizeof(ctl_data));
	if (err < 0) {
		SNDERR("error: can't write CTL\n");
		return err;
	}

	return err;
}

static int plug_ctl_write_bytes(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
				unsigned char *data, size_t max_bytes)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	struct snd_soc_tplg_ctl_hdr *hdr;
	struct snd_soc_tplg_bytes_control *bytes = (struct snd_soc_tplg_bytes_control *)hdr;
	struct sof_ipc_ctrl_data ctl_data = {0};
	int err;

	//printf("%s %d\n", __func__, __LINE__);
	err = plug_ipc_cmd(&ctl->ipc, &ctl_data, sizeof(ctl_data),
			   &ctl_data, sizeof(ctl_data));
	if (err < 0) {
		SNDERR("error: can't write CTL\n");
		return err;
	}

	return err;
}

/*
 * TLV ops
 *
 * The format of an array of \a tlv argument is:
 *   tlv[0]:   Type. One of SND_CTL_TLVT_XXX.
 *   tlv[1]:   Length. The length of value in units of byte.
 *   tlv[2..]: Value. Depending on the type.
 */
static int plug_tlv_rw(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key, int op_flag,
		       unsigned int numid, unsigned int *tlv, unsigned int tlv_size)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	struct snd_soc_tplg_ctl_hdr *hdr;
	struct snd_soc_tplg_mixer_control *mixer_ctl;
	int err = 0;

	//printf("%s %d\n", __func__, __LINE__);
	hdr = ctls->tplg[key];

	//TODO: alsamixer showing wrong dB scales
	tlv[0] = hdr->tlv.type;
	tlv[1] = hdr->tlv.size - sizeof(uint32_t) * 2;
	memcpy(&tlv[2], hdr->tlv.data, hdr->tlv.size - sizeof(uint32_t) * 2);

	return 0;
}

static void plug_ctl_subscribe_events(snd_ctl_ext_t * ext, int subscribe)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	//printf("%s %d\n", __func__, __LINE__);

	ctl->subscribed = !!(subscribe & SND_CTL_EVENT_MASK_VALUE);
}

static int plug_ctl_read_event(snd_ctl_ext_t * ext, snd_ctl_elem_id_t * id,
			    unsigned int *event_mask)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	int numid;
	int err = 0;
//	printf("%s %d\n", __func__, __LINE__);

	numid = snd_ctl_elem_id_get_numid(id);

	// TODO: we need a notify() or listening thread to take async/volatile ctl
	// notifications from sof-pipe and notify userspace via events of the ctl change.
	if (!ctls->updated[numid - 1] || !ctl->subscribed) {
		err = -EAGAIN;
		goto out;
	}

	*event_mask = SND_CTL_EVENT_MASK_VALUE;
out:
	return err;
}

static int plug_ctl_poll_revents(snd_ctl_ext_t * ext, struct pollfd *pfd,
				  unsigned int nfds,
				  unsigned short *revents)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	int err, i;
	//printf("%s %d\n", __func__, __LINE__);

	*revents = 0;

	for (i = 0; i < ctls->count; i++) {
		if (ctls->updated[i]) {
			*revents = POLLIN;
			break;
		}
	}

	return 0;
}

static void plug_ctl_close(snd_ctl_ext_t * ext)
{
	snd_sof_ctl_t *ctl = ext->private_data;
	struct plug_ctl *ctls = &ctl->ctls;
	int i;

	//printf("%s %d\n", __func__, __LINE__);
	for (i = 0; i < ctls->count; i++)
		free(ctls->tplg[i]);

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
	.get_enumerated_info = plug_ctl_get_enumerated_info,
	.get_enumerated_name = plug_ctl_get_enumerated_name,
	.read_enumerated = plug_ctl_read_enumerated,
	.write_enumerated = plug_ctl_write_enumerated,
	.read_bytes = plug_ctl_read_bytes,
	.write_bytes = plug_ctl_write_bytes,
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

	/* load the topology TDOD: add pipeline ID*/
	err = plug_parse_topology(&plug->tplg, &ctl->ipc, &ctl->ctls, plug->tplg.pipeline_id);
	if (err < 0) {
		SNDERR("failed to parse topology: %s", strerror(err));
		goto error;
	}

	/* TODO: add some flavour to the names based on the topology */
	ctl->ext.version = SND_CTL_EXT_VERSION;
	ctl->ext.card_idx = 0;
	strncpy(ctl->ext.id, "sof", sizeof(ctl->ext.id) - 1);
	strncpy(ctl->ext.driver, "SOF plugin",
		sizeof(ctl->ext.driver) - 1);
	strncpy(ctl->ext.name, "SOF", sizeof(ctl->ext.name) - 1);
	strncpy(ctl->ext.longname, plug->tplg.tplg_file,
		sizeof(ctl->ext.longname) - 1);
	strncpy(ctl->ext.mixername, "SOF",
		sizeof(ctl->ext.mixername) - 1);

	/* polling on message queue - supported on Linux but not portable */
	ctl->ext.poll_fd = ctl->ipc.mq;

	ctl->ext.callback = &sof_ext_callback;
	ctl->ext.private_data = ctl;
	ctl->ext.tlv.c = plug_tlv_rw;

	err = snd_ctl_ext_create(&ctl->ext, name, mode);
	if (err < 0)
		goto error;

	*handlep = ctl->ext.handle;

	return 0;

error:
	free(ctl);

	return err;
}

SND_CTL_PLUGIN_SYMBOL(sof);
