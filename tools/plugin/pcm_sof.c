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
#include <mqueue.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <assert.h>
#include <errno.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

#include <sof/sof.h>
#include <sof/audio/pipeline.h>
#include <sof/audio/component.h>
#include <ipc/stream.h>
#include <tplg_parser/topology.h>

#include "plugin.h"

static char *pipe_name = "/home/lrg/work/sof/sof/build_plugin/sof-pipe";

typedef struct snd_sof_pcm {
	snd_pcm_ioplug_t io;
	size_t frame_size;
	struct timespec wait_timeout;
	int capture;
	int copies;
	int events;

	/* PCM flow control */
	struct plug_lock ready;
	struct plug_lock done;

	struct plug_shm_context shm_ctx;
	struct plug_shm_context shm_pcm;

	struct plug_mq ipc;

} snd_sof_pcm_t;

static int plug_pcm_start(snd_pcm_ioplug_t * io)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct sof_ipc_stream stream = {0};
	int err;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	stream.hdr.size = sizeof(stream);
	stream.hdr.cmd = SOF_IPC_GLB_STREAM_MSG | SOF_IPC_STREAM_TRIG_START;
	//stream.comp_id =

	err = plug_ipc_cmd(&pcm->ipc, &stream, sizeof(stream), &stream, sizeof(stream));
	if (err < 0) {
		SNDERR("error: can't trigger START the PCM\n");
		return err;
	}

	return 0;
}

static int plug_pcm_stop(snd_pcm_ioplug_t * io)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct sof_ipc_stream stream = {0};
	int err;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	stream.hdr.size = sizeof(stream);
	stream.hdr.cmd = SOF_IPC_GLB_STREAM_MSG | SOF_IPC_STREAM_TRIG_STOP;
	//stream.comp_id =

	err = plug_ipc_cmd(&pcm->ipc, &stream, sizeof(stream), &stream, sizeof(stream));
	if (err < 0) {
		SNDERR("error: can't trigger STOP the PCM\n");
		return err;
	}
	return 0;
}

static int plug_pcm_drain(snd_pcm_ioplug_t * io)
{
	snd_sof_plug_t *plug = io->private_data;
	int err = 0;

	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	printf("%s %d\n", __func__, __LINE__);
	return err;
}

static int _called = 0;

/* buffer position up to buffer_size */
static snd_pcm_sframes_t plug_pcm_pointer(snd_pcm_ioplug_t *io)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct plug_context *ctx = pcm->shm_ctx.addr;
	snd_pcm_sframes_t ret = 0;
	int err;
	//printf("%s %d\n", __func__, __LINE__);
	_called++;
	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	if (io->state == SND_PCM_STATE_XRUN)
		return -EPIPE;

	if (io->state != SND_PCM_STATE_RUNNING)
		return 0;
#if 0
	if (plug->underrun)
		ret = -EPIPE;
	else
		ret = snd_pcm_bytes_to_frames(io->pcm, plug->ptr);

finish:
#endif

#if 0
	printf("plugin position %ld copies %d called %d pipe copies %ld\n",
				ctx->position, pcm->copies, _called, ctx->process_count);
#endif
	return ctx->position;
}

/* get the delay for the running PCM; optional; since v1.0.1 */
static int plug_pcm_delay(snd_pcm_ioplug_t * io, snd_pcm_sframes_t * delayp)
{
	snd_sof_plug_t *plug = io->private_data;
	int err = 0;

	printf("%s %d\n", __func__, __LINE__);
	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;
#if 0

	*delayp =
	    snd_pcm_bytes_to_frames(io->pcm,
				    read_delay_from_shm_context(plug));

	err = 0;

	if (plug->underrun && plug->io.state == SND_PCM_STATE_RUNNING)
		snd_pcm_ioplug_set_state(io, SND_PCM_STATE_XRUN);
#endif
	return err;
}

/* return frames written */
static snd_pcm_sframes_t plug_pcm_write(snd_pcm_ioplug_t *io,
				     const snd_pcm_channel_area_t *areas,
				     snd_pcm_uframes_t offset,
				     snd_pcm_uframes_t size)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct plug_context *ctx = pcm->shm_ctx.addr;
	struct timespec before, after;
	snd_pcm_sframes_t ret = 0;
	ssize_t bytes;
	const char *buf;
	int err;
	long ns;

	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	/* calculate the buffer position and size */
	buf = (char *)areas->addr + (areas->first + areas->step * offset) / 8;
	bytes = size * pcm->frame_size;

	/* write audio data to pipe */
	memcpy(pcm->shm_pcm.addr, buf, bytes);
	ctx->frames = size;

	/* tell the pipe data is ready */
	sem_post(pcm->ready.sem);

	/* wait for sof-pipe reader to consume data or timeout */
	err = clock_gettime(CLOCK_REALTIME, &pcm->wait_timeout);
	if (err == -1) {
		SNDERR("write: cant get time: %s", strerror(errno));
		return -EPIPE;
	}
	before = pcm->wait_timeout;

	plug_timespec_add_ms(&pcm->wait_timeout, 200);

	err = sem_timedwait(pcm->done.sem, &pcm->wait_timeout);
	if (err == -1) {
		SNDERR("write: fatal timeout: %s", strerror(errno));
		kill(plug->cpid, SIGTERM);
		return -EPIPE;
	}
	clock_gettime(CLOCK_REALTIME, &after);
	ctx->frame_ns = plug_timespec_delta_ns(&before, &after);

	pcm->copies++;
	return bytes / pcm->frame_size;
}

/* return frames read */
static snd_pcm_sframes_t plug_pcm_read(snd_pcm_ioplug_t *io,
				    const snd_pcm_channel_area_t *areas,
				    snd_pcm_uframes_t offset,
				    snd_pcm_uframes_t size)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct plug_context *ctx = pcm->shm_ctx.addr;
	snd_pcm_sframes_t ret = 0;
	ssize_t bytes;
	char *buf;
	int err;

	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	/* calculate the buffer position and size */
	buf = (char *)areas->addr + (areas->first + areas->step * offset) / 8;
	bytes = ctx->frames * pcm->frame_size;

	/* wait for sof-pipe reader to consume data or timeout */
	err = clock_gettime(CLOCK_REALTIME, &pcm->wait_timeout);
	if (err == -1) {
		SNDERR("write: cant get time: %s", strerror(errno));
		return -EPIPE;
	}

	plug_timespec_add_ms(&pcm->wait_timeout, 200);

	/* wait for sof-pipe writer to produce data or timeout */
	err = sem_timedwait(pcm->ready.sem, &pcm->wait_timeout);
	if (err == -1) {
		SNDERR("read: fatal timeout: %s", strerror(errno));
		kill(plug->cpid, SIGTERM);
		return -EPIPE;
	}

	/* write audio data to pipe */
	memcpy(buf, pcm->shm_pcm.addr, bytes);

	/* tell pipe that the data has been consumed */
	sem_post(pcm->done.sem);

	pcm->copies++;
	return ctx->frames;
}

static int plug_pcm_prepare(snd_pcm_ioplug_t * io)
{
	snd_sof_plug_t *plug = io->private_data;
	struct timespec ts;
	int err = 0;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	return err;
}

static int plug_pcm_hw_params(snd_pcm_ioplug_t * io,
			   snd_pcm_hw_params_t * params)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct sof_ipc_pcm_params ipc_params = {0};
	struct sof_ipc_pcm_params_reply params_reply = {0};
	struct ipc_comp_dev *pcm_dev;
	struct comp_dev *cd;
	int err = 0;

	printf("%s %d\n", __func__, __LINE__);
	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	/* set plug params */
	//ipc_params.comp_id = plug->pipeline->comp_id;
	ipc_params.params.buffer_fmt = SOF_IPC_BUFFER_INTERLEAVED; // TODO:
	ipc_params.params.rate = io->rate;
	ipc_params.params.channels = io->channels;
	printf("%s %d\n", __func__, __LINE__);
	switch (io->format) {
	case SND_PCM_FORMAT_S16_LE:
		ipc_params.params.frame_fmt = SOF_IPC_FRAME_S16_LE;
		ipc_params.params.sample_container_bytes = 2;
		ipc_params.params.sample_valid_bytes = 2;
		break;
	case SND_PCM_FORMAT_S24_LE:
		ipc_params.params.frame_fmt = SOF_IPC_FRAME_S24_4LE;
		ipc_params.params.sample_container_bytes = 4;
		ipc_params.params.sample_valid_bytes = 3;
		break;
	case SND_PCM_FORMAT_S32_LE:
		ipc_params.params.frame_fmt = SOF_IPC_FRAME_S32_LE;
		ipc_params.params.sample_container_bytes = 4;
		ipc_params.params.sample_valid_bytes = 4;
		break;
	default:
		SNDERR("SOF: Unsupported format %s\n",
			snd_pcm_format_name(io->format));
		return -EINVAL;
	}

	pcm->frame_size =
	    (snd_pcm_format_physical_width(io->format) * io->channels) / 8;

	ipc_params.params.host_period_bytes = io->period_size * pcm->frame_size;

	/* Set pipeline params direction from scheduling component */
	ipc_params.params.direction = io->stream;

	ipc_params.hdr.size = sizeof(ipc_params);
	ipc_params.hdr.cmd = SOF_IPC_GLB_STREAM_MSG | SOF_IPC_STREAM_PCM_PARAMS;

	err = plug_ipc_cmd(&pcm->ipc, &ipc_params, sizeof(ipc_params),
			   &params_reply, sizeof(params_reply));
	if (err < 0) {
		SNDERR("error: can't set PCM params\n");
		return err;
	}

	return err;
}

static int plug_pcm_sw_params(snd_pcm_ioplug_t *io, snd_pcm_sw_params_t *params)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	snd_pcm_uframes_t start_threshold;
	struct plug_context *ctx = pcm->shm_ctx.addr;
	int err;
	printf("%s %d\n", __func__, __LINE__);
	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	/* get the stream start threshold */
	err = snd_pcm_sw_params_get_start_threshold(params, &start_threshold);
	if (err < 0) {
		SNDERR("sw params: failed to get start threshold: %s", strerror(err));
		return err;
	}

	/* TODO: this seems to be ignored or overridden by application params ??? */
	if (start_threshold < io->period_size) {

		start_threshold = io->period_size;
		err = snd_pcm_sw_params_set_start_threshold(pcm->io.pcm,
							    params, start_threshold);
		if (err < 0) {
			SNDERR("sw params: failed to set start threshold %d: %s",
				start_threshold, strerror(err));
			return err;
		}
	}

	/* keep running as long as we can */
	err = snd_pcm_sw_params_set_avail_min(pcm->io.pcm, params, 1);
	if (err < 0) {
		SNDERR("sw params: failed to set avail min %d: %s",
			1, strerror(err));
		return err;
	}

	ctx->buffer_frames = io->buffer_size;
	return 0;
}

static int plug_pcm_close(snd_pcm_ioplug_t * io)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct plug_context *ctx = pcm->shm_ctx.addr;
	int err;

	printf("%s %d\n", __func__, __LINE__);

	if (--ctx->num_users <= 0)
		kill(plug->cpid, SIGTERM);

	err = plug_check_sofpipe_status(plug, 1);

	return err;
}

static int plug_pcm_poll_revents(snd_pcm_ioplug_t * io,
				  struct pollfd *pfd, unsigned int nfds,
				  unsigned short *revents)
{
	snd_sof_plug_t *plug = io->private_data;
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct plug_context *ctx = pcm->shm_ctx.addr;
	int err;

	printf("%s %d\n", __func__, __LINE__);

	err = plug_check_sofpipe_status(plug, 0);
	if (err)
		return err;

	if (pcm->copies != pcm->events) {
		*revents = io->stream == SND_PCM_STREAM_PLAYBACK ? POLLOUT : POLLIN;
		pcm->events = pcm->copies;
	} else
		*revents = 0;

	return err;
}

static const snd_pcm_ioplug_callback_t sof_playback_callback = {
	.start = plug_pcm_start,
	.stop = plug_pcm_stop,
	.drain = plug_pcm_drain,
	.pointer = plug_pcm_pointer,
	.transfer = plug_pcm_write,
	.delay = plug_pcm_delay,
	.prepare = plug_pcm_prepare,
	.hw_params = plug_pcm_hw_params,
	.sw_params = plug_pcm_sw_params,
	.poll_revents = plug_pcm_poll_revents,
	.close = plug_pcm_close,
};


static const snd_pcm_ioplug_callback_t sof_capture_callback = {
	.start = plug_pcm_start,
	.stop = plug_pcm_stop,
	.pointer = plug_pcm_pointer,
	.transfer = plug_pcm_read,
	.delay = plug_pcm_delay,
	.prepare = plug_pcm_prepare,
	.hw_params = plug_pcm_hw_params,
	.poll_revents = plug_pcm_poll_revents,
	.close = plug_pcm_close,
};

static const snd_pcm_access_t access_list[] = {
	SND_PCM_ACCESS_RW_INTERLEAVED
};

static const unsigned int formats[] = {
	SND_PCM_FORMAT_S16_LE,
	SND_PCM_FORMAT_FLOAT_LE,
	SND_PCM_FORMAT_S32_LE,
	SND_PCM_FORMAT_S24_LE,
};

/*
 * Set HW constraints for the SOF plugin. This needs to be quite unrestrictive atm
 * as we really need to parse topology before the HW constraints can be narrowed
 * to a range that will work with the specified pipeline.
 * TODO: Align with topology.
 */
static int plug_hw_constraint(snd_sof_plug_t * plug)
{
	snd_sof_pcm_t *pcm = plug->module_prv;
	snd_pcm_ioplug_t *io = &pcm->io;
	int err;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS,
					    ARRAY_SIZE(access_list),
					    access_list);
	if (err < 0) {
		SNDERR("constraints: failed to set access: %s", strerror(err));
		return err;
	}

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT,
					    ARRAY_SIZE(formats), formats);
	if (err < 0) {
		SNDERR("constraints: failed to set format: %s", strerror(err));
		return err;
	}

	err =
	    snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_CHANNELS,
					    1, 8);
	if (err < 0) {
		SNDERR("constraints: failed to set channels: %s", strerror(err));
		return err;
	}

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_RATE,
					      1, 192000);
	if (err < 0) {
		SNDERR("constraints: failed to set rate: %s", strerror(err));
		return err;
	}

	err =
	    snd_pcm_ioplug_set_param_minmax(io,
					    SND_PCM_IOPLUG_HW_BUFFER_BYTES,
					    1, 4 * 1024 * 1024);
	if (err < 0) {
		SNDERR("constraints: failed to set buffer bytes: %s", strerror(err));
		return err;
	}

	err =
	    snd_pcm_ioplug_set_param_minmax(io,
					    SND_PCM_IOPLUG_HW_PERIOD_BYTES,
					    128, 2 * 1024 * 1024);
	if (err < 0) {
		SNDERR("constraints: failed to set period bytes: %s", strerror(err));
		return err;
	}

	err =
	    snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS,
					   1, 4);
	if (err < 0) {
		SNDERR("constraints: failed to set period count: %s", strerror(err));
		return err;
	}

	return 0;
}

/*
 * Register the plugin with ALSA and make available for use.
 * TODO: setup all audio params
 * TODO: setup polling fd for RW or mmap IOs
 */
static int plug_create(snd_sof_plug_t *plug, snd_pcm_t **pcmp, const char *name,
		       snd_pcm_stream_t stream, int mode)
{
	snd_sof_pcm_t *pcm = plug->module_prv;
	int err;

	pcm->io.version = SND_PCM_IOPLUG_VERSION;
	pcm->io.name = "ALSA <-> SOF PCM I/O Plugin";
	pcm->io.poll_fd = pcm->shm_pcm.fd;
	pcm->io.poll_events = POLLIN;
	pcm->io.mmap_rw = 0;

	if (stream == SND_PCM_STREAM_PLAYBACK) {
		pcm->io.callback = &sof_playback_callback;
	} else {
		pcm->io.callback = &sof_capture_callback;
	}
	pcm->io.private_data = plug;

	/* create the plugin */
	err = snd_pcm_ioplug_create(&pcm->io, name, stream, mode);
	if (err < 0) {
		SNDERR("failed to register plugin %s: %s\n", name, strerror(err));
		return err;
	}

	/* set the HW constrainst */
	err = plug_hw_constraint(plug);
	if (err < 0) {
		snd_pcm_ioplug_delete(&pcm->io);
		return err;
	}

	*pcmp = pcm->io.pcm;
	return 0;
}

/* complete any init for the parent */
int plug_parent_complete_init(snd_sof_plug_t *plug, snd_pcm_t **pcmp,
		  	  	     const char *name, snd_pcm_stream_t stream, int mode)
{
	snd_sof_pcm_t *pcm = plug->module_prv;
	struct timespec delay;
	struct plug_context *ctx;
	int err;
	int tries = 10;

	delay.tv_sec = 0;
	delay.tv_nsec = 20 * 1000 * 1000;	/* 20 milliseconds */

	/* the SHM context file indicates the pipe is ready */
	while (tries--) {
		err = plug_open_mmap_regions(&pcm->shm_ctx);
		if (err == 0) {
			/* found */
			ctx = pcm->shm_ctx.addr;
			if (ctx->cpid == plug->cpid)
				goto next;
			munmap(pcm->shm_ctx.addr, pcm->shm_ctx.size);
			shm_unlink(pcm->shm_ctx.name);
		}

		/* give pipe more time to start */
		nanosleep(&delay, NULL);
	}
	SNDERR("timeout on opening pipe SHM context: %s", pcm->shm_ctx.name);
	return -ETIMEDOUT;

next:
	/* increment user count */
	ctx->num_users++;

	/* create pipe for audio data - TODO support mmap() */
	err = plug_ipc_open_lock(&pcm->ready);
	if (err < 0)
		goto error;

	/* create pipe for audio data - TODO support mmap() */
	err = plug_ipc_open_lock(&pcm->done);
	if (err < 0)
		goto error;

	err = plug_open_mmap_regions(&pcm->shm_pcm);
	if (err < 0)
		goto error;

	err = plug_open_ipc_queue(&pcm->ipc);
	if (err < 0)
		goto error;

	/* load the topology TDOD: add pipeline ID*/
	err = plug_parse_topology(&plug->tplg, &pcm->ipc, NULL, plug->tplg.pipeline_id);
	if (err < 0) {
		SNDERR("failed to parse topology: %s", strerror(err));
		goto error;
	}

	/* now register the plugin */
	err = plug_create(plug, pcmp, name, stream, mode);
	if (err < 0) {
		SNDERR("failed to create plugin: %s", strerror(err));
		goto error;
	}

	return 0;

error:
	ctx->num_users--;
	return err;
}

/*
 * ALSA PCM plugin entry point.
 */
SND_PCM_PLUGIN_DEFINE_FUNC(sof)
{
	snd_sof_plug_t *plug;
	snd_sof_pcm_t *pcm;
	int err;

	/* create context */
	plug = calloc(1, sizeof(*plug));
	if (!plug)
		return -ENOMEM;
	plug->newargv[plug->argc++] = pipe_name;

	pcm = calloc(1, sizeof(*pcm));
	if (!pcm) {
		free(plug);
		return -ENOMEM;
	}
	plug->module_prv = pcm;

	if (stream == SND_PCM_STREAM_CAPTURE)
		pcm->capture = 1;

	/* parse the ALSA configuration file for sof plugin */
	err = plug_parse_conf(plug, name, root, conf);
	if (err < 0) {
		SNDERR("failed to parse config: %s", strerror(err));
		goto pipe_error;
	}

	/* register interest in signals from child */
	err = plug_init_signals(plug);
	if (err < 0)
		goto signal_error;

	/* context args */
	plug_add_pipe_arg(plug, "t", plug->tplg.tplg_file);

	/* create message queue for IPC */
	err = plug_ipc_init_lock(&pcm->ready, plug->tplg.tplg_file, "ready");
	if (err < 0)
		goto ipc_error;
	err = plug_ipc_init_lock(&pcm->done, plug->tplg.tplg_file, "done");
	if (err < 0)
		goto ipc_error;

	/* create message queue for IPC */
	err = plug_ipc_init_queue(&pcm->ipc, plug->tplg.tplg_file, "pcm");
	if (err < 0)
		goto ipc_error;

	/* create a SHM mapping for low latency stream position */
	err = plug_ipc_init_shm(&pcm->shm_ctx, plug->tplg.tplg_file, "ctx");
	if (err < 0)
		goto ipc_error;

	err = plug_ipc_init_shm(&pcm->shm_pcm, plug->tplg.tplg_file, "pcm");
	if (err < 0)
		goto ipc_error;

	/* the pipeline runs in its own process context */
	plug->cpid = fork();
	if (plug->cpid < 0) {
		SNDERR("failed to fork for new pipeline: %s", strerror(errno));
		goto fork_error;
	}

	/* init flow diverges now depending if we are child or parent */
	if (plug->cpid == 0) {

		/* in child */
		plug_child_complete_init(plug, pcm->capture);

	} else {

		/* in parent */
		err = plug_parent_complete_init(plug, pcmp, name, stream, mode);
		if (err < 0) {
			SNDERR("failed to complete plugin init: %s", strerror(err));
			kill(plug->cpid, SIGTERM);
			plug_check_sofpipe_status(plug, 1);
			_exit(EXIT_FAILURE);
		}
	}

	/* everything is good */
	return 0;

	/* error cleanup */
fork_error:
	munmap(pcm->shm_ctx.addr, pcm->shm_ctx.size);
	//shm_unlink(pcm->shm_ctx.name);

signal_error:
	//mq_unlink(pcm->ipc.queue_name);
ipc_error:

pipe_error:
	free(plug->device);
dev_error:
	free(plug);
	return err;
}

SND_PCM_PLUGIN_SYMBOL(sof);
