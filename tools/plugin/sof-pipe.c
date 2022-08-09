// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2022 Intel Corporation. All rights reserved.
//
// Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>

/*
 * SOF pipeline in userspace.
 */

#define _GNU_SOURCE

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
#include <pthread.h>
#include <limits.h>
#include <getopt.h>
#include <dlfcn.h>

#include <sof/sof.h>
#include <sof/schedule/task.h>
#include <sof/lib/alloc.h>
#include <sof/lib/notifier.h>
#include <sof/ipc/driver.h>
#include <sof/ipc/topology.h>
#include <sof/lib/agent.h>
#include <sof/lib/dai.h>
#include <sof/lib/dma.h>
#include <sof/schedule/edf_schedule.h>
#include <sof/schedule/ll_schedule.h>
#include <sof/schedule/ll_schedule_domain.h>
#include <sof/schedule/schedule.h>
#include <sof/lib/wait.h>
#include <sof/audio/pipeline.h>
#include <sof/audio/component.h>
#include <sof/audio/component_ext.h>

#include "plugin.h"
#include "common.h"

#define VERSION		"v0.1"
#define MAX_MODULE_ID	256

struct sof_pipe_module {
	void *handle;
	char uuid[SOF_UUID_SIZE];
};

struct sof_pipe {
	const char *alsa_name;
	char topology_name[NAME_SIZE];
	int realtime;
	int use_P_core;
	int use_E_core;
	int capture;
	int dead;
	int file_mode;

	struct sigaction action;

	/* SHM for stream context sync */
	struct plug_shm_context shm_context;

	/* PCM flow control */
	struct plug_lock ready;
	struct plug_lock done;
	struct plug_shm_context pcm;

	FILE *log;
	pthread_mutex_t ipc_lock;

	/* PCM IPC */
	pthread_t ipc_pcm_thread;
	int pcm_ipc_thread_running;
	struct plug_mq pcm_ipc;

	/* CTL IPC */
	pthread_t ipc_ctl_thread;
	int ctl_ipc_thread_running;
	struct plug_mq ctl_ipc;

	/* module SO handles */
	struct sof_pipe_module module[MAX_MODULE_ID];
	int mod_idx;
};

/* global needed for signal handler */
struct sof_pipe *_sp;

/* dump the IPC data - dont print lines of 0s */
static void pipe_ipc_dump(void *vdata, size_t bytes)
{
	uint32_t *data = vdata;
	size_t words = bytes >> 2;
	int i;

	for (i = 0; i < words; i++) {
		/* 4 words per line */
		if (i % 4 == 0) {
			/* delete lines with all 0s */
			if (i > 0 &&
				data[i - 3] == 0 &&
				data[i - 2] == 0 &&
				data[i - 1] == 0 &&
				data[i - 0] == 0)
				printf("\r");
			else
				printf("\n");

			printf("0x%4.4x: 0x%8.8x", i, data[i]);
		} else
			printf(" 0x%8.8x", data[i]);
	}
	printf("\n");
}

/* read the CPU ID register data on x86 */
static inline void x86_cpuid(unsigned int *eax, unsigned int *ebx,
                             unsigned int *ecx, unsigned int *edx)
{
        /* data type is passed in on eax (and sometimes ecx) */
        asm volatile("cpuid"
            : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
            : "0" (*eax), "2" (*ecx));
}

/*
 * Check core type for E cores. If non hybrid then it does not matter.
 */
static inline int use_this_core(struct sof_pipe *sp)
{
	/* CPUID - set eax to 0x1a for hybrid core types */
	unsigned eax = 0x1a, ebx = 0, ecx = 0, edx = 0;
	char core_mask;

	/* get the processor core type we are running on now */
	x86_cpuid(&eax, &ebx, &ecx, &edx);

	/* core type 0x20 is atom, 0x40 is core */
	core_mask = (eax >> 24) & 0xFF;
	switch (core_mask) {
	case 0x20:
		fprintf(sp->log, "found E core\n");
		if (sp->use_E_core)
			return 1;
		return 0;
	case 0x40:
		fprintf(sp->log, "found P core\n");
		if (sp->use_P_core)
			return 1;
		return 0;
	default:
		/* non hybrid arch, just use first core */
		fprintf(sp->log, "found non hybrid core topology\n");
		return 1;
	}
}

static void shutdown(struct sof_pipe *sp)
{
	sp->dead = 1;

	//pthread_join(sp->ipc_ctl_thread);

	//pthread_join(sp->ipc_pcm_thread);

	/* free everything */
	munmap(sp->shm_context.addr, sp->shm_context.size);
	shm_unlink(sp->shm_context.name);

	munmap(sp->pcm.addr, sp->pcm.size);
	shm_unlink(sp->pcm.name);

	sem_close(sp->ready.sem);
	sem_unlink(sp->ready.name);

	sem_close(sp->done.sem);
	sem_unlink(sp->done.name);

	mq_close(sp->pcm_ipc.mq);
	mq_unlink(sp->pcm_ipc.queue_name);

	mq_close(sp->ctl_ipc.mq);
	mq_unlink(sp->ctl_ipc.queue_name);

	pthread_mutex_destroy(&sp->ipc_lock);

	fflush(sp->log);
	fflush(stdout);
	fflush(stderr);
}

/* signals from the ALSA PCM plugin or something has gone wrong */
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
		fprintf(_sp->log, "Pipe caught SIGTERM - shutdown\n");
		break;
	default:
		fprintf(_sp->log, "Pipe caught signal %d, something went wrong\n", sig);
		break;
	}
	fprintf(_sp->log, "Pipe shutdown signal\n");

	/* try and clean up if we can */
	shutdown(_sp);
	exit(EXIT_FAILURE);
}

static int pipe_init_signals(struct sof_pipe *sp)
{
	struct sigaction *action = &sp->action;
	int err;

	/*
	 * signals - currently only check for SIGCHLD
	 */
	sigemptyset(&action->sa_mask);
	//sigaddset(&action->sa_mask, SIGTERM);
	action->sa_handler = signal_handler;
	err = sigaction(SIGTERM, action, NULL);
	if (err < 0) {
		fprintf(sp->log, "failed to register signal action: %s",
			strerror(errno));
		return err;
	}
	err = sigaction(SIGSEGV, action, NULL);
	if (err < 0) {
		fprintf(sp->log, "failed to register signal action: %s",
			strerror(errno));
		return err;
	}

	return 0;
}

/* sof-pipe needs to be sticky to the current core for low latency */
static int pipe_set_affinity(struct sof_pipe *sp)
{

	cpu_set_t cpuset;
	pthread_t thread;
	long core_count = sysconf(_SC_NPROCESSORS_ONLN);
	int i;
	int err;

	/* Set affinity mask to  core */
	thread = pthread_self();
	CPU_ZERO(&cpuset);

	/* find the first E core (usually come after the P cores ?) */
	for (i = core_count - 1; i >= 0; i--) {
		CPU_ZERO(&cpuset);
		CPU_SET(i, &cpuset);

		/* change our core to i */
		err = pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
		if (err != 0) {
			fprintf(sp->log, "error: failed to set CPU affinity to core %d: %s\n",
				i, strerror(err));
			return err;
		}

		/* should we use this core ? */
		if (use_this_core(sp))
			break;
	}

	return 0;
}

/* set ipc thread to low priority */
static int pipe_set_ipc_lowpri(struct sof_pipe *sp)
{
	pthread_attr_t attr;
	struct sched_param param;
	int err;

	/* attempt to set thread priority - needs suid */
	fprintf(sp->log, "pipe: set IPC low priority\n");

	err = pthread_attr_init(&attr);
	if (err < 0) {
		fprintf(sp->log, "error: can't create thread attr %d %s\n",
		       err, strerror(errno));
		return err;
	}

	err = pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
	if (err < 0) {
		fprintf(sp->log, "error: can't set thread policy %d %s\n",
		       err, strerror(errno));
		return err;
	}
	param.sched_priority = 0;
	err = pthread_attr_setschedparam(&attr, &param);
	if (err < 0) {
		fprintf(sp->log, "error: can't set thread sched param %d %s\n",
		       err, strerror(errno));
		return err;
	}

	return 0;
}

static int pipe_ipc_message(struct sof_pipe *sp, void *mailbox)
{
	int err = 0;

	/* reply is copied back to mailbox */
	pthread_mutex_lock(&sp->ipc_lock);
	ipc_cmd(mailbox);
	pthread_mutex_unlock(&sp->ipc_lock);

	return err;
}

static int pipe_register_comp(struct sof_pipe *sp, struct sof_ipc_comp *comp,
		struct sof_ipc_comp_ext *comp_ext)
{
	char uuid_sofile[NAME_SIZE];
	char *uuid;
	int index;
	void (*entry)(void);
	int i;

	/* determine module uuid */
	switch (comp->type) {
	case SOF_COMP_HOST:
		/* HOST is the sof-pipe SHM */
		break;
	case SOF_COMP_DAI:
		/* DAI is either ALSA device or file */
		break;
	default:
		/* dont care */
		break;
	}

	/* check if module already loaded */
	for (i = 0; i < sp->mod_idx; i++) {
		if (!strncmp(sp->module[i].uuid, comp_ext->uuid, sizeof(*comp_ext->uuid)))
			return 0; /* module found and already loaded */
	}

	/* TODO: try other paths */
	snprintf(uuid_sofile, sizeof(uuid_sofile), "libsof-%s.so", comp_ext->uuid);
	printf("try to load module: %s\n", uuid_sofile);

	/* not loaded, so load module */
	sp->module[sp->mod_idx].handle = dlopen(uuid_sofile, RTLD_LAZY);
	if (!sp->module[sp->mod_idx].handle) {
		fprintf(stderr, "error: cant load module %s : %s\n",
			uuid, dlerror());
		return -errno;
	}

	/* find the module entry */
	entry = dlsym(sp->module[sp->mod_idx].handle, "init");
	if (!entry) {
		fprintf(stderr, "error: cant get entry for module %s : %s\n",
			uuid, dlerror());
		return -errno;
	}

	/* register the module */
	entry();
	sp->mod_idx++;

	return 0;
}

static int pipe_comp_new(struct sof_pipe *sp, struct sof_ipc_cmd_hdr *hdr)
{
	struct sof_ipc_comp *comp = (struct sof_ipc_comp *)hdr;
	struct sof_ipc_comp_ext *comp_ext;
	int ret;

	if (comp->ext_data_length == 0) {
		fprintf(stderr, "error: no uuid for hdr 0x%x\n", hdr->cmd);
		return -EINVAL;
	}

	comp_ext = (struct sof_ipc_comp_ext *)(comp + 1);

	ret = pipe_register_comp(sp, comp, comp_ext);
	return 0;
}

static int pipe_comp_free(struct sof_pipe *sp, struct sof_ipc_cmd_hdr *hdr)
{
	return 0;
}

#define iCS(x) ((x) & SOF_CMD_TYPE_MASK)

static int pipe_sof_pcm_ipc_message(struct sof_pipe *sp, void *mailbox)
{
	struct sof_ipc_cmd_hdr *hdr = mailbox;
	int err = 0;
	uint32_t cmd = iCS(hdr->cmd);

	switch (cmd) {
	case SOF_IPC_TPLG_COMP_NEW:
		return pipe_comp_new(sp, hdr);
	case SOF_IPC_TPLG_COMP_FREE:
		return pipe_comp_free(sp, hdr);
	default:
		/* handled by SOF core */
		return 1;
	}
}

static void *pipe_ipc_pcm_thread(void *arg)
{
	struct sof_pipe *sp = arg;
	ssize_t ipc_size;
	char mailbox[384] = {0};
	int err;

	/* IPC thread should not preempt processing thread */
	err = pipe_set_ipc_lowpri(sp);
	if (err < 0)
		fprintf(sp->log, "error: cant set PCM IPC thread to low priority");

	/* create the IPC message queue */
	err = plug_create_ipc_queue(&sp->pcm_ipc);
	if (err < 0) {
		fprintf(sp->log, "error: can't create PCM IPC message queue : %s\n",
			strerror(errno));
		return NULL;
	}

	/* let main() know we are ready */
	sp->pcm_ipc_thread_running = 1;
	fprintf(sp->log, "sof-pipe: PCM IPC thread ready\n");

	/* main PCM IPC handling loop */
	while (1) {
		ipc_size = mq_receive(sp->pcm_ipc.mq, mailbox, IPC3_MAX_MSG_SIZE, NULL);
		if (err < 0) {
			fprintf(sp->log, "error: can't read PCM IPC message queue %s : %s\n",
				sp->pcm_ipc.queue_name, strerror(errno));
			break;
		}

		/* do the message work */
		printf("got IPC %ld bytes from PCM: %s\n", ipc_size, mailbox);
		pipe_ipc_dump(mailbox, IPC3_MAX_MSG_SIZE);
		if (sp->dead)
			break;

		if (pipe_sof_pcm_ipc_message(sp, mailbox))
			pipe_ipc_message(sp, mailbox);

		/* now return message completion status */
		err = mq_send(sp->pcm_ipc.mq, mailbox, IPC3_MAX_MSG_SIZE, 0);
		if (err < 0) {
			fprintf(sp->log, "error: can't send PCM IPC message queue %s : %s\n",
				sp->pcm_ipc.queue_name, strerror(errno));
			break;
		}
	}

	fprintf(sp->log, "PCM IPC thread finished !!\n");
	return NULL;
}

static void *pipe_ipc_ctl_thread(void *arg)
{
	struct sof_pipe *sp = arg;
	ssize_t ipc_size;
	char mailbox[384] = {0};
	int err;

	/* IPC thread should not preempt processing thread */
	err = pipe_set_ipc_lowpri(sp);
	if (err < 0)
		fprintf(sp->log, "error: cant set CTL IPC thread to low priority");

	/* create the IPC message queue */
	err = plug_create_ipc_queue(&sp->ctl_ipc);
	if (err < 0) {
		fprintf(sp->log, "error: can't create CTL IPC message queue : %s\n",
			strerror(errno));
		return NULL;
	}

	/* let main() know we are ready */
	sp->ctl_ipc_thread_running = 1;
	fprintf(sp->log, "sof-pipe: CTL IPC thread ready\n");

	/* main CTL IPC handling loop */
	while (1) {
		ipc_size = mq_receive(sp->ctl_ipc.mq, mailbox, IPC3_MAX_MSG_SIZE, NULL);
		if (err < 0) {
			fprintf(sp->log, "error: can't read CTL IPC message queue %s : %s\n",
				sp->ctl_ipc.queue_name, strerror(errno));
			break;
		}

		/* do the message work */
		printf("got IPC %ld bytes from CTL: %s\n", ipc_size, mailbox);
		if (sp->dead)
			break;
		pipe_ipc_message(sp, mailbox);

		/* now return message completion status */
		err = mq_send(sp->ctl_ipc.mq, mailbox, IPC3_MAX_MSG_SIZE, 0);
		if (err < 0) {
			fprintf(sp->log, "error: can't send CTL IPC message queue %s : %s\n",
				sp->ctl_ipc.queue_name, strerror(errno));
			break;
		}
	}

	fprintf(sp->log, "CTL IPC thread finished !!\n");
	return NULL;
}


/* set pipeline to realtime priority */
static int pipe_set_rt(struct sof_pipe *sp)
{
	pthread_attr_t attr;
	struct sched_param param;
	int err;
	uid_t uid = getuid();
	uid_t euid = geteuid();

	/* do we have elevated privileges to attempt RT priority */
	if (uid < 0 || uid != euid) {

		/* attempt to set thread priority - needs suid */
		fprintf(sp->log, "pipe: set RT priority\n");

		err = pthread_attr_init(&attr);
		if (err < 0) {
			fprintf(sp->log, "error: can't create thread attr %d %s\n",
			       err, strerror(errno));
			return err;
		}

		err = pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
		if (err < 0) {
			fprintf(sp->log, "error: can't set thread policy %d %s\n",
			       err, strerror(errno));
			return err;
		}
		param.sched_priority = 80;
		err = pthread_attr_setschedparam(&attr, &param);
		if (err < 0) {
			fprintf(sp->log, "error: can't set thread sched param %d %s\n",
			       err, strerror(errno));
			return err;
		}
		err = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
		if (err < 0) {
			fprintf(sp->log, "error: can't set thread inherit %d %s\n",
			       err, strerror(errno));
			return err;
		}
	} else {
		fprintf(sp->log, "error: no elevated privileges for RT. uid %d euid %d\n",
			uid, euid);
	}

	return 0;
}

/*
 * The main playback processing loop
 */
static int pipe_process_playback(struct sof_pipe *sp)
{
	struct plug_context *ctx = sp->shm_context.addr;
	struct timespec ts;
	ssize_t bytes;

	fprintf(sp->log, "pipe ready for playback\n");

	ts.tv_sec = 0;
	ts.tv_nsec = MS_TO_NS(125);
	do {
		/* wait for data */
		sem_wait(sp->ready.sem);

		/* FAKE the HW: now do all the processing and tell plugin we are done */
		nanosleep(&ts, NULL);

		ctx->position += ctx->frames;
		if (ctx->position > ctx->buffer_frames)
			ctx->position -= ctx->buffer_frames;

		ctx->process_count++;

		/* tell plugin we are done */
		sem_post(sp->done.sem);
	} while (1);

	return 0;
}

/*
 * The main capture processing loop
 */
static int pipe_process_capture(struct sof_pipe *sp)
{
	struct plug_context *ctx = sp->shm_context.addr;
	struct timespec ts;
	ssize_t bytes;

	fprintf(sp->log, "pipe ready for capture\n");

	ts.tv_sec = 0;
	ts.tv_nsec = MS_TO_NS(10);

	do {

		/* FAKE the HW: now do all the processing and tell plugin we are done */
		nanosleep(&ts, NULL);

		ctx->position += ctx->frames;
		if (ctx->position > ctx->buffer_frames)
				ctx->position -= ctx->buffer_frames;

		ctx->process_count++;

		/* tell plugin data is ready */
		sem_post(sp->ready.sem);


		/* wait for plugin to consume */
		sem_wait(sp->done.sem);

	} while (1);

	return 0;
}

// TODO: all these stepd are probably not needed - i.e we only need IPC and pipeline.
static int pipe_sof_setup(struct sof *sof)
{
	struct ll_schedule_domain domain = {0};

	/* register modules */


	domain.next_tick = 0;

	/* init components */
	sys_comp_init(sof);

	/* other necessary initializations, todo: follow better SOF init */
	pipeline_posn_init(sof);
	init_system_notify(sof);

	/* init IPC */
	if (ipc_init(sof) < 0) {
		fprintf(stderr, "error: IPC init\n");
		return -EINVAL;
	}

	/* init LL scheduler */
	if (scheduler_init_ll(&domain) < 0) {
		fprintf(stderr, "error: edf scheduler init\n");
		return -EINVAL;
	}

	/* init EDF scheduler */
	if (scheduler_init_edf() < 0) {
		fprintf(stderr, "error: edf scheduler init\n");
		return -EINVAL;
	}

	return 0;
}

/*
 * -D ALSA device. e.g. hw:0,1
 * -R realtime (needs parent to set uid)
 * -p Force run on P core
 * -e Force run on E core
 * -c capture
 * -t topology name.
 * -L log file (otherwise stdout)
 * -h help
 */
static void usage(char *name)
{
	fprintf(stdout, "Usage: %s -D ALSA device | -F in/out file"
			" -i ipc_msg", name);
}

int main(int argc, char *argv[], char *env[])
{
	struct sof_pipe sp = {0};
	struct plug_context *ctx;
	struct timespec delay;
	int option = 0;
	int ret = 0;
	int tries = 100;
	int i;

	/* default config */
	sp.log = stdout;
	_sp = &sp;

	ret = pthread_mutex_init(&sp.ipc_lock, NULL);
	if (ret < 0) {
		fprintf(sp.log, "error: cant create mutex %s\n",  strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* parse all args */
	while ((option = getopt(argc, argv, "hD:Rpect:")) != -1) {

		switch (option) {
		/* Alsa device  */
		case 'D':
			sp.alsa_name = strdup(optarg);
			break;
		case 'R':
			sp.realtime = 1;
			break;
		case 'p':
			sp.use_P_core = 1;
			sp.use_E_core = 0;
			break;
		case 'e':
			sp.use_E_core = 1;
			sp.use_P_core = 0;
			break;
		case 'c':
			sp.capture = 1;
			break;
		case 't':
			snprintf(sp.topology_name, NAME_SIZE, "%s", optarg);
			break;

		/* print usage */
		default:
			fprintf(sp.log, "unknown option %c\n", option);
			__attribute__ ((fallthrough));
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		}
	}

	/* validate cmd line params */
	if (strlen(sp.topology_name) == 0) {
		fprintf(sp.log, "error: no IPC topology name specified\n");
		exit(EXIT_FAILURE);
	}

	/* initialise IPC data */
	ret = plug_ipc_init_queue(&sp.pcm_ipc, sp.topology_name, "pcm");
	if (ret < 0)
		goto out;
	ret = plug_ipc_init_queue(&sp.ctl_ipc, sp.topology_name, "ctl");
	if (ret < 0)
		goto out;
	ret = plug_ipc_init_shm(&sp.shm_context, sp.topology_name, "ctx");
	if (ret < 0)
		goto out;
	ret = plug_ipc_init_shm(&sp.pcm, sp.topology_name, "pcm");
	if (ret < 0)
		goto out;
	ret = plug_ipc_init_lock(&sp.ready, sp.topology_name, "ready");
	if (ret < 0)
		goto out;
	ret = plug_ipc_init_lock(&sp.done, sp.topology_name, "done");
	if (ret)
		goto out;

	/* cleanup any lingering IPC files */
	shm_unlink(sp.shm_context.name);
	shm_unlink(sp.pcm.name);
	sem_unlink(sp.ready.name);
	sem_unlink(sp.done.name);
	mq_unlink(sp.ctl_ipc.queue_name);
	mq_unlink(sp.pcm_ipc.queue_name);

#if 1
	/* turn on logging */
	unlink("log.txt");
	sp.log = fopen("log.txt", "w+");
	if (!sp.log) {
		fprintf(stderr, "failed to open log: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
#endif
	/* make sure we can cleanly shutdown */
	ret = pipe_init_signals(&sp);
	if (ret < 0)
		goto out;

	fprintf(sp.log, "sof-pipe-%s: using topology %s\n", VERSION, sp.topology_name);

	/* set CPU affinity */
	if (sp.use_E_core || sp.use_P_core) {
		ret = pipe_set_affinity(&sp);
		if (ret < 0)
			goto out;
	}

	/* initialize ipc and scheduler */
	if (pipe_sof_setup(sof_get()) < 0) {
		fprintf(stderr, "error: pipeline init\n");
		exit(EXIT_FAILURE);
	}

	/* start PCM IPC thread */
	ret = pthread_create(&sp.ipc_pcm_thread, NULL, &pipe_ipc_pcm_thread, &sp);
	if (ret < 0) {
		fprintf(sp.log, "failed to create PCM IPC thread: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* start CTL IPC thread */
	ret = pthread_create(&sp.ipc_ctl_thread, NULL, &pipe_ipc_ctl_thread, &sp);
	if (ret < 0) {
		fprintf(sp.log, "failed to create CTL IPC thread: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* set priority if asked */
	if (sp.realtime) {
		ret = pipe_set_rt(&sp);
		if (ret < 0)
			goto out;
	}

	/* mmap PCM */
	ret = plug_create_mmap_regions(&sp.pcm);
	if (ret < 0)
		goto out;

	/* open semaphore */
	ret = plug_ipc_create_lock(&sp.ready);
	if (ret < 0)
		goto out;
	ret = plug_ipc_create_lock(&sp.done);
	if (ret < 0)
		goto out;

	/* we need to wait for all threads to be ready */
	delay.tv_sec = 0;
	delay.tv_nsec = 20 * 1000 * 1000;	/* 20 milliseconds */
	while (!sp.pcm_ipc_thread_running &&
		   !sp.ctl_ipc_thread_running &&
		   tries--) {
		nanosleep(&delay, NULL);
	}
	if (!tries) {
		fprintf(sp.log, "timeout waiting on threads\n");
		goto out;
	}

	/* mmap context */
	ret = plug_create_mmap_regions(&sp.shm_context);
	if (ret < 0)
		goto out;
	ctx = sp.shm_context.addr;
	memset(ctx, 0 , sizeof(*ctx));
	ctx->cpid = getpid();

	/* open ALSA device or IO file */

	/* process */
	if (sp.capture)
		pipe_process_capture(&sp);
	else
		pipe_process_playback(&sp);
out:
fprintf(sp.log, "shutdown main\n");
	shutdown(&sp);
	return ret;
}
