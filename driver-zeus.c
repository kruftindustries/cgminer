/*
 * Copyright 2012-2013 Andrew Smith
 * Copyright 2012 Xiangfu <xiangfu@openmobilefree.com>
 * Copyright 2013-2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2014 Dominik Lehner
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <dirent.h>
#include <unistd.h>
#include <math.h>
#ifndef WIN32
#include <termios.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#else
#include <windows.h>
#include <io.h>
#endif

#include "fpgautils.h"
#include "miner.h"
#include "driver-zeus.h"

// Configuration options
extern bool opt_zeus_debug;
extern int opt_zeus_chips_count;		// number of Zeus chips chained together
extern int opt_zeus_chip_clk;			// frequency to run chips with
extern bool opt_zeus_nocheck_golden;	// bypass hashrate check

static int opt_zeus_chips_count_max = 1;// smallest power of 2 >= opt_zeus_chips_count
										// is currently auto-calculated, cannot be
										// specified on command line

// Looking for options in --zeus-timing and --zeus-options:
//
// Code increments this each time we start to look at a device
// However, this means that if other devices are checked by
// the Icarus code (e.g. BFL) they will count in the option offset
//
// This, however, is deterministic so that's OK
//
// If we were to increment after successfully finding an Icarus
// that would be random since an Icarus may fail and thus we'd
// not be able to predict the option order
//
// This also assumes that serial_detect() checks them sequentially
// and in the order specified on the command line
//
static int option_offset = -1;


/************************************************************
 * Utility Functions
 ************************************************************/

static void flush_uart(int fd)
{
#ifdef WIN32
	const HANDLE fh = (HANDLE)_get_osfhandle(fd);
	PurgeComm(fh, PURGE_RXCLEAR);
#else
	tcflush(fd, TCIFLUSH);
#endif
}

static int flush_fd(int fd) {		// sadly tcflush only works with terminal fds
	static char discard[10];		// note this function assumes fd is non-blocking
	int ret;						// so a return of -1 means success for our purposes
	while ((ret = read(fd, discard, sizeof(discard))) > 0);
	return ret;
}

static void rev(unsigned char *s, size_t l)
{
	size_t i, j;
	unsigned char t;

	for (i = 0, j = l - 1; i < j; i++, j--) {
		t = s[i];
		s[i] = s[j];
		s[j] = t;
	}
}

static int log_2(int value)
{
	int x = 0;
	while (value > 1) {
		value >>= 1;
		x++;
	}
	return x;
}

static uint32_t chip_index(uint32_t value, int bit_num)
{
	uint32_t newvalue = 0;
	int i;

	// isolate bits 19-28, then shift right to get the
	// highest bits that distinguish multiple chips
	value = (value & 0x1ff80000) >> (29 - bit_num);

	for (i = 0; i < bit_num; i++) {
		newvalue = newvalue << 1;
		newvalue += value & 0x01;
		value = value >> 1;
	}

	return newvalue;
}

int lowest_pow2(int min) {
	int i;
	for (i = 1; i < 1024; i = i * 2) {
		if (min <= i){
			return i;
		}
	}
	return 1024;
}

static void notify_io_thread(struct cgpu_info *zeus)
{
	struct ZEUS_INFO *info = zeus->device_data;
	static char tickle = 'W';
	write(info->pipefd[PIPE_W], &tickle, 1);
}

/************************************************************
 * I/O helper functions
 ************************************************************/

#define zeus_open(devpath, baud, purge) serial_open(devpath, baud, ZEUS_READ_FAULT_DECISECONDS, purge)
#define zeus_close(fd) close(fd)

static int zeus_write(int fd, const void *buf, size_t len)
{
	ssize_t ret;
	size_t total = 0;

#if ZEUS_PROTOCOL_DEBUG
	char *hexstr;
	hexstr = bin2hex(buf, len);
	applog(LOG_DEBUG, "> %s", hexstr);
	free(hexstr);
#endif

	while (total < len) {
		ret = write(fd, buf, len);
		if (ret < 0) {
			applog(LOG_ERR, "zeus_write: error on write: %s", strerror(errno));
			return -1;
		}
		total += (size_t)ret;
	}

	return total;
}

#define zeus_read(fd, buf, len) zeus_read_timeout(fd, buf, len, -1, NULL)
static int zeus_read_timeout(int fd, void *buf, size_t len, int read_count, struct timeval *tv_firstbyte)
{
	ssize_t ret;
	size_t total = 0;
	int rc = 0;

	while (total < len) {
		ret = read(fd, buf + total, len);
		if (ret < 0) {
			applog(LOG_ERR, "zeus_read: error on read: %s", strerror(errno));
			return -1;
		}

		if (tv_firstbyte != NULL && total == 0)
			cgtime(tv_firstbyte);

		if (ret == 0 && read_count > 0 && ++rc >= read_count)
			break;

		applog(LOG_DEBUG, "zeus_read: read returned %d", (int)ret);

		total += (size_t)ret;
	}

#if ZEUS_PROTOCOL_DEBUG
	char *hexstr;
	if (total > 0) {
		hexstr = bin2hex(buf, total);
		applog(LOG_DEBUG, "< %s", hexstr);
		free(hexstr);
	} else {
		applog(LOG_DEBUG, "< (no data)");
	}
#endif

	return total;
}

/************************************************************
 * Detection and setup
 ************************************************************/

static bool zeus_detect_one(const char *devpath)
{
	struct timeval tv_start, tv_finish, golden_tv;
	int fd, baud, cores_per_chip, chips_count_max, chips_count;
	int this_option_offset = ++option_offset;
	int numbytes = ZEUS_COMMAND_PKT_LEN;
	uint32_t clk_reg;
	uint32_t clk_reg_init;
	uint64_t golden_speed_per_core;

	char clk_header_str[10];

	if (opt_zeus_chip_clk > ZEUS_CLK_MAX)
		opt_zeus_chip_clk = ZEUS_CLK_MAX;
	else if (opt_zeus_chip_clk < ZEUS_CLK_MIN)
		opt_zeus_chip_clk = ZEUS_CLK_MIN;

	clk_reg = (uint32_t)(opt_zeus_chip_clk * 2./3.);

	char golden_ob[] =
			"55aa0001"
			"00038000063b0b1b028f32535e900609c15dc49a42b1d8492a6dd4f8f15295c989a1decf584a6aa93be26066d3185f55ef635b5865a7a79b7fa74121a6bb819da416328a9bd2f8cef72794bf02000000";

	char golden_ob2[] =
			"55aa00ff"
			"c00278894532091be6f16a5381ad33619dacb9e6a4a6e79956aac97b51112bfb93dc450b8fc765181a344b6244d42d78625f5c39463bbfdc10405ff711dc1222dd065b015ac9c2c66e28da7202000000";

	const char golden_nonce[] = "00038d26";
	const uint32_t golden_nonce_val = 0x00038d26; // 0xd26 = 3366

	unsigned char ob_bin[ZEUS_COMMAND_PKT_LEN], nonce_bin[ZEUS_EVENT_PKT_LEN];
	char *nonce_hex;

	baud = ZEUS_IO_SPEED;				// baud rate is fixed
	cores_per_chip = ZEUS_CHIP_CORES;		// cores/chip also fixed
	chips_count = opt_zeus_chips_count;	// number of chips per ASIC device
	if (chips_count > opt_zeus_chips_count_max)				// find smallest power of
		opt_zeus_chips_count_max = lowest_pow2(chips_count);// 2 >= chips_count
	chips_count_max = opt_zeus_chips_count_max;

	applog(LOG_INFO, "Zeus Detect: Attempting to open %s", devpath);

	fd = zeus_open(devpath, baud, true);
	if (unlikely(fd == -1)) {
		applog(LOG_ERR, "Zeus Detect: Failed to open %s", devpath);
		return false;
	}

	uint32_t clk_header;

	// from 150M step to the high or low speed. we need to add delay and resend to init chip

	if (clk_reg > (150 * 2./3.))
		clk_reg_init = 165 * 2./3.;
	else
		clk_reg_init = 139 * 2./3.;

	flush_uart(fd);


	clk_header = (clk_reg_init << 24) + ((0xff - clk_reg_init) << 16);
	sprintf(clk_header_str, "%08x", clk_header + 0x01);
	memcpy(golden_ob2, clk_header_str, 8);

	hex2bin(ob_bin, golden_ob2, numbytes);
	zeus_write(fd, ob_bin, numbytes);
	sleep(1);
	flush_uart(fd);
	zeus_write(fd, ob_bin, numbytes);
	sleep(1);
	flush_uart(fd);
	zeus_write(fd, ob_bin, numbytes);
	sleep(1);
	flush_uart(fd);


	clk_header = (clk_reg << 24) + ((0xff - clk_reg) << 16);
	sprintf(clk_header_str, "%08x", clk_header + 0x01);
	memcpy(golden_ob2, clk_header_str, 8);

	hex2bin(ob_bin, golden_ob2, numbytes);
	zeus_write(fd, ob_bin, numbytes);
	sleep(1);
	flush_uart(fd);
	zeus_write(fd, ob_bin, numbytes);
	sleep(1);
	flush_uart(fd);



	clk_header = (clk_reg << 24) + ((0xff - clk_reg) << 16);
	sprintf(clk_header_str, "%08x", clk_header + 0x01);
	memcpy(golden_ob, clk_header_str, 8);


	if (!opt_zeus_nocheck_golden) {
		memset(nonce_bin, 0, sizeof(nonce_bin));

		flush_uart(fd);

		hex2bin(ob_bin, golden_ob, numbytes);

		zeus_write(fd, ob_bin, numbytes);
		cgtime(&tv_start);

		zeus_read_timeout(fd, nonce_bin, sizeof(nonce_bin), 1000, &tv_finish);

		zeus_close(fd);

		nonce_hex = bin2hex(nonce_bin, sizeof(nonce_bin));
		if (strncmp(nonce_hex, golden_nonce, 8) != 0) {
			applog(LOG_ERR,
					"Zeus Detect: "
					"Test failed at %s: got %s, should be: %s",
					devpath, nonce_hex, golden_nonce);
			free(nonce_hex);
			return false;
		}

		timersub(&tv_finish, &tv_start, &golden_tv);

		golden_speed_per_core = (uint64_t)(((double)0xd26)/((double)(golden_tv.tv_sec) + ((double)(golden_tv.tv_usec))/((double)1000000)));

		if (opt_zeus_debug)
			applog(LOG_NOTICE, "Test succeeded at %s: got %s",
					devpath, nonce_hex);

		free(nonce_hex);
	} else{
		zeus_close(fd);
		golden_speed_per_core = (((opt_zeus_chip_clk * 2) / 3) * 1024) / 8;
	}

	/* We have a real Zeus miner! */
	struct cgpu_info *zeus;
	struct ZEUS_INFO *info;

	zeus = calloc(1, sizeof(struct cgpu_info));
	if (unlikely(!zeus))
		quit(1, "Failed to malloc struct cgpu_info");
	info = calloc(1, sizeof(struct ZEUS_INFO));
	if (unlikely(!info))
		quit(1, "Failed to malloc struct ZEUS_INFO");

	zeus->drv = &zeus_drv;
	zeus->device_path = strdup(devpath);
	zeus->threads = 1;
	zeus->device_data = info;
	add_cgpu(zeus);

	applog(LOG_NOTICE, "Found Zeus at %s, mark as %d",
			devpath, zeus->device_id);

	applog(LOG_INFO, "Zeus: Init: %d baud=%d cores_per_chip=%d chips_count=%d",
			zeus->device_id, baud, cores_per_chip, chips_count);

	info->device_fd = -1;
	info->device_name = strrchr(zeus->device_path, '/');
	if (info->device_name == NULL)
		info->device_name = zeus->device_path + strlen(zeus->device_path);

	info->check_num = 0x1234;
	info->baud = baud;
	info->cores_per_chip = cores_per_chip;
	info->chips_count = chips_count;
	info->chips_count_max= chips_count_max;
	if ((chips_count_max & (chips_count_max - 1)) != 0)
		quit(1, "chips_count_max must be a power of 2");
	info->chips_bit_num = log_2(chips_count_max);
	info->golden_speed_per_core = golden_speed_per_core;

	info->freqcode = (unsigned char)(clk_reg & 0xff);

	info->read_count = (uint32_t)((4294967296*10)/(cores_per_chip*chips_count_max*golden_speed_per_core*2));
	info->read_count = info->read_count*3/4;

	info->chip_clk=opt_zeus_chip_clk;
	info->clk_header=clk_header;

	//suffix_string(golden_speed_per_core, info->core_hash, sizeof(info->core_hash), 0);
	//suffix_string(golden_speed_per_core*cores_per_chip, info->chip_hash, sizeof(info->chip_hash), 0);
	//suffix_string(golden_speed_per_core*cores_per_chip*chips_count, info->board_hash, sizeof(info->board_hash), 0);

	/*
	if (opt_zeus_debug) {
		applog(LOG_NOTICE,
				"[Speed] %dMhz core|chip|board: [%s/s], [%s/s], [%s/s], readcount:%d,bitnum:%d ",
				info->chip_clk,info->core_hash,info->chip_hash,info->board_hash,info->read_count,info->chips_bit_num);
	}
	*/

	return true;
}

/************************************************************
 * Host <-> ASIC protocol implementation
 ************************************************************/

static void zeus_purge_work(struct cgpu_info *zeus)
{
	struct ZEUS_INFO *info = zeus->device_data;
	mutex_lock(&info->lock);
	if (info->current_work != NULL) {
		free_work(info->current_work);
		info->current_work = NULL;
	}
	mutex_unlock(&info->lock);
}

static bool zeus_read_response(struct cgpu_info *zeus)
{
	struct ZEUS_INFO *info = zeus->device_data;
	unsigned char evtpkt[ZEUS_EVENT_PKT_LEN];
	struct timeval elapsed;
	int ret;
	uint32_t nonce, chip, core;
	bool valid;

	ret = zeus_read(info->device_fd, evtpkt, sizeof(evtpkt));
	if (ret != ZEUS_EVENT_PKT_LEN)
		return false;

	memcpy(&nonce, evtpkt, sizeof(evtpkt));
#if !defined (__BIG_ENDIAN__) && !defined(MIPSEB)
	nonce = swab32(nonce);
#endif

	valid = submit_nonce(info->thr, info->current_work, nonce);

	chip = chip_index(nonce, info->chips_bit_num);
	core = (nonce & 0xe0000000) >> 29;	// core indicated by 3 highest bits

	++info->workdone;
	// TODO: calculate hashes_per_ms
	// TODO: purge work

	++info->nonce_count[chip];
	if (!valid)
		++info->error_count[chip];

	return true;
}

static bool zeus_check_need_work(struct cgpu_info *zeus)
{
	struct ZEUS_INFO *info = zeus->device_data;
	struct thr_info *thr = info->thr;
	struct work *work;
	bool need_work;

	need_work = (info->current_work == NULL);

	if (need_work) {
		work = get_work(thr, thr->id);

		mutex_lock(&info->lock);
		if (info->current_work == NULL) {
			work->devflag = false;
			info->current_work = work;
		} else {
			need_work = false;
		}
		mutex_unlock(&info->lock);

		if (!need_work)
			discard_work(work);
	}

	return need_work;
}

static bool zeus_send_work(struct cgpu_info *zeus, struct work *work)
{
	struct ZEUS_INFO *info = zeus->device_data;
	unsigned char cmdpkt[ZEUS_COMMAND_PKT_LEN];
	int ret, diff;
	uint16_t diff_code;

	diff = (int)work->device_diff;
	if (diff < info->chips_count)
		diff = info->chips_count;

	diff_code = 0xffff / diff;
	applog(LOG_DEBUG, "zeus_send_work: diff_code=%02x", diff_code);

	cmdpkt[0] = info->freqcode;
	cmdpkt[1] = ~(info->freqcode);
	cmdpkt[2] = (diff_code & 0xff00) >> 8;
	cmdpkt[3] = (diff_code & 0x00ff);

	memcpy(cmdpkt + 4, work->data, 80);
	rev(cmdpkt + 4, 80);

	ret = zeus_write(info->device_fd, cmdpkt, sizeof(cmdpkt));
	if (ret < 0) {
		applog(LOG_ERR, "%s%d: Comms error", zeus->drv->name, zeus->device_id);
		dev_error(zeus, REASON_DEV_COMMS_ERROR);
		return false;
	}

	return true;
}

static void *zeus_io_thread(void *data)
{
	struct cgpu_info *zeus = (struct cgpu_info *)data;
	struct ZEUS_INFO *info = zeus->device_data;
	char threadname[24];
	fd_set rfds;
	struct timeval tv;
	int retval, maxfd = MAX(info->device_fd, info->pipefd[PIPE_R]);

	snprintf(threadname, sizeof(threadname), "Zeus/%d", zeus->device_id);
	RenameThread(threadname);
	applog(LOG_INFO, "Zeus: serial I/O thread running, %s", threadname);

	while (likely(!zeus->shutdown)) {
		FD_ZERO(&rfds);
		FD_SET(info->device_fd, &rfds);
		FD_SET(info->pipefd[PIPE_R], &rfds);

		tv.tv_sec = 11;
		tv.tv_usec = 0;

		retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (retval < 0) {								// error
			if (errno == EINTR)
				continue;
			applog(LOG_ERR, "%s%d: I/O error: %s",
					zeus->drv->name, zeus->device_id, strerror(errno));
			zeus->shutdown = true;
			break;
		} else if (retval > 0) {
			if (FD_ISSET(info->device_fd, &rfds)) {		// event packet
				mutex_lock(&info->lock);
				cgtime(&info->workend);
				zeus_read_response(zeus);
				mutex_unlock(&info->lock);
			}
			if (FD_ISSET(info->pipefd[PIPE_R], &rfds)) {// miner thread woke us up
				if (flush_fd(info->pipefd[PIPE_R]) == 0) {
					// this should never happen
					applog(LOG_ERR, "%s%d: Inter-thread pipe closed, miner thread dead?",
							zeus->drv->name, zeus->device_id);
					zeus->shutdown = true;
					break;
				}
			}
		} else {										// timeout
			zeus_purge_work(zeus);						// abandon current work
		}

		if (zeus_check_need_work(zeus)) {
			/* send task to device */
			mutex_lock(&info->lock);
			if (info->current_work != NULL && !info->current_work->devflag &&
					zeus_send_work(zeus, info->current_work)) {
				info->current_work->devflag = true;
				cgtime(&info->workstart);
			}
			mutex_unlock(&info->lock);
		}
	}

	return NULL;
}

/************************************************************
 * CGMiner Interface functions
 ************************************************************/

static void zeus_detect(bool __maybe_unused hotplug)
{
	serial_detect(&zeus_drv, zeus_detect_one);
}

static bool zeus_prepare(struct thr_info *thr)
{
	struct cgpu_info *zeus = thr->cgpu;
	struct ZEUS_INFO *info = zeus->device_data;
	int fd;

	fd = zeus_open(zeus->device_path, info->baud, true);
	if (unlikely(fd < 0)) {
		applog(LOG_ERR, "Failed to open Zeus %s%d on %s",
					zeus->drv->name, zeus->device_id, zeus->device_path);
		return false;
	}

	info->device_fd = fd;

	applog(LOG_INFO, "Zeus %s%d opened on %s",
			zeus->drv->name, zeus->device_id, zeus->device_path);

	info->thr = thr;
	mutex_init(&info->lock);
	if (pipe(info->pipefd) < 0) {
		applog(LOG_ERR, "zeus_prepare: error on pipe: %s", strerror(errno));
		return false;
	}
	fcntl(info->pipefd[PIPE_R], F_SETFL, O_NONBLOCK);

	return true;
}

static bool zeus_thread_init(struct thr_info *thr)
{
	struct cgpu_info *zeus = thr->cgpu;
	struct ZEUS_INFO *info = zeus->device_data;

	if (pthread_create(&info->th_io, NULL, zeus_io_thread, zeus)) {
		applog(LOG_ERR, "%s%d: Failed to create I/O thread",
						zeus->drv->name, zeus->device_id);
		return false;
	}

	return true;
}

static int64_t zeus_scanwork(struct thr_info *thr)
{
	struct cgpu_info *zeus = thr->cgpu;
	struct ZEUS_INFO *info = zeus->device_data;
	struct timeval old_scanwork_time;
	double elapsed_s;
	int64_t estimate_hashes;

	cgsleep_ms(100);

	old_scanwork_time = info->scanwork_time;
	cgtime(&info->scanwork_time);
	elapsed_s = tdiff(&info->scanwork_time, &old_scanwork_time);

	estimate_hashes = elapsed_s * info->golden_speed_per_core *
						info->cores_per_chip * info->chips_count;

	if (unlikely(estimate_hashes > 0xffffffff))
		estimate_hashes = 0xffffffff;

	return estimate_hashes;
}

#define zeus_update_work zeus_flush_work
static void zeus_flush_work(struct cgpu_info *zeus)
{
	zeus_purge_work(zeus);
	notify_io_thread(zeus);
}

static struct api_data *zeus_api_stats(struct cgpu_info *zeus)
{
	struct ZEUS_INFO *info = zeus->device_data;
	struct api_data *root = NULL;
	static double khs_core, khs_chip, khs_board;

	khs_core = (double)info->golden_speed_per_core / 1000.;
	khs_chip = (double)info->golden_speed_per_core * (double)info->cores_per_chip / 1000.;
	khs_board = (double)info->golden_speed_per_core * (double)info->cores_per_chip * (double)info->chips_count / 1000.;
	root = api_add_khs(root, "KHS/Core", &khs_core, false);
	root = api_add_khs(root, "KHS/Chip", &khs_chip, false);
	root = api_add_khs(root, "KHS/Board", &khs_board, false);
	//root = api_add_string(root, "core_hash", info->core_hash, false);
	//root = api_add_string(root, "chip_hash", info->chip_hash, false);
	//root = api_add_string(root, "board_hash", info->board_hash, false);
	root = api_add_int(root, "chip_clk", &(info->chip_clk), false);
	root = api_add_int(root, "chips_count", &(info->chips_count), false);
	root = api_add_int(root, "chips_count_max", &(info->chips_count_max), false);
	root = api_add_uint32(root, "read_count", &(info->read_count), false);

	return root;
}

static void zeus_get_statline_before(char *buf, size_t bufsiz, struct cgpu_info *zeus)
{
	struct ZEUS_INFO *info = zeus->device_data;
	tailsprintf(buf, bufsiz, "%s  %4d MHz  ", info->device_name, info->chip_clk);
}

static void zeus_shutdown(struct thr_info *thr)
{
	struct cgpu_info *zeus = thr->cgpu;
	struct ZEUS_INFO *info = zeus->device_data;

	applog(LOG_NOTICE, "%s%d: Shutting down", zeus->drv->name, zeus->device_id);

	pthread_join(info->th_io, NULL);
	mutex_destroy(&info->lock);
	close(info->pipefd[PIPE_R]);
	close(info->pipefd[PIPE_W]);

	zeus_close(info->device_fd);
	info->device_fd = -1;
}

struct device_drv zeus_drv = {
		.drv_id = DRIVER_zeus,
		.dname = "Zeus",
		.name = "ZUS",
		.max_diff = 32768,
		.drv_detect = zeus_detect,
		.thread_prepare = zeus_prepare,
		.thread_init = zeus_thread_init,
		.hash_work = hash_driver_work,
		.scanwork = zeus_scanwork,
		.flush_work = zeus_flush_work,
		.update_work = zeus_update_work,
		.get_api_stats = zeus_api_stats,
		.get_statline_before = zeus_get_statline_before,
		.thread_shutdown = zeus_shutdown,
};
