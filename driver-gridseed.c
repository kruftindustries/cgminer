/*
 * Copyright 2013 Faster <develop@gridseed.com>
 * Copyright 2012-2013 Andrew Smith
 * Copyright 2012 Luke Dashjr
 * Copyright 2012 Con Kolivas <kernel@kolivas.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>
#include <math.h>

#ifdef WIN32
  #include "compat.h"
  #include <windows.h>
  #include <winsock2.h>
  #include <io.h>
#else
  #include <sys/select.h>
  #include <termios.h>
  #include <sys/stat.h>
  #include <fcntl.h>
#endif /* WIN32 */

#include "elist.h"
#include "miner.h"
#include "usbutils.h"
#include "driver-gridseed.h"
#include "util.h"

static const char *gridseed_version = "v3.8.5.20140210.02";

static const char *str_reset[] = {
	"55AAC000808080800000000001000000", // Chip reset
	"55AAC000E0E0E0E00000000001000000", // FW reset
	NULL
};

static const char *str_init[] = {
	"55AAC000C0C0C0C00500000001000000",
	"55AAEF020000000000000000000000000000000000000000",
	"55AAEF3020000000",
	NULL
};

static const char *str_ltc_reset[] = {
	"55AA1F2817000000",
	"55AA1F2814000000",
	"55AA1F2817000000",
	NULL
};

static const char *str_nofifo[] = {
	"55AAC000D0D0D0D00000000001000000",
	NULL
};

#ifdef WIN32
static void set_text_color(WORD color)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
#endif

/*---------------------------------------------------------------------------------------*/

static int gridseed_send_ping_packet(GRIDSEED_INFO *, struct sockaddr_in);
static void *gridseed_recv_packet(void *);
static void gc3355_send_cmds(struct cgpu_info *, const char **);
static bool gridseed_send_work_usb(struct cgpu_info *, unsigned char *, unsigned char *,
					unsigned char *, int, enum gsd_mode);
static void __gridseed_test_ltc_nonce(struct cgpu_info *, GRIDSEED_INFO *,
		struct thr_info *, uint32_t, unsigned int);


static int check_udp_port_in_use(short port)
{
	int sock;
	struct sockaddr_in local;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
		close(sock);
		return -2;
	}

	return sock;
}

static int gridseed_create_proxy(struct cgpu_info *gridseed, GRIDSEED_INFO *info)
{
	int sock = info->sockltc;
	short port = info->ltc_port;

	if (sock > 0)
		close(sock);

	info->sockltc = -1;
	while (true) {
		sock = check_udp_port_in_use(port);
		if (sock > 0)
			break;
		port++;
	}
	info->sockltc = sock;
	info->ltc_port = port;

	applog(LOG_NOTICE, "Create scrypt proxy on %d/UDP for %s%d", info->ltc_port, gridseed->drv->name, gridseed->device_id);
	return 0;
}

static int gridseed_find_proxy(GRIDSEED_INFO *info)
{
	struct sockaddr_in remote;
	struct timeval tv_timeout;
	fd_set rdfs;
	int sock = info->sockltc;
	short port = info->ltc_port + 1000;

	if (sock > 0)
		close(sock);

	info->sockltc = -1;
	while (true) {
		sock = check_udp_port_in_use(port);
		if (sock > 0)
			break;
		port++;
	}
	info->sockltc = sock;
	info->ltc_port = port - 1000;

	remote.sin_family = AF_INET;
	remote.sin_port = htons(info->ltc_port);
	remote.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (gridseed_send_ping_packet(info, remote) != 0)
		return -1;

	tv_timeout.tv_sec = 0;
	tv_timeout.tv_usec = 500000;
	FD_ZERO(&rdfs);
	FD_SET(sock, &rdfs);
	if (select(sock+1, &rdfs, NULL, NULL, &tv_timeout) != 1)
		return -1;

	//if (cgsem_mswait(&info->psem, 500) != 0)
	//	return -1;

	applog(LOG_NOTICE, "Found scrypt proxy on %d/UDP", info->ltc_port);
	return 0;
}

static int gridseed_send_ping_packet(GRIDSEED_INFO *info, struct sockaddr_in to)
{
	GRIDSEED_PACKET packet;

	if (info->sockltc <= 0)
		return -1;

	packet.type = PACKET_PING;

	if (sendto(info->sockltc, &packet, sizeof(packet), 0, (struct sockaddr *)&to,
			sizeof(to)) != sizeof(packet)) {
		applog(LOG_WARNING, "Couldn't send ping packet: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int gridseed_send_info_packet(GRIDSEED_INFO *info, struct sockaddr_in to)
{
	GRIDSEED_PACKET packet;

	if (info->sockltc <= 0)
		return -1;

	packet.type = PACKET_INFO;
	packet.info.freq = info->freq;
	packet.info.chips = info->chips;
	packet.info.modules = info->modules;
	strncpy(packet.info.serial, info->serial, sizeof(packet.info.serial));

	if (sendto(info->sockltc, &packet, sizeof(packet), 0, (struct sockaddr *)&to,
			sizeof(to)) != sizeof(packet)) {
		applog(LOG_WARNING, "Couldn't send info packet: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static void gridseed_recv_info_packet(struct cgpu_info *gridseed, GRIDSEED_INFO *info,
					GRIDSEED_PACKET packet, struct sockaddr_in from)
{
	mutex_lock(&info->qlock);
	info->freq = packet.info.freq;
	info->chips = packet.info.chips;
	info->modules = packet.info.modules;
	strncpy(info->serial, packet.info.serial, sizeof(info->serial));
	gridseed->unique_id = info->serial;
	info->toaddr = from;
	mutex_unlock(&info->qlock);

	cgsem_post(&info->psem);
}

static bool gridseed_send_work_packet(GRIDSEED_INFO *info, struct work *work)
{
	GRIDSEED_PACKET packet;

	if (info->sockltc <= 0)
		return false;

	packet.type = PACKET_WORK;
	memcpy(packet.work.target, work->target, sizeof(packet.work.target));
	memcpy(packet.work.midstate, work->midstate, sizeof(packet.work.midstate));
	memcpy(packet.work.data, work->data, sizeof(packet.work.data));
	packet.work.id = work->id;

	if (sendto(info->sockltc, &packet, sizeof(packet), 0, (struct sockaddr *)&(info->toaddr),
			sizeof(info->toaddr)) != sizeof(packet)) {
		applog(LOG_WARNING, "Couldn't send work packet: %s", strerror(errno));
		return false;
	}

	return true;
}

static void gridseed_recv_work_packet(struct cgpu_info *gridseed, GRIDSEED_INFO *info,
					GRIDSEED_PACKET packet, struct sockaddr_in from)
{
	mutex_lock(&info->qlock);
	info->toaddr = from;
	gridseed_send_work_usb(gridseed, packet.work.target, packet.work.midstate,
				packet.work.data, packet.work.id, MODE_SCRYPT_DUAL);
	mutex_unlock(&info->qlock);
}

static int gridseed_send_nonce_packet(GRIDSEED_INFO *info, unsigned char *data)
{
	GRIDSEED_PACKET packet;
	uint32_t nonce;
	int workid;

	if (info->sockltc <= 0)
		return -1;

	memcpy(&workid, data+8, 4);
	memcpy(&nonce, data+4, 4);

	packet.type = PACKET_NONCE;
	packet.nonce.nonce = nonce;
	packet.nonce.workid = workid;

	if (sendto(info->sockltc, &packet, sizeof(packet), 0, (struct sockaddr *)&(info->toaddr),
			sizeof(info->toaddr)) != sizeof(packet)) {
		applog(LOG_WARNING, "Couldn't send nonce packet: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static void gridseed_recv_nonce_packet(struct cgpu_info *gridseed, GRIDSEED_INFO *info,
					GRIDSEED_PACKET packet)
{
	__gridseed_test_ltc_nonce(gridseed, info, info->thr, packet.nonce.nonce, packet.nonce.workid);
}

static void *gridseed_recv_packet(void *userdata)
{
	struct cgpu_info *gridseed = (struct cgpu_info *)userdata;
	GRIDSEED_INFO *info = gridseed->device_data;
	GRIDSEED_PACKET packet;
	struct timeval ts_packet, ts_now, tv_timeout;
	struct sockaddr_in fromaddr;
	fd_set rdfs;
	char threadname[24];
	int addrlen, n, no_packets = 0, sock = info->sockltc;

	snprintf(threadname, sizeof(threadname), "GridSeed_Packet/%d", gridseed->device_id);
	RenameThread(threadname);
	applog(LOG_INFO, "GridSeed: packet thread running, %s", threadname);

	cgtime(&ts_packet); // initialize

	while(likely(!gridseed->shutdown)) {
		cgtime(&ts_now);
		if (info->mode == MODE_SCRYPT_DUAL &&
			tdiff(&ts_now, &ts_packet) > (120 + 60 * no_packets)) {
			if (no_packets > 5) {
				applog(LOG_ERR, "%s%d: Proxy not responding, shutting down",
					gridseed->drv->name, gridseed->device_id);
				gridseed->shutdown = true;
				break;
			} else {
				applog(LOG_NOTICE, "%s%d: No data from proxy, sending ping",
					gridseed->drv->name, gridseed->device_id);
				gridseed_send_ping_packet(info, info->toaddr);
			}
			no_packets++;
		} else if (info->mode == MODE_SHA256_DUAL &&
				tdiff(&ts_now, &ts_packet) > 130) {
			info->mode = MODE_SHA256;

			mutex_lock(&info->qlock);
			gc3355_send_cmds(gridseed, str_ltc_reset);
			cgsleep_ms(50);
			mutex_unlock(&info->qlock);
		}

		tv_timeout.tv_sec = 2;
		tv_timeout.tv_usec = 0;
		FD_ZERO(&rdfs);
		FD_SET(sock, &rdfs);
		n = select(sock+1, &rdfs, NULL, NULL, &tv_timeout);
		if (n == 0)
			continue;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			applog(LOG_ERR, "Error calling select: %s", strerror(errno));
			gridseed->shutdown = true;
			break;
		}

		addrlen = sizeof(fromaddr);
		n = recvfrom(sock, &packet, sizeof(packet), 0, (struct sockaddr *)&fromaddr, (socklen_t *)&addrlen);
		if (n != sizeof(packet))
			continue;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			applog(LOG_ERR, "Error calling recvfrom: %s", strerror(errno));
			gridseed->shutdown = true;
			break;
		}
		cgtime(&ts_packet);

		switch (packet.type) {
			case PACKET_PING:
				if (!SHA256_MODE(info->mode))
					break;
				gridseed_send_info_packet(info, fromaddr);
				applog(LOG_INFO, "Received ping packet");
				break;
			case PACKET_INFO:
				if (!SCRYPT_MODE(info->mode))
					break;
				gridseed_recv_info_packet(gridseed, info, packet, fromaddr);
				applog(LOG_INFO, "Received info packet");
				break;
			case PACKET_WORK:
				if (!SHA256_MODE(info->mode))
					break;
				info->mode = MODE_SHA256_DUAL;
				gridseed_recv_work_packet(gridseed, info, packet, fromaddr);
				applog(LOG_INFO, "Received work packet");
				break;
			case PACKET_NONCE:
				if (!SCRYPT_MODE(info->mode))
					break;
				gridseed_recv_nonce_packet(gridseed, info, packet);
				applog(LOG_INFO, "Received nonce packet");
				break;
			default:
				applog(LOG_ERR, "Received unknown packet");
				break;
		}
	}
	return NULL;
}

/*---------------------------------------------------------------------------------------*/

static void _transfer(struct cgpu_info *gridseed, uint8_t request_type, uint8_t bRequest,
		uint16_t wValue, uint16_t wIndex, uint32_t *data, int siz, enum usb_cmds cmd)
{
	int err;

	err = usb_transfer_data(gridseed, request_type, bRequest, wValue, wIndex, data, siz, cmd);
	cgsleep_ms(GRIDSEED_COMMAND_DELAY);

	applog(LOG_DEBUG, "%s: cgid %d %s got err %d",
			gridseed->drv->name, gridseed->cgminer_id,
			usb_cmdname(cmd), err);
}

static int gc3355_write(struct cgpu_info *gridseed, unsigned char *data, int size)
{
	int err, wrote;

#if 1
	if (!opt_quiet && opt_debug) {
		int i;
#ifndef WIN32
		fprintf(stderr, "[1;33m >>> %d : [0m", size);
#else
		set_text_color(FOREGROUND_RED|FOREGROUND_GREEN);
		fprintf(stderr, " >>> %d : ", size);
		set_text_color(FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE);
#endif
		for(i=0; i<size; i++) {
			fprintf(stderr, "%02x", data[i]);
			if (i==3)
				fprintf(stderr, " ");
		}
		fprintf(stderr, "\n");
	}
#endif
	err = usb_write(gridseed, (char *)data, size, &wrote, C_SENDWORK);
	if (err != LIBUSB_SUCCESS || wrote != size)
		return -1;

	cgsleep_ms(GRIDSEED_COMMAND_DELAY);
	return 0;
}

#define gc3355_get_data(gridseed, buf, size) gc3355_read(gridseed, buf, size, NULL)
static int gc3355_read(struct cgpu_info *gridseed, unsigned char *buf, int size, int *amount)
{
	int err = 0, offset = 0, end = 0;

	while (offset == 0 && likely(!gridseed->shutdown)) {
		err = usb_read_once_timeout(gridseed, (char *)buf + offset, size - offset, &end, 2000, C_GETRESULTS);
		if (err && err != LIBUSB_ERROR_TIMEOUT)
			break;
		offset += end;
	}

	if (amount != NULL)
		*amount = offset;

	if (!opt_quiet && opt_debug) {
		int i;
#ifndef WIN32
		fprintf(stderr, "[1;31m <<< %d : [0m", offset);
#else
		set_text_color(FOREGROUND_RED);
		fprintf(stderr, " <<< %d : ", offset);
		set_text_color(FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE);
#endif
		for(i = 0; i < offset; i++) {
			fprintf(stderr, "%02x", buf[i]);
			if ((i+1) % 4 == 0)
				fprintf(stderr, " ");
		}
		fprintf(stderr, "\n");
	}

	if (amount == NULL)
		return !(size == offset);
	else
		return err;
}

static void gc3355_send_cmds(struct cgpu_info *gridseed, const char *cmds[])
{
	unsigned char ob[512];
	int i;

	for(i=0; cmds[i] != NULL; i++) {
		hex2bin(ob, cmds[i], sizeof(ob));
		gc3355_write(gridseed, ob, strlen(cmds[i])/2);
	}
}

static void gc3355_send_cmds_bin(struct cgpu_info *gridseed, const char *cmds[], int size)
{
	int i;

	for(i=0; cmds[i] != NULL; i++) {
		gc3355_write(gridseed, (unsigned char *)cmds[i], size);
	}
}

static bool gc3355_read_register(struct cgpu_info *gridseed, uint32_t reg_addr,
				 uint32_t *reg_value) {
	GRIDSEED_INFO *info = (GRIDSEED_INFO*)(gridseed->device_data);
	unsigned char cmd[16] = "\x55\xaa\xc0\x01";
	uint32_t reg_len = 4;
	unsigned char buf[4];

	if (info->fw_version != 0x01140113) {
		applog(LOG_ERR, "Can't read registers; incompatible firmware %08X on %s%d",
			info->fw_version, gridseed->drv->name, gridseed->device_id);
		return false;
	}

	*(uint32_t *)(cmd + 4) = htole32(reg_addr);
	*(uint32_t *)(cmd + 8) = htole32(reg_len);
	*(uint32_t *)(cmd + 12) = htole32(reg_len);
	if (gc3355_write(gridseed, cmd, sizeof(cmd))) {
		applog(LOG_DEBUG, "Failed to write data to %s%d", gridseed->drv->name, gridseed->device_id);
		return false;
	}

	if (gc3355_get_data(gridseed, buf, 4)) {
		applog(LOG_DEBUG, "No response from %s%d", gridseed->drv->name, gridseed->device_id);
		return false;
	}
	*reg_value = le32toh(*(uint32_t *)buf);
	return true;
}

static bool gc3355_write_register(struct cgpu_info *gridseed, uint32_t reg_addr,
				  uint32_t reg_value) {
	GRIDSEED_INFO *info = (GRIDSEED_INFO*)(gridseed->device_data);
	unsigned char cmd[16] = "\x55\xaa\xc0\x02";
	uint32_t reg_len = 4;
	unsigned char buf[4];

	if (info->fw_version != 0x01140113) {
		applog(LOG_ERR, "Can't write registers; incompatible firmware %08X on %s%d",
			info->fw_version, gridseed->drv->name, gridseed->device_id);
		return false;
	}

	*(uint32_t *)(cmd + 4) = htole32(reg_addr);
	*(uint32_t *)(cmd + 8) = htole32(reg_value);
	*(uint32_t *)(cmd + 12) = htole32(reg_len);
	if (gc3355_write(gridseed, cmd, sizeof(cmd)) != 0) {
		applog(LOG_DEBUG, "Failed to write data to %s%d", gridseed->drv->name, gridseed->device_id);
		return false;
	}

	if (gc3355_get_data(gridseed, buf, 4)) {
		applog(LOG_DEBUG, "No response from %s%d", gridseed->drv->name, gridseed->device_id);
		return false;
	}
	return true;
}

static void gc3355_switch_leds(struct cgpu_info *gridseed) {
	uint32_t reg_value;

	// Set GPIOB pins 0 and 1 as general purpose output, open-drain, 50 MHz max
	if (!gc3355_read_register(gridseed, GRIDSEED_GPIOB_BASE + GRIDSEED_CRL_OFFSET, &reg_value)) {
		applog(LOG_DEBUG, "Failed to read GPIOA CRL register from %i", gridseed->device_id);
		return;
	}
	reg_value = (reg_value & 0xffffff00) | 0x00000077;
	if (!gc3355_write_register(gridseed, GRIDSEED_GPIOB_BASE + GRIDSEED_CRL_OFFSET, reg_value)) {
		applog(LOG_DEBUG, "Failed to write GPIOA CRL register from %i", gridseed->device_id);
		return;
	}

	applog(LOG_NOTICE, "%s%d: Turned off GC3355 LEDs",
			gridseed->drv->name, gridseed->device_id);
}

static void gc3355_switch_voltage(struct cgpu_info *gridseed) {
	uint32_t reg_value;

	// Put GPIOA pin 5 into general function, 50 MHz output.
	if (!gc3355_read_register(gridseed, GRIDSEED_GPIOA_BASE + GRIDSEED_CRL_OFFSET, &reg_value)) {
		applog(LOG_DEBUG, "Failed to read GPIOA CRL register from %s%d", gridseed->drv->name, gridseed->device_id);
		return;
	}
	reg_value = (reg_value & 0xff0fffff) | 0x00300000;
	if (!gc3355_write_register(gridseed, GRIDSEED_GPIOA_BASE + GRIDSEED_CRL_OFFSET, reg_value)) {
		applog(LOG_DEBUG, "Failed to write GPIOA CRL register from %s%d", gridseed->drv->name, gridseed->device_id);
		return;
	}

	// Set GPIOA pin 5 high.
	if (!gc3355_read_register(gridseed, GRIDSEED_GPIOA_BASE + GRIDSEED_ODR_OFFSET, &reg_value)) {
		applog(LOG_DEBUG, "Failed to read GPIOA ODR register from %s%d", gridseed->drv->name, gridseed->device_id);
		return;
	}
	reg_value |= 0x00000020;
	if (!gc3355_write_register(gridseed, GRIDSEED_GPIOA_BASE + GRIDSEED_ODR_OFFSET, reg_value)) {
		applog(LOG_DEBUG, "Failed to write GPIOA ODR register from %s%d", gridseed->drv->name, gridseed->device_id);
		return;
	}

	applog(LOG_NOTICE, "%s%d: Switched GC3355 voltage to alternate voltage",
			gridseed->drv->name, gridseed->device_id);
}

static void gc3355_set_init_nonce(struct cgpu_info *gridseed)
{
	GRIDSEED_INFO *info;
	int i;
	char **cmds, *p;
	uint32_t nonce, step;

	info = (GRIDSEED_INFO*)(gridseed->device_data);
	cmds = calloc(sizeof(char*)*(info->chips+1), 1);
	if (unlikely(!cmds))
		quit(1, "Failed to calloc init nonce commands data array");

	step = 0xffffffff / info->chips;
	for(i=0; i<info->chips; i++) {
		p = calloc(8, 1);
		if (unlikely(!p))
			quit(1, "Failed to calloc init nonce commands data");
		memcpy(p, "\x55\xaa\x00\x00", 4);
		p[2] = i;
		nonce = htole32(step*i);
		memcpy(p+4, &nonce, sizeof(nonce));
		cmds[i] = p;
	}
	cmds[i] = NULL;
	gc3355_send_cmds_bin(gridseed, (const char **)cmds, 8);

	for(i=0; i<info->chips; i++)
		free(cmds[i]);
	free(cmds);
}

static void gc3355_enable_btc_cores(struct cgpu_info *gridseed, GRIDSEED_INFO *info)
{
	unsigned char cmd[24], c1, c2;
	uint16_t	mask;
	int i;

	mask = 0x00;
	for(i=0; i<info->btcore; i++)
		mask = mask << 1 | 0x01;

	if (mask == 0)
		return;

	c1 = mask & 0x00ff;
	c2 = mask >> 8;

	memset(cmd, 0, sizeof(cmd));
	memcpy(cmd, "\x55\xAA\xEF\x02", 4);
	for(i=4; i<24; i++) {
		cmd[i] = ((i%2)==0) ? c1 : c2;
		gc3355_write(gridseed, cmd, sizeof(cmd));
	}
}

static void gc3355_set_core_freq(struct cgpu_info *gridseed)
{
	GRIDSEED_INFO *info = (GRIDSEED_INFO*)(gridseed->device_data);

	gc3355_write(gridseed, info->cmd_freq, sizeof(info->cmd_freq));
	if (SHA256_MODE(info->mode)) {
		gc3355_write(gridseed, info->cmd_btc_baud, sizeof(info->cmd_btc_baud));
	}

	applog(LOG_NOTICE, "%s%d: Set GC3355 core frequency to %d MHz",
			gridseed->drv->name, gridseed->device_id, info->freq);
}

static void gc3355_init(struct cgpu_info *gridseed, GRIDSEED_INFO *info)
{
	char buf[512];
	int amount;

	applog(LOG_NOTICE, "%s%d: System reseting", gridseed->drv->name, gridseed->device_id);
	gc3355_send_cmds(gridseed, str_reset);
	cgsleep_ms(200);
	usb_buffer_clear(gridseed);
	usb_read_timeout(gridseed, buf, sizeof(buf), &amount, 10, C_GETRESULTS);
	gc3355_send_cmds(gridseed, str_init);
	gc3355_send_cmds(gridseed, str_ltc_reset);
	gc3355_set_core_freq(gridseed);

	if (SHA256_MODE(info->mode)) {
		gc3355_set_init_nonce(gridseed);
		gc3355_enable_btc_cores(gridseed, info);
		if (info->usefifo == 0)
			gc3355_send_cmds(gridseed, str_nofifo);
	}

	if (info->voltage)
		gc3355_switch_voltage(gridseed);
	if (info->led)
		gc3355_switch_leds(gridseed);
}

static void set_freq_cmd(GRIDSEED_INFO *info, int pll_r, int pll_f, int pll_od)
{
	if (pll_r == 0 && pll_f == 0 && pll_od == 0) {
		// Support frequency increments of 12.5 MHz
		// Non-integer frequencies must be specified rounded up
		// With these values the minimum we can set is 12.5 and the max 1600
		pll_r = 1;
		pll_f = 2 * info->freq / GRIDSEED_F_IN - 1;
		pll_f = MAX(0, MIN(127, pll_f));
	}

	double f_ref = GRIDSEED_F_IN / (pll_r + 1.);
	double f_vco = f_ref * (pll_f + 1.);
	double f_out = f_vco / (1 << pll_od);
	int pll_bs = (f_out >= 500.) ? 1 : 0;
	int cfg_pm = 1, pll_clk_gate = 1;
	uint32_t cmdf = (cfg_pm << 0) | (pll_clk_gate << 2) | (pll_r << 16) |
		(pll_f << 21) | (pll_od << 28) | (pll_bs << 31);
	info->freq = (int)ceil(f_out);
	memcpy(info->cmd_freq, "\x55\xaa\xef\x00", 4);
	//*(uint32_t *)(info->cmd_freq + 4) = htole32(cmdf);
	cmdf = htole32(cmdf);
	memcpy(info->cmd_freq + 4, &cmdf, 4);

	uint32_t cmdb = 0x40000000 | ((uint32_t)round(f_out * 1000000. / info->baud) & 0xffff);
	cmdb = htole32(cmdb);
	memcpy(info->cmd_btc_baud, "\x55\xaa\x0f\xff", 4);
	memcpy(info->cmd_btc_baud + 4, &cmdb, 4);
}

static bool get_options(GRIDSEED_INFO *info, char *options)
{
	char *ss, *p, *end, *comma, *eq;
	int tmp, pll_r = 0, pll_f = 0, pll_od = 0;

	if (options == NULL)
		return false;

	applog(LOG_NOTICE, "GridSeed options: '%s'", options);
	ss = strdup(options);
	p  = ss;
	end = p + strlen(p);

another:
	comma = strchr(p, ',');
	if (comma != NULL)
		*comma = '\0';
	eq = strchr(p, '=');
	if (eq == NULL)
		goto next;
	*eq = '\0';

	tmp = atoi(eq+1);
	if (strcasecmp(p, "baud")==0) {
		info->baud = (tmp != 0) ? tmp : info->baud;
	}
	else if (strcasecmp(p, "freq")==0) {
		info->freq = tmp;
	}
	else if (strcasecmp(p, "pll_r")==0) {
		pll_r = (tmp != 0) ? tmp : pll_r;
		pll_r = MAX(0, MIN(31, pll_r));
	}
	else if (strcasecmp(p, "pll_f")==0) {
		pll_f = (tmp != 0) ? tmp : pll_f;
		pll_f = MAX(0, MIN(127, pll_f));
	}
	else if (strcasecmp(p, "pll_od")==0) {
		pll_od = (tmp != 0) ? tmp : pll_od;
		pll_od = MAX(0, MIN(4, pll_od));
	}
	else if (strcasecmp(p, "chips")==0) {
		info->chips = (tmp != 0) ? tmp : info->chips;
		info->chips = MAX(0, MIN(GRIDSEED_MAX_CHIPS, info->chips));
	}
	else if (strcasecmp(p, "modules")==0) {
		info->modules = (tmp != 0) ? tmp : info->modules;
	}
	else if (strcasecmp(p, "usefifo")==0) {
		info->usefifo = tmp;
	}
	else if (strcasecmp(p, "btc")==0) {
		info->btcore = tmp;
	}
	else if (strcasecmp(p, "voltage")==0) {
		info->voltage = (tmp != 0) ? tmp : info->voltage;
	}
	else if (strcasecmp(p, "led_off")==0) {
		info->led = (tmp != 0) ? tmp : info->led;
	}
	else if (strcasecmp(p, "per_chip_stats")==0) {
		info->per_chip_stats = (tmp != 0) ? tmp : info->per_chip_stats;
	}
	else if (strcasecmp(p, "start_port")==0) {
		info->ltc_port = tmp;
	}

next:
	if (comma != NULL) {
		p = comma + 1;
		if (p < end)
			goto another;
	}
	free(ss);

	set_freq_cmd(info, pll_r, pll_f, pll_od);

	return true;
}

static bool get_freq(GRIDSEED_INFO *info, char *options)
{
	char *ss, *p, *end, *comma, *eq;
	int tmp;

	if (options == NULL)
		return false;

	applog(LOG_NOTICE, "GridSeed freq options: '%s'", options);
	ss = strdup(options);
	p  = ss;
	end = p + strlen(p);

another:
	comma = strchr(p, ',');
	if (comma != NULL)
		*comma = '\0';
	eq = strchr(p, '=');
	if (eq == NULL)
		goto next;
	*eq = '\0';

	tmp = atoi(eq+1);
	if (strcasecmp(p, info->serial)==0) {
		info->freq = tmp;
		set_freq_cmd(info, 0, 0, 0);
		if (info->freq == tmp)
			applog(LOG_INFO, "%s unique frequency: %i MHz", p, info->freq);
		else
			applog(LOG_NOTICE, "%s unique frequency: requested %i MHz, using instead %i MHz", p, tmp, info->freq);
	}

next:
	if (comma != NULL) {
		p = comma + 1;
		if (p < end)
			goto another;
	}
	free(ss);

	return true;
}

static bool get_override(GRIDSEED_INFO *info, char *options)
{
	char *ss, *p, *colon, *semi;
	bool ret = false;

	if (options == NULL)
		return false;

	ss = strdup(options);
	p  = ss;

	do {
		semi = strchr(p, ';');
		if (semi != NULL)
			*semi = '\0';
		colon = strchr(p, ':');
		if (colon == NULL)
			continue;
		*colon = '\0';

		if (strcasecmp(p, info->serial) == 0) {
			ret = get_options(info, colon + 1);
			break;
		}
	} while (semi != NULL && (p = semi + 1));

	free(ss);

	return ret;
}

static int gridseed_cp210x_init(struct cgpu_info *gridseed, int interface)
{
	// Enable the UART
	transfer(gridseed, CP210X_TYPE_OUT, CP210X_REQUEST_IFC_ENABLE, CP210X_VALUE_UART_ENABLE,
			interface, C_ENABLE_UART);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set data control
	transfer(gridseed, CP210X_TYPE_OUT, CP210X_REQUEST_DATA, CP210X_VALUE_DATA,
			interface, C_SETDATA);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set the baud
	uint32_t data = CP210X_DATA_BAUD;
	_transfer(gridseed, CP210X_TYPE_OUT, CP210X_REQUEST_BAUD, 0,
			interface, &data, sizeof(data), C_SETBAUD);

	return 0;
}

static int gridseed_ftdi_init(struct cgpu_info *gridseed, int interface)
{
	int err;

	// Reset
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_RESET,
				FTDI_VALUE_RESET, interface, C_RESET);

	applog(LOG_DEBUG, "%s%i: reset got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set latency
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_LATENCY,
			   GRIDSEED_LATENCY, interface, C_LATENCY);

	applog(LOG_DEBUG, "%s%i: latency got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set data
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_DATA,
				FTDI_VALUE_DATA_AVA, interface, C_SETDATA);

	applog(LOG_DEBUG, "%s%i: data got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set the baud
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_BAUD, FTDI_VALUE_BAUD_AVA,
				(FTDI_INDEX_BAUD_AVA & 0xff00) | interface,
				C_SETBAUD);

	applog(LOG_DEBUG, "%s%i: setbaud got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set Modem Control
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_MODEM,
				FTDI_VALUE_MODEM, interface, C_SETMODEM);

	applog(LOG_DEBUG, "%s%i: setmodemctrl got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set Flow Control
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_FLOW,
				FTDI_VALUE_FLOW, interface, C_SETFLOW);

	applog(LOG_DEBUG, "%s%i: setflowctrl got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	/* Avalon repeats the following */
	// Set Modem Control
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_MODEM,
				FTDI_VALUE_MODEM, interface, C_SETMODEM);

	applog(LOG_DEBUG, "%s%i: setmodemctrl 2 got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set Flow Control
	err = usb_transfer(gridseed, FTDI_TYPE_OUT, FTDI_REQUEST_FLOW,
				FTDI_VALUE_FLOW, interface, C_SETFLOW);

	applog(LOG_DEBUG, "%s%i: setflowctrl 2 got err %d",
		gridseed->drv->name, gridseed->device_id, err);

	if (gridseed->usbinfo.nodev)
		return -1;

	return 0;
}

static int gridseed_pl2303_init(struct cgpu_info *gridseed, int interface)
{
	// Set Data Control
	transfer(gridseed, PL2303_CTRL_OUT, PL2303_REQUEST_CTRL, PL2303_VALUE_CTRL,
			 interface, C_SETDATA);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Set Line Control
	uint32_t ica_data[2] = { PL2303_VALUE_LINE0, PL2303_VALUE_LINE1 };
	_transfer(gridseed, PL2303_CTRL_OUT, PL2303_REQUEST_LINE, PL2303_VALUE_LINE,
			 interface, &ica_data[0], PL2303_VALUE_LINE_SIZE, C_SETLINE);

	if (gridseed->usbinfo.nodev)
		return -1;

	// Vendor
	transfer(gridseed, PL2303_VENDOR_OUT, PL2303_REQUEST_VENDOR, PL2303_VALUE_VENDOR,
			 interface, C_VENDOR);

	return 0;
}

static int gridseed_initialise(struct cgpu_info *gridseed, GRIDSEED_INFO *info)
{
	int err, interface;

	if (gridseed->usbinfo.nodev)
		return -1;

	interface = usb_interface(gridseed);
	info->ident = usb_ident(gridseed);

	switch(info->ident) {
		case IDENT_GSD:
			err = 0;
			break;
		case IDENT_GSD1:
			err = gridseed_cp210x_init(gridseed, interface);
			break;
		case IDENT_GSD2:
			err = gridseed_ftdi_init(gridseed, interface);
			break;
		case IDENT_GSD3:
			err = gridseed_pl2303_init(gridseed, interface);
			break;
		default:
			err = -1;
			applog(LOG_DEBUG, "gridseed_intialise() called with invalid %s cgid %i ident=%d",
				gridseed->drv->name, gridseed->cgminer_id, info->ident);
	}

	return err;
}

static struct cgpu_info *gridseed_detect_one_scrypt_proxy()
{
	struct cgpu_info *gridseed;
	GRIDSEED_INFO *info;

	gridseed = calloc(1, sizeof(*gridseed));
	if (unlikely(!gridseed))
		return NULL;
	info = calloc(1, sizeof(*info));
	if (unlikely(!info))
		goto shin;

	gridseed->drv = &gridseed_drv;
	gridseed->threads = GRIDSEED_MINER_THREADS;
	gridseed->deven = DEV_ENABLED;
	gridseed->device_data = (void *)info;

	info->mode = MODE_SCRYPT_DUAL;

	info->baud = GRIDSEED_DEFAULT_BAUD;
	info->freq = GRIDSEED_DEFAULT_FREQUENCY;
	info->chips = GRIDSEED_DEFAULT_CHIPS;
	info->modules = GRIDSEED_DEFAULT_MODULES;
	info->usefifo = GRIDSEED_DEFAULT_USEFIFO;
	info->btcore = GRIDSEED_DEFAULT_BTCORE;
	info->voltage = 0;
	info->led = 0;
	info->per_chip_stats = 0;
	memset(info->nonce_count, 0, sizeof(info->nonce_count));
	memset(info->error_count, 0, sizeof(info->error_count));
	set_freq_cmd(info, 0, 0, 0);
	info->ltc_port = GRIDSEED_PROXY_PORT;
	cgsem_init(&info->psem);

	get_options(info, opt_gridseed_options);

	if (gridseed_find_proxy(info))
		goto unshin;

	if (!add_cgpu(gridseed))
		goto unshin;

	return gridseed;

unshin:
	free(info);
	gridseed->device_data = NULL;

shin:
	free(gridseed);
	return NULL;
}

static struct cgpu_info *gridseed_detect_one_usb(struct libusb_device *dev, struct usb_find_devices *found)
{
	struct cgpu_info *gridseed;
	GRIDSEED_INFO *info;
	unsigned char rbuf[GRIDSEED_READ_SIZE];
	const char detect_cmd[] = "55aac000909090900000000001000000";
	unsigned char detect_data[16];

	gridseed = usb_alloc_cgpu(&gridseed_drv, GRIDSEED_MINER_THREADS);
	if (!usb_init(gridseed, dev, found))
		goto shin;

	libusb_reset_device(gridseed->usbdev->handle);

	info = (GRIDSEED_INFO*)calloc(1, sizeof(GRIDSEED_INFO));
	if (unlikely(!info))
		quit(1, "Failed to calloc gridseed_info data");
	gridseed->device_data = (void *)info;

	update_usb_stats(gridseed);

	if (opt_scrypt)
		info->mode = MODE_SCRYPT;
	else
		info->mode = MODE_SHA256;

	info->baud = GRIDSEED_DEFAULT_BAUD;
	info->freq = GRIDSEED_DEFAULT_FREQUENCY;
	info->chips = GRIDSEED_DEFAULT_CHIPS;
	info->modules = GRIDSEED_DEFAULT_MODULES;
	info->usefifo = GRIDSEED_DEFAULT_USEFIFO;
	info->btcore = GRIDSEED_DEFAULT_BTCORE;
	info->voltage = 0;
	info->led = 0;
	info->per_chip_stats = 0;
	memset(info->nonce_count, 0, sizeof(info->nonce_count));
	memset(info->error_count, 0, sizeof(info->error_count));
	strncpy(info->serial, gridseed->usbdev->serial_string, sizeof(info->serial));
	info->serial[sizeof(info->serial)-1] = '\0';
	gridseed->unique_id = info->serial;
	set_freq_cmd(info, 0, 0, 0);
	info->ltc_port = GRIDSEED_PROXY_PORT;
	cgsem_init(&info->psem);

	get_options(info, opt_gridseed_options);
	get_freq(info, opt_gridseed_freq);
	get_override(info, opt_gridseed_override);

	gridseed->usbdev->usb_type = USB_TYPE_STD;
	if (gridseed_initialise(gridseed, info)) {
		applog(LOG_ERR, "Failed to initialize gridseed device");
		goto unshin;
	}

	/* get MCU firmware version */
	hex2bin(detect_data, detect_cmd, sizeof(detect_data));
	if (gc3355_write(gridseed, detect_data, sizeof(detect_data))) {
		applog(LOG_DEBUG, "Failed to write detect command to gridseed device");
		goto unshin;
	}

	/* waiting for return */
	if (gc3355_get_data(gridseed, rbuf, GRIDSEED_READ_SIZE)) {
		applog(LOG_DEBUG, "No response from gridseed device");
		goto unshin;
	}

	if (memcmp(rbuf, "\x55\xaa\xc0\x00\x90\x90\x90\x90", GRIDSEED_READ_SIZE-4) != 0) {
		applog(LOG_DEBUG, "Bad response from gridseed device");
		goto unshin;
	}

	if (!add_cgpu(gridseed))
		goto unshin;

	info->fw_version = le32toh(*(uint32_t *)(rbuf+GRIDSEED_READ_SIZE-4));
	applog(LOG_NOTICE, "Gridseed device found, firmware v%08X, driver %s, serial %s",
				info->fw_version, gridseed_version, info->serial);

	gc3355_init(gridseed, info);

	return gridseed;

unshin:
	usb_uninit(gridseed);
	free(gridseed->device_data);
	gridseed->device_data = NULL;

shin:
	gridseed = usb_free_cgpu(gridseed);
	return NULL;
}

static bool gridseed_send_query_cmd(struct cgpu_info *gridseed, GRIDSEED_INFO *info)
{
	unsigned char *cmd = (unsigned char *)"\x55\xaa\xc0\x00\xa0\xa0\xa0\xa0\x00\x00\x00\x00\x01\x00\x00\x00";
	cgtimer_t ts_now, ts_res;
	bool ret = false;

	cgtimer_time(&ts_now);
	mutex_lock(&info->qlock);
	if (!info->query_qlen) {
		cgtimer_sub(&ts_now, &info->query_ts, &ts_res);
#ifndef WIN32
		if (ts_res.tv_sec > 0) {
#else
		if (ts_res.QuadPart > 10000000) {
#endif
			if (gc3355_write(gridseed, cmd, 16) == 0) {
				info->query_qlen = true;
				ret = true;
			}
		}
	}
	mutex_unlock(&info->qlock);
	return ret;
}

#define SHA256_TASK_LEN 52
#define SCRYPT_TASK_LEN 156
static bool gridseed_send_work_usb(struct cgpu_info *gridseed,
			unsigned char *target, unsigned char *midstate, unsigned char *data,
			int workid, enum gsd_mode mode)
{
	unsigned char cmd[ MAX(SHA256_TASK_LEN, SCRYPT_TASK_LEN) ];
	int ret;

	if (SHA256_MODE(mode)) {
		memcpy(cmd, "\x55\xaa\x0f\x01", 4);
		memcpy(cmd+4, midstate, 32);
		memcpy(cmd+36, data+64, 12);
		memcpy(cmd+48, &(workid), 4);
	} else {
		gc3355_send_cmds(gridseed, str_ltc_reset);
		cgsleep_ms(50);

		memcpy(cmd, "\x55\xaa\x1f\x00", 4);
		memcpy(cmd+4, target, 32);
		memcpy(cmd+36, midstate, 32);
		memcpy(cmd+68, data, 80);
		memcpy(cmd+148, "\xff\xff\xff\xff", 4);	// nonce_max
		memcpy(cmd+152, &(workid), 4);		// taskid
	}

	ret = gc3355_write(gridseed, cmd, (SHA256_MODE(mode)) ? SHA256_TASK_LEN : SCRYPT_TASK_LEN);
	return (ret == 0);
}

static bool gridseed_send_work(struct cgpu_info *gridseed, GRIDSEED_INFO *info,
				struct work *work)
{
	if (info->mode == MODE_SCRYPT_DUAL)
		return gridseed_send_work_packet(info, work);
	else
		return gridseed_send_work_usb(gridseed, work->target, work->midstate,
						work->data, work->id, info->mode);
}

static void gridseed_get_queue_length(GRIDSEED_INFO *info,
		unsigned char *data)
{
	uint32_t qlen;

	memcpy(&qlen, data+8, 4);
	qlen = htole32(qlen);

	mutex_lock(&info->qlock);
	info->query_qlen = false;
	info->dev_queue_len = GRIDSEED_MCU_QUEUE_LEN - qlen;
	info->needworks = qlen;
	cgtimer_time(&info->query_ts);
	mutex_unlock(&info->qlock);
}

static void gridseed_parse_mcu_command(struct cgpu_info *gridseed, GRIDSEED_INFO *info,
		unsigned char *data)
{
	if (memcmp(data+4, "\xa0\xa0\xa0\xa0", 4) == 0) {
		/* FIFO idle slots */
		gridseed_get_queue_length(info, data);
	} else if (memcmp(data+4, "\x4d\x43\x55\x52\x45\x53\x45\x54", 8) == 0) {
		/* MCU watchdog did HW reset. Re-init GC3355 chips */
		gc3355_init(gridseed, info);
	}
}

static void __gridseed_purge_sha_work_queue(struct cgpu_info *gridseed, GRIDSEED_INFO *info, int newstart)
{
	int i;

	if (newstart <= 0 || newstart >= info->soft_queue_len)
		return;

	for(i=0; i<newstart; i++) {
		work_completed(gridseed, info->workqueue[i]);
		info->workdone++;
	}
	memmove(&(info->workqueue[0]), &(info->workqueue[newstart]),
			sizeof(struct work*)*(info->soft_queue_len - newstart));
	info->soft_queue_len -= newstart;
}

static void __maybe_unused gridseed_purge_sha_work_queue(struct cgpu_info *gridseed, GRIDSEED_INFO *info, int newstart)
{
	mutex_lock(&info->qlock);
	__gridseed_purge_sha_work_queue(gridseed, info, newstart);
	mutex_unlock(&info->qlock);
}

static void __gridseed_purge_scrypt_work(GRIDSEED_INFO *info)
{
	if (info->ltc_work != NULL) {
		free_work(info->ltc_work);
		info->ltc_work = NULL;
	}
}

static void gridseed_purge_scrypt_work(GRIDSEED_INFO *info)
{
	mutex_lock(&info->qlock);
	__gridseed_purge_scrypt_work(info);
	mutex_unlock(&info->qlock);
}

static void gridseed_test_btc_nonce(struct cgpu_info *gridseed, GRIDSEED_INFO *info,
				struct thr_info *thr, unsigned char *data)
{
	struct work *work;
	uint32_t nonce, chip;
	unsigned int workid;
	int index, i;
	bool valid = false;
	bool nowork = false;

	memcpy(&workid, data+8, 4);
	memcpy(&nonce, data+4, 4);
	nonce = htole32(nonce);
	chip = nonce / (0xffffffff / info->chips);

	mutex_lock(&info->qlock);
	nowork = (info->soft_queue_len <= 0);
	for(i=0; i<info->soft_queue_len; i++) {
		struct work *dupwork;
		work = info->workqueue[i];
		if (work->devflag == false)
			continue;
		if (work->id > workid)
			break;
		dupwork = copy_work(work);
		if (dupwork == NULL)
			continue;
		if (test_nonce(dupwork, nonce)) {
			submit_tested_work(thr, dupwork);
			index = i;
			valid = true;
			free_work(dupwork);
			break;
		} else
			free_work(dupwork);
	}
	if (valid)
		__gridseed_purge_sha_work_queue(gridseed, info, index);
	info->nonce_count[chip]++;
	if (!valid && !nowork)
		info->error_count[chip]++;
	mutex_unlock(&info->qlock);

	if (!valid && !nowork)
		inc_hw_errors(thr);
}

static void __gridseed_test_ltc_nonce(struct cgpu_info *gridseed, GRIDSEED_INFO *info,
		struct thr_info *thr, uint32_t nonce, unsigned int workid)
{
	struct timeval tv_workend;
	uint32_t chip = nonce / (0xffffffff / info->chips);
	bool valid = false;

	cgtime(&tv_workend);

	mutex_lock(&info->qlock);
	if (info->ltc_work == NULL) {	/* Work was flushed while the GSD was hashing, *
					 * and no new work has been sent yet. */
		applog(LOG_DEBUG, "%s%d sent nonce for flushed work", gridseed->drv->name, gridseed->device_id);
		mutex_unlock(&info->qlock);
		return;
	}
	/*
	if (work->devflag == false) {
		applog(LOG_ERR, "gridseed_test_ltc_nonce called but work hasn't been sent (G:%d L:%d F:%d)", workid, info->last_work_id, info->flushed);
		mutex_unlock(&info->qlock);
		return;
	}
	*/
	if (info->ltc_work->id != workid) {	/* Work was flushed and new work assigned *
						 * just as the GSD reported its result. */
		applog(LOG_DEBUG, "%s%d sent nonce for old work", gridseed->drv->name, gridseed->device_id);
		mutex_unlock(&info->qlock);
		return;
	}
	if (test_nonce(info->ltc_work, nonce)) {
		submit_tested_work(thr, info->ltc_work);
		valid = true;
	}
	info->workdone++;
	info->hashes_per_ms = (nonce % (0xffffffff / info->chips)) * info->chips / ms_tdiff(&tv_workend, &info->ltc_workstart);
	__gridseed_purge_scrypt_work(info);
	info->nonce_count[chip]++;
	if (!valid)
		info->error_count[chip]++;
	mutex_unlock(&info->qlock);

	if (!valid)
		inc_hw_errors(thr);
}

static void gridseed_test_ltc_nonce(struct cgpu_info *gridseed, GRIDSEED_INFO *info,
		struct thr_info *thr, unsigned char *data)
{
	uint32_t nonce;
	unsigned int workid;

	memcpy(&workid, data+8, 4);
	memcpy(&nonce, data+4, 4);
	nonce = htole32(nonce);

	__gridseed_test_ltc_nonce(gridseed, info, thr, nonce, workid);
}

static void gridseed_parse_response(struct cgpu_info *gridseed, GRIDSEED_INFO *info,
				struct thr_info *thr, unsigned char *readbuf, int *offset)
{
	unsigned char *p;
	int size;

	p = readbuf;
	size = *offset;

one_cmd:
	/* search the starting 0x55 */
	while(size > 0) {
		if (likely(*p == 0x55))
			break;
		p++;
		size--;
	}
	if (size < GRIDSEED_READ_SIZE)
		goto out_cmd;

	switch(p[1]) {
		case 0xaa:
			/* Queue length result */
			gridseed_parse_mcu_command(gridseed, info, p);
			break;
		case 0x10:
			/* BTC result */
			gridseed_test_btc_nonce(gridseed, info, thr, p);
			break;
		case 0x20:
			/* LTC result */
			if (SHA256_MODE(info->mode)) {
				gridseed_send_nonce_packet(info, p);
			} else if (SCRYPT_MODE(info->mode)) {
				gridseed_test_ltc_nonce(gridseed, info, thr, p);
			}
			break;
		default:
			applog(LOG_ERR, "%s%d: Received unknown response",
				gridseed->drv->name, gridseed->device_id);
			break;
	}

	p += GRIDSEED_READ_SIZE;
	size -= GRIDSEED_READ_SIZE;
	goto one_cmd;

out_cmd:
	if (size > 0)
		memmove(readbuf, p, size);
	*offset = size;
}

static bool gridseed_check_new_btc_task(GRIDSEED_INFO *info)
{
	cgtimer_t ts_now, ts_res;
	bool ret = false;

	cgtimer_time(&ts_now);
	mutex_lock(&info->qlock);
	cgtimer_sub(&ts_now, &info->query_ts, &ts_res);
#ifndef WIN32
	if (ts_res.tv_sec > 0 || ts_res.tv_nsec > 350000000) {
#else
	if (ts_res.QuadPart > 3500000) {
#endif
		info->query_qlen = false;
		info->dev_queue_len = 1;
		info->needworks = 1;
		cgtimer_time(&info->query_ts);
		ret = true;
	}
	mutex_unlock(&info->qlock);
	return ret;
}

static bool gridseed_check_new_ltc_work(GRIDSEED_INFO *info)
{
	struct thr_info *thr = info->thr;
	struct work *work;
	const int thr_id = thr->id;
	bool need_work;

	need_work = (info->ltc_work == NULL);

	if (need_work) {
		work = get_work(thr, thr_id);

		mutex_lock(&info->qlock);
		if (info->ltc_work == NULL) {
			work->devflag = false;
			info->ltc_work = work;
		} else {
			need_work = false;
		}
		mutex_unlock(&info->qlock);

		if (!need_work)
			discard_work(work);
	}

	return need_work;
}

/*
 * Thread to read response from Miner device
 */
static void *gridseed_recv_usb(void *userdata)
{
	struct cgpu_info *gridseed = (struct cgpu_info *)userdata;
	GRIDSEED_INFO *info = gridseed->device_data;
	struct thr_info *thr = info->thr;
	char threadname[24];
	unsigned char readbuf[GRIDSEED_READBUF_SIZE];
	int offset = 0, amount, ret;

	snprintf(threadname, sizeof(threadname), "GridSeed_Recv/%d", gridseed->device_id);
	RenameThread(threadname);
	applog(LOG_INFO, "GridSeed: recv thread running, %s", threadname);

	while(likely(!gridseed->shutdown)) {
		if (unlikely(gridseed->usbinfo.nodev)) {
			applog(LOG_ERR, "%s%d: Device disappeared, shutting down",
				gridseed->drv->name, gridseed->device_id);
			gridseed->shutdown = true;
			break;
		}

		ret = gc3355_read(gridseed, readbuf + offset, GRIDSEED_READ_SIZE, &amount);
		if (ret && ret != LIBUSB_ERROR_TIMEOUT) {
			applog(LOG_ERR, "%s%d: Read error %d, read %d", gridseed->drv->name,
				gridseed->device_id, ret, amount);
			continue;
		}
		offset += amount;

		if (offset >= GRIDSEED_READ_SIZE)
			gridseed_parse_response(gridseed, info, thr, readbuf, &offset);

		if (unlikely(offset + GRIDSEED_READ_SIZE >= GRIDSEED_READBUF_SIZE)) {
			applog(LOG_ERR, "%s%d: Read buffer overflow, resetting", gridseed->drv->name, gridseed->device_id);
			offset = 0;
		}
	}
	return NULL;
}

/*
 * Thread to send task and queue length query command to device
 */
static void *gridseed_send(void *userdata)
{
	struct cgpu_info *gridseed = (struct cgpu_info *)userdata;
	GRIDSEED_INFO *info = gridseed->device_data;
	char threadname[24];
	int i;

	snprintf(threadname, sizeof(threadname), "GridSeed_Send/%d", gridseed->device_id);
	RenameThread(threadname);
	applog(LOG_INFO, "GridSeed: send thread running, %s", threadname);

	while(likely(!gridseed->shutdown)) {
		if (SHA256_MODE(info->mode)) {
			cgsleep_ms(50);

			if (info->usefifo == 0) {
				/* mark the first work in queue as complete after several ms */
				if (gridseed_check_new_btc_task(info))
					continue;
			} else {
				/* send query command to device */
				if (gridseed_send_query_cmd(gridseed, info))
					continue;
			}

			/* send task to device */
			mutex_lock(&info->qlock);
			for(i=0; i<info->soft_queue_len; i++) {
				if (info->workqueue[i] && info->workqueue[i]->devflag == false) {
					if (gridseed_send_work(gridseed, info, info->workqueue[i])) {
						info->workqueue[i]->devflag = true;
						break;
					}
				}
			}
			mutex_unlock(&info->qlock);
		} else {
			cgsleep_ms(100);

			if (!gridseed_check_new_ltc_work(info))
				continue;

			/* send task to device */
			mutex_lock(&info->qlock);
			if (info->ltc_work != NULL && !info->ltc_work->devflag &&
				gridseed_send_work(gridseed, info, info->ltc_work)) {
				info->ltc_work->devflag = true;
				cgtime(&info->ltc_workstart);
			}
			mutex_unlock(&info->qlock);
		}
	}
	return NULL;
}

/*========== functions for struct device_drv ===========*/

static int64_t gridseed_scanwork_sha(struct thr_info *);
static int64_t gridseed_scanwork_scrypt(struct thr_info *);

static void gridseed_detect(bool __maybe_unused hotplug)
{
	applog(LOG_DEBUG, "[1;32mEntering[0m %s", __FUNCTION__);
	usb_detect(&gridseed_drv, gridseed_detect_one_usb);
	if (!total_devices && opt_scrypt)
		while (gridseed_detect_one_scrypt_proxy()) {}
}

static bool gridseed_prepare(struct thr_info *thr)
{
	applog(LOG_DEBUG, "[1;32mEntering[0m %s", __FUNCTION__);
	struct cgpu_info *gridseed = thr->cgpu;
	GRIDSEED_INFO *info = gridseed->device_data;

	info->thr = thr;
	mutex_init(&info->lock);
	mutex_init(&info->qlock);

	switch (info->mode) {
		case MODE_SHA256:
		case MODE_SHA256_DUAL:
			gridseed_drv.hash_work = hash_queued_work;
			gridseed_drv.scanwork = gridseed_scanwork_sha;

			info->queued = 0;
			info->dev_queue_len = GRIDSEED_MCU_QUEUE_LEN;
			info->soft_queue_len = 0;
			info->needworks = 0;
			info->query_qlen = false;
			cgtimer_time(&info->query_ts);
			memset(&info->workqueue, 0, sizeof(struct work *)*GRIDSEED_SOFT_QUEUE_LEN);
			info->workdone = 0;
			info->sockltc = -1;

			gridseed_create_proxy(gridseed, info);

			break;
		case MODE_SCRYPT:
		case MODE_SCRYPT_DUAL:
			gridseed_drv.hash_work = hash_driver_work;
			gridseed_drv.scanwork = gridseed_scanwork_scrypt;

			info->workdone = 0;
			info->ltc_work = NULL;
			info->hashes_per_ms = 0;
			cgtime(&info->scanhash_time);

			break;
		default:
			applog(LOG_ERR, "Gridseed driver could not determine SHA or Scrypt mode");
			return false;
	}

	if (info->mode == MODE_SCRYPT_DUAL)
		applog(LOG_NOTICE, "Gridseed %s%d opened on %d/UDP",
			gridseed->drv->name, gridseed->device_id, info->ltc_port);
	else
		applog(LOG_NOTICE, "GridSeed %s%d opened on usb:%s",
			gridseed->drv->name, gridseed->device_id, gridseed->device_path);

	return true;
}

static bool gridseed_thread_init(struct thr_info *thr)
{
	applog(LOG_DEBUG, "[1;32mEntering[0m %s", __FUNCTION__);
	struct cgpu_info *gridseed = thr->cgpu;
	GRIDSEED_INFO *info = gridseed->device_data;

	if (info->mode != MODE_SCRYPT_DUAL) {
		if (pthread_create(&info->th_read, NULL, gridseed_recv_usb, (void*)gridseed)) {
			applog(LOG_ERR, "%s%d: Failed to create read thread", gridseed->drv->name, gridseed->device_id);
			return false;
		}
	}

	if (pthread_create(&info->th_send, NULL, gridseed_send, (void*)gridseed)) {
		applog(LOG_ERR, "%s%d: Failed to create send thread", gridseed->drv->name, gridseed->device_id);
		return false;
	}

	if (pthread_create(&info->th_packet, NULL, gridseed_recv_packet, (void*)gridseed)) {
		applog(LOG_ERR, "%s%d: Failed to create packet thread", gridseed->drv->name, gridseed->device_id);
		return -1;
	}

	return true;
}

static bool gridseed_full(struct cgpu_info *gridseed)
{
	GRIDSEED_INFO *info = gridseed->device_data;
	struct work *work;
	int subid;
	bool ret = true;

	mutex_lock(&info->qlock);
	if (info->needworks <= 0)
		goto out_unlock;

	work = get_queued(gridseed);
	if (unlikely(!work)) {
		ret = false;
		goto out_unlock;
	}
	subid = info->queued++;
	work->subid = subid;
	work->devflag = false; /* true when send to device */

	if (info->soft_queue_len >= GRIDSEED_SOFT_QUEUE_LEN)
		__gridseed_purge_sha_work_queue(gridseed, info, 1);
	info->workqueue[info->soft_queue_len++] = work;
	info->needworks--;

	ret = (info->needworks <= 0);

out_unlock:
	mutex_unlock(&info->qlock);
	return ret;
}

static int64_t gridseed_scanwork_sha(struct thr_info *thr)
{
	struct cgpu_info *gridseed = thr->cgpu;
	GRIDSEED_INFO *info = gridseed->device_data;
	int64_t hashs;

	cgsleep_ms(100);

	mutex_lock(&info->qlock);
	hashs = info->workdone * 0xffffffffL;
	info->workdone = 0;
	mutex_unlock(&info->qlock);
	return hashs;
}

static int64_t gridseed_scanwork_scrypt(struct thr_info *thr)
{
	struct cgpu_info *gridseed = thr->cgpu;
	GRIDSEED_INFO *info = gridseed->device_data;
	struct timeval old_scanhash_time;
	int64_t elapsed_ms;

	cgsleep_ms(100);

	mutex_lock(&info->qlock);
	old_scanhash_time = info->scanhash_time;
	cgtime(&info->scanhash_time);
	elapsed_ms = ms_tdiff(&info->scanhash_time, &old_scanhash_time);
	mutex_unlock(&info->qlock);

#if 0
	return GRIDSEED_HASH_SPEED * (double)elapsed_ms * (double)(info->freq * info->chips * info->modules);
#else
	return info->hashes_per_ms * elapsed_ms;
#endif
}

#define gridseed_update_work gridseed_flush_work
static void gridseed_flush_work(struct cgpu_info *gridseed)
{
	applog(LOG_DEBUG, "[1;32mEntering[0m %s", __FUNCTION__);
	GRIDSEED_INFO *info = gridseed->device_data;

	applog(LOG_INFO, "%s%d: Work updated, flushing work queue", gridseed->drv->name, gridseed->device_id);

	if (SHA256_MODE(info->mode)) {
		int i;

		mutex_lock(&info->qlock);
		for(i=0; i<info->soft_queue_len; i++) {
			work_completed(gridseed, info->workqueue[i]);
		}
		info->soft_queue_len = 0;
		mutex_unlock(&info->qlock);
	} else {
		gridseed_purge_scrypt_work(info);
	}
}

static struct api_data *gridseed_api_stats(struct cgpu_info *gridseed)
{
	applog(LOG_DEBUG, "[1;32mEntering[0m %s", __FUNCTION__);
	GRIDSEED_INFO *info = gridseed->device_data;
	struct api_data *root = NULL;
	char *mode_str;

	switch (info->mode) {
		case MODE_SHA256:
			mode_str = MODE_SHA256_STR;
			break;
		case MODE_SHA256_DUAL:
			mode_str = MODE_SHA256_DUAL_STR;
			break;
		case MODE_SCRYPT:
			mode_str = MODE_SCRYPT_STR;
			break;
		case MODE_SCRYPT_DUAL:
			mode_str = MODE_SCRYPT_DUAL_STR;
			break;
		case MODE_UNK:
		default:
			mode_str = MODE_UNK_STR;
			break;
	}

	root = api_add_string(root, "Mode", mode_str, false);
	root = api_add_string(root, "Serial", info->serial, false);
	root = api_add_int(root, "Frequency", &(info->freq), false);
	root = api_add_int(root, "Baud", &(info->baud), false);
	root = api_add_int(root, "Chips", &(info->chips), false);
	root = api_add_int(root, "BTCore", &(info->btcore), false);
	root = api_add_int(root, "Modules", &(info->modules), false);
	root = api_add_int(root, "Use FIFO", &(info->usefifo), false);
	root = api_add_int(root, "Voltage", &(info->voltage), false);
	root = api_add_int(root, "Per Chip Stats", &(info->per_chip_stats), false);
	if (SHA256_MODE(info->mode) || info->mode == MODE_SCRYPT_DUAL) {
		root = api_add_short(root, "Scrypt Proxy Port", &info->ltc_port, false);
	}
	root = api_add_timeval(root, "LTC Workstart", &(info->ltc_workstart), false);

	return root;
}

static void gridseed_get_statline_before(char *buf, size_t siz, struct cgpu_info *gridseed) {
	GRIDSEED_INFO *info = gridseed->device_data;
	//tailsprintf(buf, siz, "%s %4d MHz", info->serial, info->freq);
	tailsprintf(buf, siz, "%4d MHz  ", info->freq);
	if (info->mode == MODE_SHA256)
		tailsprintf(buf, siz, "SHA256");
	else if (info->mode == MODE_SHA256_DUAL)
		tailsprintf(buf, siz, "DUAL / SHA256");
	else if (info->mode == MODE_SCRYPT)
		tailsprintf(buf, siz, "SCRYPT");
	else if (info->mode == MODE_SCRYPT_DUAL)
		tailsprintf(buf, siz, "DUAL / SCRYPT");
}

static void gridseed_get_statline(char *buf, size_t siz, struct cgpu_info *gridseed) {
	GRIDSEED_INFO *info = gridseed->device_data;
	/* With the per_chip_stats option, print the number of nonces
	 * and (if applicable) HW errors per chip at the end of each
	 * device's status line. This however only works for small numbers
	 * of chips, otherwise the information extends off screen and
	 * the string buffer could overflow */
	if (info->per_chip_stats && info->chips <= GRIDSEED_DEFAULT_CHIPS * 2) {
		int i;
		tailsprintf(buf, siz, " N:");
		for (i = 0; i < info->chips; ++i) {
			tailsprintf(buf, siz, " %d", info->nonce_count[i]);
			if (info->error_count[i])
				tailsprintf(buf, siz, "[%d]", info->error_count[i]);
		}
	}
}

static char *gridseed_set_device(struct cgpu_info *gridseed, char *option, char *setting, char *replybuf)
{
	applog(LOG_DEBUG, "[1;32mEntering[0m %s", __FUNCTION__);
	GRIDSEED_INFO *info = gridseed->device_data;
	int val;

	if (strcasecmp(option, "help") == 0) {
		sprintf(replybuf, "freq: range %d-%d",
				GRIDSEED_MIN_FREQUENCY, GRIDSEED_MAX_FREQUENCY);
		return replybuf;
	}

	if (strcasecmp(option, "freq") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing freq setting");
			return replybuf;
		}

		val = atoi(setting);
		if (val < GRIDSEED_MIN_FREQUENCY || val > GRIDSEED_MAX_FREQUENCY) {
			sprintf(replybuf, "invalid freq: '%s' valid range %d-%d",
						setting, GRIDSEED_MIN_FREQUENCY, GRIDSEED_MAX_FREQUENCY);
			return replybuf;
		}

		info->freq = val;
		set_freq_cmd(info, 0, 0, 0);
		gc3355_set_core_freq(gridseed);
		return NULL;
	}

	sprintf(replybuf, "Unknown option: %s", option);
	return replybuf;
}

static void gridseed_reinit(struct cgpu_info __maybe_unused *gridseed)
{
	applog(LOG_DEBUG, "[1;32mEntering[0m %s", __FUNCTION__);
}

static void gridseed_shutdown(struct thr_info *thr)
{
	applog(LOG_DEBUG, "[1;32mEntering[0m %s", __FUNCTION__);
	struct cgpu_info *gridseed = thr->cgpu;
	GRIDSEED_INFO *info = gridseed->device_data;

	applog(LOG_NOTICE, "%s%d: Shutting down", gridseed->drv->name, gridseed->device_id);
	pthread_join(info->th_packet, NULL);
	pthread_join(info->th_send, NULL);
	if (info->mode != MODE_SCRYPT_DUAL)
		pthread_join(info->th_read, NULL);
	cgsem_destroy(&info->psem);
	mutex_destroy(&info->qlock);
	mutex_destroy(&info->lock);
	if (info->sockltc > 0) {
		close(info->sockltc);
		info->sockltc = -1;
	}
	if (info->mode != MODE_SCRYPT_DUAL)
		gc3355_send_cmds(gridseed, str_reset);
}

static void gridseed_hw_errors(struct thr_info __maybe_unused *thr)
{
	applog(LOG_DEBUG, "[1;32mEntering[0m %s", __FUNCTION__);
#if 0
	struct cgpu_info *gridseed = thr->cgpu;
	GRIDSEED_INFO *info = gridseed->device_data;

	if (gridseed->hw_errors > 5) {
		gc3355_init(gridseed, info, true);
		gridseed->hw_errors = 0;
		applog(LOG_ERR, "HW error, do hardware reset");
	}
#endif
}

/* driver functions */
struct device_drv gridseed_drv = {
	.drv_id = DRIVER_gridseed,
	.dname = "gridseed",
	.name = "GSD",
	.drv_detect = gridseed_detect,
	.thread_prepare = gridseed_prepare,	// called before miner thread is created
	.thread_init = gridseed_thread_init,	// called at start of miner thread
	//.thread_enable = gridseed_thread_enable,
	//.hash_work				// set in gridseed_prepare	// called in miner thread, main loop
	.queue_full = gridseed_full,		// sha256 only			// called to determine if driver needs more work; applies only if hash_work = hash_queued_work
	//.scanwork				// set in gridseed_prepare	// called repeatedly from the loop in hash_work
	.flush_work = gridseed_flush_work,	// called when new block detected on network */
	.update_work = gridseed_update_work,
	.get_api_stats = gridseed_api_stats,
	.get_statline_before = gridseed_get_statline_before,
	.get_statline = gridseed_get_statline,
	.set_device = gridseed_set_device,
	.reinit_device = gridseed_reinit,	// used by watchdog to restart hung drivers
	.thread_shutdown = gridseed_shutdown,	// called last thing in miner thread, after hash_work has returned
	.hw_error = gridseed_hw_errors,		// called from submit_nonce or inc_hw_errors
};
