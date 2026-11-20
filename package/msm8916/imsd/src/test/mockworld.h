/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_TEST_MOCKWORLD_H
#define IMSD_TEST_MOCKWORLD_H
#include "../modem/imsmodem.h"

/*
 * A scripted "world" behind struct uq_ops / netcfg_ops / qrtr_ops: a fake
 * uqmid with one modem, an ISIM card, an IMS bearer, the netdev
 * configuration counters and the QRTR lookup. Every reply is delivered from
 * a 0 ms timer of the fake event loop, like the real asynchronous backend.
 */
struct world {
	/* uqmid */
	bool modem_exists;
	char mpath[64], mdev[96], state[16], imei[24], imsi[24], iccid[32];
	/* bearers */
	struct { bool used; char path[64]; char apn[32]; char status[16]; } br[6];
	int next_br;
	char ifname[16], addr[48];
	int prefix, mtu;
	char pcscf[4][48];
	int n_pcscf;
	bool create_fail, connect_fail;
	char connect_err[80];
	/* card */
	char impi[128], domain[96], impu[4][160], fqdn[3][48];
	int n_impu, n_fqdn;
	int aka_mode;		/* 0 ok, 1 sync failure, 2 card error */
	bool read_fail;		/* EF_IMPI cannot be read */
	int chan_next;
	bool chan_open[8];
	int fail_apdu;		/* the next n APDU calls fail with "channel closed" */
	int selected;
	uint8_t rand[16];
	/* USIM / serving cell */
	char chan_aid[8][20];
	uint8_t smsp[64];	/* EF_SMSP record 1 (smsp_len 0: file not found, 6A82) */
	size_t smsp_len;
	bool smsp_6c;		/* answer the first READ RECORD with 6C <len> */
	bool smsp_61;		/* answer READ RECORD with 61 <len>, data with GET RESPONSE */
	uint8_t psi_isim[64], psi_usim[64];	/* EF_PSISMSC content (len 0: file not found) */
	size_t psi_isim_len, psi_usim_len;
	bool usim_open_fail;
	int n_usim_open, n_usim_close, n_usim_apdu, n_usim_select;
	bool cell_present;	/* a serving LTE cell is reported */
	char cell_plmn[8];
	unsigned cell_tac, cell_ci, cell_earfcn;
	bool cell_has_earfcn, cell_fail;
	bool hang_psi_select;	/* the SELECT of EF_PSISMSC on the ISIM never gets an answer */
	/* hang: no reply (the imsmodem timeout has to fire) */
	bool hang[16];
	/* counters */
	int n_call[16];
	int n_apdu, n_select, n_read, n_chan_open, n_chan_close, n_delete, n_enable, n_watch;
	char last_watch[64];
	struct uq_req last_create;
	/* netcfg */
	int net_apply, net_remove;
	bool net_active, net_fail;
	struct netcfg_params net_last;
	/* qrtr */
	int qrtr_present, n_qrtr;
	bool qrtr_hang;
	/* link callbacks */
	int n_link;
	struct ims_link link;
};

extern struct world W;
void world_reset(void);
/* give the card the EF_SMSP record of the test SIM (SMSC +821080010585) */
void world_set_smsp(void);
struct imsmodem_ops world_ops(void);
/* number of bearers currently existing */
int world_bearers(void);
#endif
