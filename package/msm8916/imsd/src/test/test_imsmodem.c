/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include "test.h"
#include "mockworld.h"
#include "evloop_fake.h"

static struct imsmodem *M;
static struct imsmodem_cfg CFG;

static void setup(void)
{
	struct imsmodem_ops o;

	evfake_reset();
	world_reset();
	imsmodem_cfg_defaults(&CFG);
	o = world_ops();
	(void)o;
}

static void start(void)
{
	struct imsmodem_ops o = world_ops();

	M = imsmodem_new(&CFG, &o);
	imsmodem_uqmid_up(M, true);
	evfake_advance(200);
}

static void teardown(void)
{
	imsmodem_free(M);
	M = NULL;
}

static void pump(unsigned ms)
{
	evfake_advance(ms);
}

/* ---- AKA collectors ---- */
struct akares {
	int n;
	struct aka_result r[4];
	int order[4];
};

static void aka_cb(void *arg, const struct aka_result *r)
{
	struct akares *a = arg;

	if (a->n < 4)
		a->r[a->n] = *r;
	a->n++;
}

static int shut_done_n;
static void shut_cb(void *arg)
{
	(void)arg;
	shut_done_n++;
}

void test_imsmodem(void)
{
	const struct ims_link *l;
	uint8_t rnd[16], autn[16];
	struct akares ar;
	int i;

	for (i = 0; i < 16; i++) { rnd[i] = i; autn[i] = 0x80 + i; }

	/* ===== happy path ===== */
	setup();
	start();
	l = imsmodem_link(M);
	CHECK(l->ready);
	CHECK_STR(imsmodem_state_name(M), "ready");
	CHECK_STR(l->id.impi, "450061051226862@lte-lguplus.co.kr");
	CHECK_STR(l->id.impu, "sip:01051226862@lte-lguplus.co.kr");	/* record 1 is the emergency identity */
	CHECK_STR(l->id.user, "01051226862");
	CHECK_STR(l->id.domain, "lte-lguplus.co.kr");
	CHECK_STR(l->id.imei, "86883708-366218-5");
	CHECK_STR(l->br.ifname, "wwan0");
	CHECK_EQ(l->br.mtu, 1400); CHECK_EQ(l->br.prefix, 64);
	CHECK(l->br.ours);
	CHECK_EQ(l->n_pcscf, 2); CHECK_EQ(l->pcscf_src, PCSCF_NETWORK);
	CHECK_STR(l->pcscf[0], "2001:4430:5:405::43");
	CHECK_STR(l->reason, "");
	CHECK_STR(W.last_create.str, "IMS"); CHECK_STR(W.last_create.str2, "ipv6"); CHECK_EQ(W.last_create.num, 6);
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 1); CHECK_EQ(W.n_call[UQ_BEARER_CONNECT], 1);
	CHECK_EQ(W.n_qrtr, 1);
	CHECK_EQ(W.net_apply, 1); CHECK(W.net_active);
	CHECK_STR(W.net_last.ifname, "wwan0"); CHECK_EQ(W.net_last.table, 1006); CHECK_EQ(W.net_last.mtu, 1400);
	CHECK_STR(W.last_watch, "uqmid.modem.0");
	CHECK_EQ(W.n_call[UQ_SIM_GET], 1);
	CHECK(W.n_chan_open >= 1);
	/* the ISIM files were read: IMPI, DOMAIN, IMPU records 1-2 (stops at the first usable one), P-CSCF records */
	CHECK(W.n_select >= 4);
	/* the link was published once as "ready" (plus the transient not-ready states) */
	CHECK(W.link.ready);
	/* idle channel closes after 20 s */
	CHECK_EQ(W.n_chan_close, 1);	/* the ISIM channel is closed before the USIM one is opened (few logical channels) */
	pump(21000);
	CHECK_EQ(W.n_chan_close, 1);

	/* ===== AKA service: serialised, channel reuse, error handling ===== */
	memset(&ar, 0, sizeof(ar));
	CHECK_EQ(imsmodem_aka(M, rnd, autn, aka_cb, &ar), 0);
	CHECK_EQ(imsmodem_aka(M, rnd, autn, aka_cb, &ar), 0);
	CHECK_EQ(ar.n, 0);	/* never from inside the call */
	pump(200);
	CHECK_EQ(ar.n, 2);
	CHECK_EQ(ar.r[0].status, AKA_OK); CHECK_EQ(ar.r[0].res_len, 8);
	CHECK(ar.r[0].res[0] == (0 ^ 0x5A) && ar.r[0].res[7] == (7 ^ 0x5A) && ar.r[0].ck[0] == 0x20 && ar.r[0].ik[15] == 0x4f);
	CHECK_EQ(ar.r[1].status, AKA_OK);
	CHECK_EQ(W.n_chan_open, 2);	/* one for identity, one reopened after the idle close; both AKAs shared it */
	{
		int opens = W.n_chan_open;

		/* sync failure */
		W.aka_mode = 1; memset(&ar, 0, sizeof(ar));
		imsmodem_aka(M, rnd, autn, aka_cb, &ar); pump(100);
		CHECK_EQ(ar.n, 1); CHECK_EQ(ar.r[0].status, AKA_SYNC_FAIL); CHECK_EQ(ar.r[0].auts_len, 14); CHECK_EQ(ar.r[0].auts[0], 0xA0);
		/* card error (MAC failure) */
		W.aka_mode = 2; memset(&ar, 0, sizeof(ar));
		imsmodem_aka(M, rnd, autn, aka_cb, &ar); pump(100);
		CHECK_EQ(ar.n, 1); CHECK_EQ(ar.r[0].status, AKA_ERR); CHECK_EQ(ar.r[0].sw, 0x9862);
		W.aka_mode = 0;
		/* channel closed behind our back: reopened once, then fine */
		W.fail_apdu = 1; memset(&ar, 0, sizeof(ar));
		imsmodem_aka(M, rnd, autn, aka_cb, &ar); pump(100);
		CHECK_EQ(ar.n, 1); CHECK_EQ(ar.r[0].status, AKA_OK);
		CHECK_EQ(W.n_chan_open, opens + 1);
		/* persistent failure: error after the single retry */
		W.fail_apdu = 5; memset(&ar, 0, sizeof(ar));
		imsmodem_aka(M, rnd, autn, aka_cb, &ar); pump(100);
		CHECK_EQ(ar.n, 1); CHECK_EQ(ar.r[0].status, AKA_ERR);
		W.fail_apdu = 0;
		/* cancel: no callback */
		memset(&ar, 0, sizeof(ar));
		imsmodem_aka(M, rnd, autn, aka_cb, &ar);
		imsmodem_aka_cancel(M, &ar);
		pump(100);
		CHECK_EQ(ar.n, 0);
		/* queue limit */
		for (i = 0; i < 5; i++) CHECK_EQ(imsmodem_aka(M, rnd, autn, aka_cb, &ar), 0);	/* one running + four queued */
		CHECK_EQ(imsmodem_aka(M, rnd, autn, aka_cb, &ar), -ENOMEM);
		pump(500);
		CHECK_EQ(ar.n, 5);
	}
	teardown();

	/* ===== static P-CSCF fallback / no-pcscf ===== */
	setup();
	W.n_pcscf = 0;
	snprintf(CFG.static_pcscf[0], sizeof(CFG.static_pcscf[0]), "10.0.0.1");	/* wrong family: ignored */
	snprintf(CFG.static_pcscf[1], sizeof(CFG.static_pcscf[1]), "2001:db8::5");
	CFG.n_static = 2;
	start();
	l = imsmodem_link(M);
	CHECK(l->ready); CHECK_EQ(l->pcscf_src, PCSCF_STATIC); CHECK_EQ(l->n_pcscf, 1); CHECK_STR(l->pcscf[0], "2001:db8::5");
	teardown();

	setup();
	W.n_pcscf = 0;
	start();
	l = imsmodem_link(M);
	CHECK(!l->ready); CHECK_STR(l->reason, "no-pcscf"); CHECK_STR(imsmodem_state_name(M), "no-pcscf");
	CHECK_EQ(l->n_pcscf, 0);
	CHECK(W.net_active);	/* the bearer is up, only the P-CSCF is missing */
	{
		int links = W.n_link;

		/* the network gives a list on a later look */
		W.n_pcscf = 1;
		pump(31000);
		l = imsmodem_link(M);
		CHECK(l->ready); CHECK_EQ(l->pcscf_src, PCSCF_NETWORK); CHECK(W.n_link > links);
		CHECK_EQ(W.net_apply, 1);	/* no second apply */
	}
	teardown();

	/* ===== modem IMS active ===== */
	setup();
	W.qrtr_present = 2;
	start();
	l = imsmodem_link(M);
	CHECK(!l->ready); CHECK_STR(l->reason, "modem-ims-active"); CHECK_STR(imsmodem_state_name(M), "modem-ims-active");
	CHECK(imsmodem_ims_active(M));
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 0); CHECK_EQ(world_bearers(), 0);
	pump(30500);
	CHECK_EQ(W.n_qrtr, 2); CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 0);
	W.qrtr_present = 0;
	pump(30500);
	CHECK_EQ(W.n_qrtr, 3);
	CHECK(imsmodem_link(M)->ready);
	CHECK(!imsmodem_ims_active(M));
	teardown();

	/* modem.added re-checks at once */
	setup();
	W.qrtr_present = 1;
	start();
	CHECK_STR(imsmodem_link(M)->reason, "modem-ims-active");
	W.qrtr_present = 0;
	imsmodem_ev_modem_removed(M, W.mpath);
	W.modem_exists = false;
	pump(100);
	CHECK(!imsmodem_link(M)->ready);
	W.modem_exists = true;
	imsmodem_ev_modem_added(M, W.mpath, W.mdev);
	pump(300);
	CHECK(imsmodem_link(M)->ready);
	teardown();

	/* QRTR failure is not fatal */
	setup();
	W.qrtr_present = -5;
	start();
	CHECK(imsmodem_link(M)->ready);
	teardown();

	/* ===== modem state ===== */
	setup();
	snprintf(W.state, sizeof(W.state), "disabled");
	start();
	CHECK(!imsmodem_link(M)->ready); CHECK_STR(imsmodem_link(M)->reason, "modem-disabled");
	CHECK_EQ(W.n_enable, 0); CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 0);
	CHECK_STR(imsmodem_state_name(M), "modem-wait");
	teardown();

	setup();
	snprintf(W.state, sizeof(W.state), "disabled");
	CFG.manage_modem = true;
	start();
	CHECK_EQ(W.n_enable, 1);
	CHECK(imsmodem_link(M)->ready);
	teardown();

	/* the modem leaves "registered": everything is released; back again: bearer recreated */
	setup();
	start();
	CHECK(imsmodem_link(M)->ready);
	CHECK_EQ(W.net_apply, 1); CHECK_EQ(W.net_remove, 0);
	imsmodem_ev_state(M, W.mpath, "searching");
	CHECK(!imsmodem_link(M)->ready); CHECK_STR(imsmodem_link(M)->reason, "modem-searching");
	CHECK_EQ(W.net_remove, 1); CHECK(!W.net_active);
	pump(100);
	CHECK_EQ(W.n_delete, 1);
	CHECK_EQ(world_bearers(), 0);
	snprintf(W.state, sizeof(W.state), "registered");
	imsmodem_ev_state(M, W.mpath, "registered");
	pump(300);
	CHECK(imsmodem_link(M)->ready);
	CHECK_EQ(W.net_apply, 2); CHECK_EQ(W.net_remove, 1); CHECK_EQ(world_bearers(), 1);
	CHECK_EQ(W.n_call[UQ_SIM_GET], 1);	/* nothing re-read */
	teardown();

	/* ===== bearer lost ===== */
	setup();
	start();
	CHECK(imsmodem_link(M)->ready);
	{
		char bp[64];

		snprintf(bp, sizeof(bp), "%s", imsmodem_link(M)->br.path);
		imsmodem_ev_bearer(M, W.mpath, "uqmid.modem.0.bearer.99", false);	/* not ours */
		CHECK(imsmodem_link(M)->ready);
		imsmodem_ev_bearer(M, W.mpath, bp, true);	/* connected: nothing to do */
		CHECK(imsmodem_link(M)->ready);
		imsmodem_ev_bearer(M, W.mpath, bp, false);
		CHECK(!imsmodem_link(M)->ready); CHECK_STR(imsmodem_link(M)->reason, "bearer-lost");
		CHECK_EQ(W.net_remove, 1);
		pump(100);
		CHECK_EQ(W.n_delete, 1); CHECK_EQ(world_bearers(), 0);
		CHECK(!imsmodem_link(M)->ready);
		pump(5200);	/* retry */
		CHECK(imsmodem_link(M)->ready);
		CHECK_EQ(W.net_apply, 2); CHECK_EQ(world_bearers(), 1);
	}
	teardown();

	/* ===== modem removed and added again: identity comes from the cache ===== */
	setup();
	start();
	CHECK(imsmodem_link(M)->ready);
	{
		int sims = W.n_call[UQ_SIM_GET], reads = W.n_read;

		W.modem_exists = false;
		memset(W.br, 0, sizeof(W.br));
		imsmodem_ev_modem_removed(M, W.mpath);
		CHECK(!imsmodem_link(M)->ready);
		CHECK_EQ(W.net_remove, 1);	/* no remote delete: the bearers went with the modem */
		CHECK_EQ(W.n_delete, 0);
		CHECK_STR(W.last_watch, "");
		pump(100);
		snprintf(W.mpath, sizeof(W.mpath), "uqmid.modem.1");	/* the number changes on every restart */
		W.modem_exists = true;
		imsmodem_ev_modem_added(M, W.mpath, W.mdev);
		pump(500);
		CHECK(imsmodem_link(M)->ready);
		CHECK_STR(W.last_watch, "uqmid.modem.1");
		CHECK_EQ(W.n_call[UQ_SIM_GET], sims + 1);	/* the SIM key is checked ... */
		CHECK_EQ(W.n_read, reads);			/* ... the ISIM is not read again */
		CHECK_EQ(W.net_apply, 2);
		/* another SIM: re-read */
		imsmodem_ev_modem_removed(M, W.mpath);
		W.modem_exists = false; memset(W.br, 0, sizeof(W.br));
		pump(10);
		snprintf(W.mpath, sizeof(W.mpath), "uqmid.modem.2");
		snprintf(W.imsi, sizeof(W.imsi), "450080020509251");
		snprintf(W.impi, sizeof(W.impi), "450080020509251@ims.mnc008.mcc450.3gppnetwork.org");
		snprintf(W.impu[1], sizeof(W.impu[1]), "sip:01058512207@ims.mnc008.mcc450.3gppnetwork.org");
		snprintf(W.domain, sizeof(W.domain), "ims.mnc008.mcc450.3gppnetwork.org");
		W.modem_exists = true;
		imsmodem_ev_modem_added(M, W.mpath, W.mdev);
		pump(500);
		CHECK(imsmodem_link(M)->ready);
		CHECK(W.n_read > reads);
		CHECK_STR(imsmodem_link(M)->id.impu, "sip:01058512207@ims.mnc008.mcc450.3gppnetwork.org");
		CHECK_STR(imsmodem_link(M)->id.user, "01058512207");
	}
	teardown();

	/* ===== modem found by discovery after start, modem.added for a modem we already use is ignored ===== */
	setup();
	W.modem_exists = false;
	start();
	CHECK_STR(imsmodem_state_name(M), "no-modem");
	W.modem_exists = true;
	imsmodem_ev_modem_added(M, W.mpath, W.mdev);
	pump(500);
	CHECK(imsmodem_link(M)->ready);
	imsmodem_ev_modem_added(M, "uqmid.modem.9", "other");
	CHECK_STR(imsmodem_modem_path(M), "uqmid.modem.0");
	teardown();

	/* a pinned modem */
	setup();
	snprintf(CFG.modem_pin, sizeof(CFG.modem_pin), "/sys/devices/platform/other");
	start();
	CHECK_STR(imsmodem_state_name(M), "no-modem");
	CHECK(!imsmodem_link(M)->ready);
	imsmodem_ev_modem_added(M, W.mpath, W.mdev);	/* ignored: wrong device */
	pump(100);
	CHECK(!imsmodem_link(M)->ready);
	teardown();
	setup();
	snprintf(CFG.modem_pin, sizeof(CFG.modem_pin), "%s", "/sys/devices/platform/soc/modem");
	start();
	CHECK(imsmodem_link(M)->ready);
	teardown();

	/* ===== bearer connect failure: error text, deletion, backoff 5 s then 10 s ===== */
	setup();
	W.connect_fail = true;
	start();
	CHECK(!imsmodem_link(M)->ready);
	CHECK(strstr(imsmodem_last_error(M), "type 2 reason 201") != NULL);
	CHECK_STR(imsmodem_reason(M), "bearer-error");
	pump(100);
	CHECK_EQ(W.n_delete, 1); CHECK_EQ(world_bearers(), 0);
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 1);
	pump(4500);
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 1);
	pump(1000);	/* 5 s */
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 2);
	pump(9000);
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 2);
	pump(1500);	/* +10 s */
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 3);
	W.connect_fail = false;
	pump(20500);	/* +20 s */
	CHECK(imsmodem_link(M)->ready);
	CHECK_STR(imsmodem_last_error(M), "");
	CHECK_EQ(W.net_apply, W.net_remove + 1);
	teardown();

	/* create_bearer failure */
	setup();
	W.create_fail = true;
	start();
	CHECK(!imsmodem_link(M)->ready); CHECK(strstr(imsmodem_last_error(M), "create_bearer") != NULL);
	teardown();

	/* connect hangs: the call times out after 45 s */
	setup();
	W.hang[UQ_BEARER_CONNECT] = true;
	start();
	CHECK_STR(imsmodem_reason(M), "connecting-bearer");
	pump(44000);
	CHECK_STR(imsmodem_reason(M), "connecting-bearer");
	pump(2000);
	CHECK_STR(imsmodem_reason(M), "bearer-error");
	CHECK(strstr(imsmodem_last_error(M), "timeout") != NULL);
	teardown();

	/* netdev configuration fails: bearer torn down, retried */
	setup();
	W.net_fail = true;
	start();
	CHECK(!imsmodem_link(M)->ready); CHECK_STR(imsmodem_reason(M), "netcfg-error");
	CHECK(strstr(imsmodem_last_error(M), "wwan0") != NULL);
	pump(100);
	CHECK_EQ(W.n_delete, 1);
	W.net_fail = false;
	pump(5200);
	CHECK(imsmodem_link(M)->ready);
	teardown();

	/* ===== adoption of a bearer an earlier run left behind ===== */
	setup();
	W.br[0].used = true; snprintf(W.br[0].path, 64, "uqmid.modem.0.bearer.7"); snprintf(W.br[0].apn, 32, "ims"); snprintf(W.br[0].status, 16, "connected");
	W.br[1].used = true; snprintf(W.br[1].path, 64, "uqmid.modem.0.bearer.8"); snprintf(W.br[1].apn, 32, "internet"); snprintf(W.br[1].status, 16, "connected");
	W.next_br = 9;
	start();
	CHECK(imsmodem_link(M)->ready);
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 0); CHECK_EQ(W.n_call[UQ_BEARER_CONNECT], 0);
	CHECK_STR(imsmodem_link(M)->br.path, "uqmid.modem.0.bearer.7");
	teardown();
	/* adopted but disconnected: connect it */
	setup();
	W.br[0].used = true; snprintf(W.br[0].path, 64, "uqmid.modem.0.bearer.3"); snprintf(W.br[0].apn, 32, "IMS"); snprintf(W.br[0].status, 16, "disconnected");
	start();
	CHECK(imsmodem_link(M)->ready);
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 0); CHECK_EQ(W.n_call[UQ_BEARER_CONNECT], 1);
	teardown();

	/* ===== config overrides: no SIM, no ISIM ===== */
	setup();
	snprintf(CFG.o_impi, sizeof(CFG.o_impi), "bench@example.net");
	snprintf(CFG.o_impu, sizeof(CFG.o_impu), "sip:555@example.net");
	snprintf(CFG.o_domain, sizeof(CFG.o_domain), "example.net");
	start();
	CHECK(imsmodem_link(M)->ready);
	CHECK_STR(imsmodem_link(M)->id.impi, "bench@example.net"); CHECK_STR(imsmodem_link(M)->id.user, "555");
	CHECK_STR(imsmodem_link(M)->id.imei, "86883708-366218-5");
	CHECK_EQ(W.n_call[UQ_SIM_GET], 0); CHECK_EQ(W.n_chan_open, 0);
	teardown();
	/* a partial override replaces just that field of the ISIM data */
	setup();
	snprintf(CFG.o_domain, sizeof(CFG.o_domain), "other.example");
	start();
	CHECK_STR(imsmodem_link(M)->id.domain, "other.example");
	CHECK_STR(imsmodem_link(M)->id.impi, "450061051226862@lte-lguplus.co.kr");
	teardown();

	/* ===== ISIM problems ===== */
	setup();
	W.read_fail = true;
	start();
	CHECK(!imsmodem_link(M)->ready); CHECK_STR(imsmodem_reason(M), "isim-error");
	CHECK(strstr(imsmodem_last_error(M), "EF_IMPI") != NULL);
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 0);
	W.read_fail = false;
	pump(5200);
	CHECK(imsmodem_link(M)->ready);
	teardown();

	setup();	/* only the emergency identity on the card */
	W.n_impu = 1;
	start();
	CHECK(!imsmodem_link(M)->ready); CHECK(strstr(imsmodem_last_error(M), "no usable IMPU") != NULL);
	teardown();

	setup();	/* a missing EF_P-CSCF is not an error */
	W.n_fqdn = 0;
	start();
	CHECK(imsmodem_link(M)->ready);
	teardown();

	/* the channel dies once during the identity read: reopened, read completes */
	setup();
	W.fail_apdu = 1;
	start();
	CHECK(imsmodem_link(M)->ready);
	CHECK_EQ(W.n_chan_open, 2);
	teardown();

	/* ===== uqmid goes away and comes back ===== */
	setup();
	start();
	CHECK(imsmodem_link(M)->ready);
	imsmodem_uqmid_up(M, false);
	memset(W.br, 0, sizeof(W.br));
	CHECK(!imsmodem_link(M)->ready); CHECK_STR(imsmodem_reason(M), "waiting-for-uqmid");
	CHECK_EQ(W.net_remove, 1);
	CHECK_EQ(imsmodem_aka(M, rnd, autn, aka_cb, &ar), -ENODEV);
	imsmodem_uqmid_up(M, true);
	pump(500);
	CHECK(imsmodem_link(M)->ready);
	CHECK_EQ(W.net_apply, 2);
	teardown();

	/* ===== an AKA in flight when the modem disappears is failed ===== */
	setup();
	start();
	memset(&ar, 0, sizeof(ar));
	W.hang[UQ_APDU] = true;
	imsmodem_aka(M, rnd, autn, aka_cb, &ar);
	pump(100);
	CHECK_EQ(ar.n, 0);
	imsmodem_ev_modem_removed(M, W.mpath);
	CHECK_EQ(ar.n, 1); CHECK_EQ(ar.r[0].status, AKA_ERR);
	teardown();

	/* ===== shutdown: link dropped, bearer deleted, netdev restored ===== */
	setup();
	start();
	CHECK(imsmodem_link(M)->ready);
	shut_done_n = 0;
	imsmodem_shutdown(M, shut_cb, NULL, 2000);
	CHECK(!imsmodem_link(M)->ready);
	CHECK(!W.link.ready);
	pump(100);
	CHECK_EQ(shut_done_n, 1);
	CHECK_EQ(W.n_delete, 1); CHECK_EQ(world_bearers(), 0);
	CHECK_EQ(W.net_apply, W.net_remove); CHECK(!W.net_active);
	CHECK_STR(imsmodem_state_name(M), "stopping");
	CHECK_EQ(imsmodem_aka(M, rnd, autn, aka_cb, &ar), -ESHUTDOWN);
	pump(60000);
	CHECK_EQ(shut_done_n, 1);	/* exactly once */
	CHECK_EQ(W.n_call[UQ_CREATE_BEARER], 1);	/* nothing restarted */
	teardown();

	/* a delete that never answers: done after the bound */
	setup();
	start();
	W.hang[UQ_DELETE_BEARER] = true;
	shut_done_n = 0;
	imsmodem_shutdown(M, shut_cb, NULL, 2000);
	pump(1500);
	CHECK_EQ(shut_done_n, 0);
	pump(1000);
	CHECK_EQ(shut_done_n, 1);
	CHECK_EQ(W.net_apply, W.net_remove);
	teardown();

	/* shutdown without a modem completes at once */
	setup();
	W.modem_exists = false;
	start();
	shut_done_n = 0;
	imsmodem_shutdown(M, shut_cb, NULL, 2000);
	pump(10);
	CHECK_EQ(shut_done_n, 1);
	teardown();

	/* ===== configuration reload ===== */
	setup();
	start();
	CHECK(imsmodem_link(M)->ready);
	{
		struct imsmodem_cfg nc = CFG;

		/* only the static list changes: no restart */
		snprintf(nc.static_pcscf[0], sizeof(nc.static_pcscf[0]), "2001:db8::9");
		nc.n_static = 1;
		CHECK(!imsmodem_set_cfg(M, &nc));
		CHECK_EQ(W.net_remove, 0); CHECK(imsmodem_link(M)->ready);
		/* the apn changes: the bearer is rebuilt */
		snprintf(nc.apn, sizeof(nc.apn), "ims2");
		CHECK(imsmodem_set_cfg(M, &nc));
		CHECK(!imsmodem_link(M)->ready);
		pump(500);
		CHECK(imsmodem_link(M)->ready);
		CHECK_STR(W.last_create.str, "ims2");
		CHECK_EQ(W.net_apply, W.net_remove + 1);
		/* the table changes: the old one is removed with the old parameters */
		nc.route_table = 2000;
		CHECK(imsmodem_set_cfg(M, &nc));
		pump(500);
		CHECK_EQ(W.net_last.table, 2000);
		CHECK_EQ(W.net_apply, W.net_remove + 1);
	}
	teardown();

	/* ===== SMSC (USIM EF_SMSP), SMS PSI (EF_PSISMSC) ===== */
	setup();
	world_set_smsp();
	start();
	CHECK(imsmodem_link(M)->ready);
	CHECK_STR(imsmodem_imsi(M), "450061051226862");	/* selects the operator table */
	CHECK_STR(imsmodem_smsc(M), "+821080010585");
	CHECK_STR(imsmodem_sms_psi(M), "");	/* neither on the ISIM nor on the USIM (SELECT 6A82, quiet) */
	CHECK_EQ(W.n_usim_open, 1); CHECK_EQ(W.n_usim_close, 1);	/* the USIM channel is closed again at once */
	CHECK_EQ(W.n_usim_select, 2);	/* EF_SMSP, then EF_PSISMSC as the ISIM had none */
	CHECK_EQ(W.n_chan_close, 1);	/* the ISIM channel logic is untouched */	/* the ISIM channel is closed before the USIM one is opened (few logical channels) */
	CHECK_STR(imsmodem_link(M)->id.domain, "lte-lguplus.co.kr");	/* phone-context default: the ISIM home domain */
	/* cached per SIM: nothing is read again while the modem stays */
	pump(40000);
	CHECK_EQ(W.n_usim_open, 1);
	/* the modem goes away and comes back: read again */
	imsmodem_ev_modem_removed(M, W.mpath);
	CHECK_STR(imsmodem_smsc(M), "");
	imsmodem_ev_modem_added(M, W.mpath, W.mdev);
	pump(500);
	CHECK_STR(imsmodem_smsc(M), "+821080010585");
	CHECK_EQ(W.n_usim_open, 2);
	CHECK(imsmodem_link(M)->ready);
	teardown();

	/* no EF_SMSP on the card: unknown, registration unaffected */
	setup();
	start();
	CHECK(imsmodem_link(M)->ready); CHECK_STR(imsmodem_smsc(M), ""); CHECK_EQ(W.n_usim_open, 1);
	teardown();

	/* the USIM application cannot be opened: quiet, no retry loop, no delay */
	setup();
	world_set_smsp();
	W.usim_open_fail = true;
	start();
	CHECK(imsmodem_link(M)->ready); CHECK_STR(imsmodem_smsc(M), "");
	pump(60000);
	CHECK_EQ(W.n_usim_open, 1);
	CHECK_STR(imsmodem_last_error(M), "");
	teardown();

	/* READ RECORD answered 6C xx (retry with the length) and 61 xx (GET RESPONSE) */
	setup();
	world_set_smsp(); W.smsp_6c = true;
	start();
	CHECK_STR(imsmodem_smsc(M), "+821080010585");
	teardown();
	setup();
	world_set_smsp(); W.smsp_61 = true;
	start();
	CHECK_STR(imsmodem_smsc(M), "+821080010585");
	teardown();

	/* garbage record: no SMSC */
	setup();
	world_set_smsp(); W.smsp[29] = 0x0c;
	start();
	CHECK(imsmodem_link(M)->ready); CHECK_STR(imsmodem_smsc(M), "");
	teardown();

	/* EF_PSISMSC on the ISIM, then (absent there) on the USIM */
	setup();
	world_set_smsp();
	memcpy(W.psi_isim, "\x80\x1c" "sip:ipsmgw.lte-lguplus.co.kr\xff\xff", 32); W.psi_isim_len = 32;
	memcpy(W.psi_usim, "\x80\x0a" "tel:+82101\xff", 13); W.psi_usim_len = 13;
	start();
	CHECK_STR(imsmodem_sms_psi(M), "sip:ipsmgw.lte-lguplus.co.kr");
	CHECK_EQ(W.n_usim_select, 1);	/* the USIM one is not even looked at */
	CHECK_STR(imsmodem_smsc(M), "+821080010585");
	teardown();
	setup();
	memcpy(W.psi_usim, "\x80\x0a" "tel:+82101\xff", 13); W.psi_usim_len = 13;
	start();
	CHECK_STR(imsmodem_sms_psi(M), "tel:+82101");
	CHECK_STR(imsmodem_smsc(M), "");
	teardown();

	/* with a complete identity override the ISIM is not used, the USIM still is */
	setup();
	world_set_smsp();
	snprintf(CFG.o_impi, sizeof(CFG.o_impi), "bench@example.net");
	snprintf(CFG.o_impu, sizeof(CFG.o_impu), "sip:555@example.net");
	snprintf(CFG.o_domain, sizeof(CFG.o_domain), "example.net");
	start();
	CHECK_EQ(W.n_chan_open, 0); CHECK_STR(imsmodem_smsc(M), "+821080010585");
	CHECK_STR(imsmodem_link(M)->id.domain, "example.net");	/* phone-context default follows the (overridden) domain */
	teardown();

	/* an AKA request does not wait for the SIM reads: they give way and run afterwards */
	setup();
	world_set_smsp();
	W.hang_psi_select = true;	/* the extras get stuck on their first APDU */
	start();
	CHECK(imsmodem_link(M)->ready);
	CHECK_STR(imsmodem_smsc(M), "");
	memset(&ar, 0, sizeof(ar));
	CHECK_EQ(imsmodem_aka(M, rnd, autn, aka_cb, &ar), 0);
	pump(100);
	CHECK_EQ(ar.n, 1); CHECK_EQ(ar.r[0].status, AKA_OK);
	CHECK_STR(imsmodem_smsc(M), "");	/* the restarted read hangs again */
	W.hang_psi_select = false;
	pump(16000);	/* call timeout: quiet, the read goes on */
	CHECK_STR(imsmodem_smsc(M), "+821080010585");
	CHECK_EQ(W.n_usim_open, 1);
	CHECK(imsmodem_link(M)->ready);
	teardown();

	/* ===== P-Access-Network-Info from the serving cell ===== */
	{
		char f[100];

		/* the vector of the captured registration */
		CHECK(!imsmodem_pani_format("45006", 0x20EB, 0x3161703, false, f, sizeof(f)));
		CHECK_STR(f, "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703");
		/* 3-digit MNC as the network reports it, TDD, small values zero padded */
		CHECK(!imsmodem_pani_format("310260", 0x1234, 0xABCDEF, false, f, sizeof(f)));
		CHECK_STR(f, "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=31026012340ABCDEF");
		CHECK(!imsmodem_pani_format("45008", 0x1, 0x2, true, f, sizeof(f)));
		CHECK_STR(f, "3GPP-E-UTRAN-TDD; utran-cell-id-3gpp=4500800010000002");
		CHECK(!imsmodem_pani_format("45006", 0xFFFF, 0xFFFFFFF, false, f, sizeof(f)));
		CHECK_STR(f, "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=45006FFFFFFFFFFF");
		CHECK(imsmodem_pani_format("4500", 1, 1, false, f, sizeof(f)) < 0);
		CHECK(imsmodem_pani_format("4500600", 1, 1, false, f, sizeof(f)) < 0);
		CHECK(imsmodem_pani_format("45a06", 1, 1, false, f, sizeof(f)) < 0);
		CHECK(imsmodem_pani_format("45006", 0x10000, 1, false, f, sizeof(f)) < 0);
		CHECK(imsmodem_pani_format("45006", 1, 0x10000000, false, f, sizeof(f)) < 0);
		CHECK(imsmodem_pani_format("45006", 1, 1, false, f, 20) < 0);
		/* FDD / TDD by EARFCN (bands 33..53 are TDD) */
		CHECK(!imsmodem_earfcn_is_tdd(0));	/* band 1 */
		CHECK(!imsmodem_earfcn_is_tdd(1300));	/* band 3 */
		CHECK(!imsmodem_earfcn_is_tdd(2850));	/* band 7 */
		CHECK(!imsmodem_earfcn_is_tdd(35999));
		CHECK(imsmodem_earfcn_is_tdd(36000));	/* band 33 */
		CHECK(imsmodem_earfcn_is_tdd(38400));	/* band 40 */
		CHECK(imsmodem_earfcn_is_tdd(40940));	/* band 41 */
		CHECK(imsmodem_earfcn_is_tdd(55240));	/* band 48 */
		CHECK(imsmodem_earfcn_is_tdd(60140));	/* band 53 */
		CHECK(imsmodem_earfcn_is_tdd(60254));
		CHECK(!imsmodem_earfcn_is_tdd(60255));
		CHECK(!imsmodem_earfcn_is_tdd(66436));	/* band 66 */
	}

	/* known at link ready, before the first REGISTER */
	setup();
	start();
	CHECK(imsmodem_link(M)->ready);
	CHECK_STR(imsmodem_pani(M), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703");
	CHECK_STR(imsmodem_cell_info(M), "lte 45006 tac 20EB ci 3161703 earfcn 1300");
	CHECK_EQ(W.n_call[UQ_CELL_INFO], 1);
	teardown();

	/* TDD band, 3-digit MNC, no EARFCN reported = FDD */
	setup();
	snprintf(W.cell_plmn, sizeof(W.cell_plmn), "310260"); W.cell_earfcn = 39000;
	start();
	CHECK_STR(imsmodem_pani(M), "3GPP-E-UTRAN-TDD; utran-cell-id-3gpp=31026020EB3161703");
	teardown();
	setup();
	W.cell_has_earfcn = false; W.cell_earfcn = 39000;
	start();
	CHECK_STR(imsmodem_pani(M), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703");
	CHECK_STR(imsmodem_cell_info(M), "lte 45006 tac 20EB ci 3161703");
	teardown();

	/* no serving cell / the query fails: nothing known, the link is not delayed */
	setup();
	W.cell_present = false;
	start();
	CHECK(imsmodem_link(M)->ready); CHECK_STR(imsmodem_pani(M), ""); CHECK_STR(imsmodem_cell_info(M), "");
	teardown();
	setup();
	W.cell_fail = true;
	start();
	CHECK(imsmodem_link(M)->ready); CHECK_STR(imsmodem_pani(M), "");
	CHECK_STR(imsmodem_last_error(M), "");
	teardown();

	/* the cell query hangs: the link waits at most 1 s for it, nothing blocks */
	setup();
	W.hang[UQ_CELL_INFO] = true;
	{
		struct imsmodem_ops o = world_ops();

		M = imsmodem_new(&CFG, &o);
		imsmodem_uqmid_up(M, true);
		evfake_advance(900);
		CHECK(!imsmodem_link(M)->ready); CHECK_STR(imsmodem_state_name(M), "bearer");
		CHECK(!W.link.ready);
		evfake_advance(200);	/* 1.1 s: given up */
		CHECK(imsmodem_link(M)->ready); CHECK_STR(imsmodem_state_name(M), "ready");
		CHECK(W.link.ready);
		CHECK_STR(imsmodem_pani(M), "");
		CHECK_EQ(W.n_call[UQ_CELL_INFO], 1);
		imsmodem_pani_refresh(M);	/* one is still in flight: coalesced */
		imsmodem_pani_refresh(M);
		pump(100);
		CHECK_EQ(W.n_call[UQ_CELL_INFO], 1);
		pump(16000);	/* the hung call times out, a refresh can start again */
		W.hang[UQ_CELL_INFO] = false;
		imsmodem_pani_refresh(M);
		CHECK_STR(imsmodem_pani(M), "");	/* never synchronous */
		pump(10);
		CHECK_EQ(W.n_call[UQ_CELL_INFO], 2);
		CHECK_STR(imsmodem_pani(M), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703");
	}
	teardown();

	/* refresh: asynchronous, coalesced, keeps the last value on failure, no-op without a modem */
	setup();
	start();
	{
		int n0 = W.n_call[UQ_CELL_INFO];

		W.cell_ci = 0x3161704; W.cell_tac = 0x20EC;
		imsmodem_pani_refresh(M);
		imsmodem_pani_refresh(M);
		imsmodem_pani_refresh(M);
		CHECK_STR(imsmodem_pani(M), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703");	/* nothing synchronous */
		pump(0);
		CHECK_EQ(W.n_call[UQ_CELL_INFO], n0 + 1);	/* three requests, one query */
		CHECK_STR(imsmodem_pani(M), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EC3161704");
		W.cell_fail = true;
		imsmodem_pani_refresh(M);
		pump(10);
		CHECK_EQ(W.n_call[UQ_CELL_INFO], n0 + 2);
		CHECK_STR(imsmodem_pani(M), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EC3161704");	/* last known value */
		W.cell_fail = false; W.cell_present = false;
		imsmodem_pani_refresh(M);
		pump(10);
		CHECK_STR(imsmodem_pani(M), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EC3161704");
		/* the modem leaves "registered": no query */
		W.cell_present = true;
		imsmodem_ev_state(M, W.mpath, "searching");
		n0 = W.n_call[UQ_CELL_INFO];
		imsmodem_pani_refresh(M);
		pump(10);
		CHECK_EQ(W.n_call[UQ_CELL_INFO], n0);
		/* the modem object goes away: forgotten */
		W.modem_exists = false;
		imsmodem_ev_modem_removed(M, W.mpath);
		CHECK_STR(imsmodem_pani(M), "");
		imsmodem_pani_refresh(M);
		pump(10);
		CHECK_EQ(W.n_call[UQ_CELL_INFO], n0);
	}
	teardown();
	setup();
	{
		struct imsmodem_ops o = world_ops();

		M = imsmodem_new(&CFG, &o);	/* uqmid never came up */
		imsmodem_pani_refresh(M);
		pump(100);
		CHECK_EQ(W.n_call[UQ_CELL_INFO], 0);
		CHECK_STR(imsmodem_pani(M), ""); CHECK_STR(imsmodem_smsc(M), ""); CHECK_STR(imsmodem_sms_psi(M), "");
	}
	teardown();
}
