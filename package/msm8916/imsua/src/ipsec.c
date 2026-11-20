/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <string.h>
#include <spawn.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include "ipsec.h"
#include "util.h"

extern char **environ;

static void put(struct ipsec_cmd *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#include <stdarg.h>
static void put(struct ipsec_cmd *c, const char *fmt, ...)
{
	va_list ap;

	if (c->n >= IPSEC_MAX_ARGS) return;
	va_start(ap, fmt);
	vsnprintf(c->a[c->n++], sizeof(c->a[0]), fmt, ap);
	va_end(ap);
}

/*
 * dir 0 = out, 1 = in. src/dst: addresses of the traffic itself.
 * UE out uc->ps (SPI ps), out us->pc (SPI pc); in ps->uc (SPI uc), in pc->us (SPI us).
 */
struct leg { int in; const char *src, *dst; int sport, dport; uint32_t spi; };

static void state_cmd(struct ipsec_cmd *c, const struct ipsec_sa *s, const struct leg *l, int add, int idx)
{
	char key[80];
	int i, kl = s->sha1 ? 20 : 16;

	put(c, "ip"); put(c, "xfrm"); put(c, "state"); put(c, add ? "add" : "delete");
	put(c, "src"); put(c, "%s", l->src);
	put(c, "dst"); put(c, "%s", l->dst);
	put(c, "proto"); put(c, "esp");
	put(c, "spi"); put(c, "0x%08x", l->spi);
	if (!add) return;
	put(c, "reqid"); put(c, "%u", s->reqid + idx);
	put(c, "mode"); put(c, "transport");
	strcpy(key, "0x");
	for (i = 0; i < kl; i++)
		sprintf(key + 2 + 2 * i, "%02x", i < 16 ? s->ik[i] : 0);
	put(c, "auth-trunc"); put(c, "%s", s->sha1 ? "hmac(sha1)" : "hmac(md5)"); put(c, "%s", key); put(c, "96");
	put(c, "enc"); put(c, "ecb(cipher_null)"); put(c, "%s", "");
	put(c, "sel"); put(c, "src"); put(c, "%s/128", l->src); put(c, "dst"); put(c, "%s/128", l->dst);
	put(c, "proto"); put(c, "udp"); put(c, "sport"); put(c, "%d", l->sport); put(c, "dport"); put(c, "%d", l->dport);
}

static void policy_cmd(struct ipsec_cmd *c, const struct ipsec_sa *s, const struct leg *l, int add, int idx)
{
	put(c, "ip"); put(c, "xfrm"); put(c, "policy"); put(c, add ? "update" : "delete");
	put(c, "src"); put(c, "%s/128", l->src);
	put(c, "dst"); put(c, "%s/128", l->dst);
	put(c, "proto"); put(c, "udp");
	put(c, "sport"); put(c, "%d", l->sport);
	put(c, "dport"); put(c, "%d", l->dport);
	put(c, "dir"); put(c, l->in ? "in" : "out");
	if (!add) return;
	put(c, "tmpl"); put(c, "src"); put(c, "%s", l->src); put(c, "dst"); put(c, "%s", l->dst);
	put(c, "proto"); put(c, "esp"); put(c, "reqid"); put(c, "%u", s->reqid + idx);
	put(c, "mode"); put(c, "transport");
}

int ipsec_build(const struct ipsec_sa *s, int add, struct ipsec_cmd *out)
{
	struct leg legs[4] = {
		{ 0, s->ue, s->pcscf, s->port_uc, s->port_ps, s->spi_ps },
		{ 0, s->ue, s->pcscf, s->port_us, s->port_pc, s->spi_pc },
		{ 1, s->pcscf, s->ue, s->port_ps, s->port_uc, s->spi_uc },
		{ 1, s->pcscf, s->ue, s->port_pc, s->port_us, s->spi_us },
	};
	int i;

	memset(out, 0, sizeof(*out) * IPSEC_NCMD);
	for (i = 0; i < 4; i++) {
		state_cmd(&out[i], s, &legs[i], add, i);
		policy_cmd(&out[4 + i], s, &legs[i], add, i);
	}
	return IPSEC_NCMD;
}

static int run(const struct ipsec_cmd *c, int quiet)
{
	char *argv[IPSEC_MAX_ARGS + 1];
	char line[1024] = "";
	pid_t pid;
	int i, st, rc;
	posix_spawn_file_actions_t fa;

	for (i = 0; i < c->n; i++) {
		argv[i] = (char *)c->a[i];
		/* never print keys */
		if (i > 0 && !strcmp(c->a[i-1], "hmac(md5)")) strlcpy_(line + strlen(line), " <key>", sizeof(line) - strlen(line));
		else if (i > 0 && !strcmp(c->a[i-1], "hmac(sha1)")) strlcpy_(line + strlen(line), " <key>", sizeof(line) - strlen(line));
		else { strlcpy_(line + strlen(line), " ", sizeof(line) - strlen(line)); strlcpy_(line + strlen(line), c->a[i][0] ? c->a[i] : "''", sizeof(line) - strlen(line)); }
	}
	argv[i] = NULL;
	ilog("exec:%s", line);
	posix_spawn_file_actions_init(&fa);
	if (quiet) posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
	rc = posix_spawnp(&pid, "ip", &fa, NULL, argv, environ);
	posix_spawn_file_actions_destroy(&fa);
	if (rc) { ilog("posix_spawnp ip failed: %d", rc); return -1; }
	if (waitpid(pid, &st, 0) < 0) return -1;
	return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : -1;
}

void ipsec_remove(const struct ipsec_sa *s)
{
	struct ipsec_cmd c[IPSEC_NCMD];
	int i;

	ipsec_build(s, 0, c);
	for (i = IPSEC_NCMD - 1; i >= 0; i--) run(&c[i], 1);
}

int ipsec_install(const struct ipsec_sa *s)
{
	struct ipsec_cmd c[IPSEC_NCMD];
	int i;

	ipsec_build(s, 1, c);
	for (i = 0; i < IPSEC_NCMD; i++)
		if (run(&c[i], 0)) {
			ilog("xfrm command %d failed, rolling back", i);
			ipsec_remove(s);
			return -1;
		}
	return 0;
}
