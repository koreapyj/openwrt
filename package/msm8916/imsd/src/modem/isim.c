/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "isim.h"
#include "../aka.h"
#include "../sip/msg.h"

size_t isim_apdu_select(int channel, uint16_t fid, uint8_t *out)
{
	out[0] = aka_cla(channel);
	out[1] = 0xA4; out[2] = 0x00; out[3] = 0x04; out[4] = 0x02;
	out[5] = fid >> 8; out[6] = fid & 0xff;
	return 7;
}

size_t isim_apdu_read_binary(int channel, uint8_t le, uint8_t *out)
{
	out[0] = aka_cla(channel);
	out[1] = 0xB0; out[2] = 0x00; out[3] = 0x00; out[4] = le;
	return 5;
}

size_t isim_apdu_read_record(int channel, int rec, uint8_t le, uint8_t *out)
{
	out[0] = aka_cla(channel);
	out[1] = 0xB2; out[2] = rec; out[3] = 0x04; out[4] = le;
	return 5;
}

size_t isim_apdu_get_response(int channel, uint8_t le, uint8_t *out)
{
	out[0] = aka_cla(channel);
	out[1] = 0xC0; out[2] = 0x00; out[3] = 0x00; out[4] = le;
	return 5;
}

int isim_smsp_parse(const uint8_t *rec, size_t n, char *out, size_t outsz)
{
	const uint8_t *sca;
	size_t len, i, o = 0;
	int ton;

	out[0] = 0;
	if (n < 28 || outsz < 24)
		return -1;
	if (rec[n - 28] & 0x02)		/* parameter indicators: bit 2 set = TS-SCA absent */
		return 0;
	sca = rec + n - 15;		/* TS-SCA: 12 bytes before PID, DCS and VP */
	len = sca[0];
	if (len == 0 || len == 0xFF)
		return 0;
	if (len < 2 || len > 11)	/* length byte counts the TON/NPI byte and the BCD bytes */
		return -1;
	ton = (sca[1] >> 4) & 7;
	if (ton == 1)
		out[o++] = '+';
	for (i = 2; i <= len; i++) {
		int k;

		for (k = 0; k < 2; k++) {
			int d = k ? sca[i] >> 4 : sca[i] & 0x0F;

			if (d == 0x0F)
				goto done;
			if (d <= 9)
				out[o++] = '0' + d;
			else if (d == 0x0A)
				out[o++] = '*';
			else if (d == 0x0B)
				out[o++] = '#';
			else {
				out[0] = 0;
				return -1;
			}
		}
	}
done:
	out[o] = 0;
	if (o == 0 || (o == 1 && out[0] == '+')) {
		out[0] = 0;
		return 0;
	}
	return o;
}

int isim_psismsc_parse(const uint8_t *d, size_t n, char *out, size_t outsz)
{
	size_t i = 0, l, k;

	out[0] = 0;
	while (i < n && d[i] == 0xFF)
		i++;
	if (i + 2 > n || d[i] != 0x80)
		return -1;
	l = d[i + 1];
	i += 2;
	if (l == 0x81) {	/* long form BER length */
		if (i >= n)
			return -1;
		l = d[i++];
	}
	if (l == 0 || i + l > n || l + 1 > outsz)
		return -1;
	for (k = 0; k < l; k++)
		if (d[i + k] < 0x20 || d[i + k] > 0x7E)
			return -1;
	memcpy(out, d + i, l);
	out[l] = 0;
	return l;
}

int isim_split_sw(const uint8_t *resp, size_t n, int *sw)
{
	if (n < 2)
		return -1;
	*sw = (resp[n - 2] << 8) | resp[n - 1];
	return n - 2;
}

int isim_tlv80(const uint8_t *d, size_t n, char *out, size_t outsz)
{
	size_t i = 0, l;

	while (i < n && d[i] == 0xFF)	/* padding in front of an unusual layout */
		i++;
	if (i + 2 > n || d[i] != 0x80)
		return -1;
	l = d[i + 1];
	if (l == 0 || i + 2 + l > n || l + 1 > outsz)
		return -1;
	memcpy(out, d + i + 2, l);
	out[l] = 0;
	if (memchr(out, 0, l))	/* embedded NUL: not text */
		return -1;
	return l;
}

int isim_impu_split(const char *impu, char *user, size_t usz, char *host, size_t hsz)
{
	struct sip_uri u;

	if (sip_uri_parse(impu, &u) || strcasecmp(u.scheme, "sip") || !u.host[0])
		return -1;
	if (strlen(u.user) >= usz || strlen(u.host) >= hsz)
		return -1;
	strcpy(user, u.user);
	strcpy(host, u.host);
	return 0;
}

int isim_impu_usable(const char *impu)
{
	char user[128], host[128];

	if (isim_impu_split(impu, user, sizeof(user), host, sizeof(host)))
		return 0;
	if (!strncasecmp(host, "sos.", 4))
		return 0;
	return 1;
}

int ims_format_imei(const char *imei, char *out, size_t n)
{
	char d[17];
	size_t len = strlen(imei), i;

	if (len < 14 || len > 16)
		return -1;
	for (i = 0; i < len; i++)
		if (!isdigit((unsigned char)imei[i]))
			return -1;
	memcpy(d, imei, 14);
	if (len == 15) {
		d[14] = imei[14];
	} else {	/* 14 digits, or IMEISV (the software version is not part of the IMEI): compute the Luhn check digit */
		int sum = 0;

		for (i = 0; i < 14; i++) {
			int v = d[13 - i] - '0';

			if (i % 2 == 0) {	/* the digit next to the check digit and every second one are doubled */
				v *= 2;
				if (v > 9)
					v -= 9;
			}
			sum += v;
		}
		d[14] = '0' + (10 - sum % 10) % 10;
	}
	d[15] = 0;
	if (n < 17 + 1)
		return -1;
	snprintf(out, n, "%.8s-%.6s-%c", d, d + 8, d[14]);
	return 0;
}
