/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MODEM_ISIM_H
#define IMSD_MODEM_ISIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * ISIM file access helpers (TS 31.103), pure functions: APDU builders and
 * data object parsing. The logical channel itself is driven by imsmodem.c.
 *
 * Files (selected by file id inside the ISIM application, i.e. on the
 * logical channel opened with ISIM_AID):
 *   EF_IMPI  6F02 transparent        impi
 *   EF_DOMAIN 6F03 transparent       home network domain
 *   EF_IMPU  6F04 linear fixed       one public identity per record
 *   EF_PCSCF 6F09 linear fixed       FQDN / address (informational only)
 * Data objects are "80 <len> <value>" padded with FF.
 */
#define ISIM_FID_IMPI	0x6F02
#define ISIM_FID_DOMAIN	0x6F03
#define ISIM_FID_IMPU	0x6F04
#define ISIM_FID_PCSCF	0x6F09
#define ISIM_FID_PSISMSC	0x6FE5	/* EF_PSISMSC, transparent (ISIM and USIM) */
/* USIM application (TS 31.102) */
#define USIM_AID	"A0000000871002"
#define USIM_FID_SMSP	0x6F42	/* EF_SMSP, linear fixed */

/* SELECT by file id: 0X A4 00 04 02 fid (7 bytes); out needs 8 bytes */
size_t isim_apdu_select(int channel, uint16_t fid, uint8_t *out);
/* READ BINARY from offset 0: 0X B0 00 00 le (5 bytes); le 0 means 256 */
size_t isim_apdu_read_binary(int channel, uint8_t le, uint8_t *out);
/* READ RECORD, absolute mode: 0X B2 rec 04 le (5 bytes) */
size_t isim_apdu_read_record(int channel, int rec, uint8_t le, uint8_t *out);

/* GET RESPONSE: 0X C0 00 00 le (5 bytes) */
size_t isim_apdu_get_response(int channel, uint8_t le, uint8_t *out);

/*
 * EF_SMSP record (TS 31.102 4.2.27, n bytes = alpha id + 28): the service centre address (TS-SCA) as text,
 * "+" prefixed for type of number international, digits as is otherwise. Returns its length, 0 when the record
 * holds no SC address (parameter indicator bit 2 set, or an empty address), -1 when the record is malformed.
 */
int isim_smsp_parse(const uint8_t *rec, size_t n, char *out, size_t outsz);
/* EF_PSISMSC content (TS 31.102 4.2.90): a BER-TLV, tag 0x80 = URI ("sip:..." / "tel:..."), parsed leniently (leading / trailing FF). Returns the URI length, -1 if there is none */
int isim_psismsc_parse(const uint8_t *d, size_t n, char *out, size_t outsz);

/* Split status word off a card response: returns the data length (response without the last two bytes) and the SW in *sw; -1 if shorter than 2 bytes */
int isim_split_sw(const uint8_t *resp, size_t n, int *sw);
/* the first 0x80 data object of an EF record / transparent file as a NUL terminated string. Returns its length, -1 if there is none (empty record: all FF), malformed, or it does not fit */
int isim_tlv80(const uint8_t *d, size_t n, char *out, size_t outsz);

/* Is this IMPU usable for normal registration? 1 yes, 0 no (not a sip: URI, or the host starts with "sos." = emergency identity) */
int isim_impu_usable(const char *impu);
/* user and host of a sip: IMPU (parameters dropped). 0 / -1 */
int isim_impu_split(const char *impu, char *user, size_t usz, char *host, size_t hsz);

/* IMEI as used in +sip.instance (urn:gsma:imei:XXXXXXXX-XXXXXX-X): 8-6-1 digits. Accepts 14 digits (the Luhn check digit is computed), 15 digits, or 16 digits (IMEISV, the software version is dropped). 0 / -1 */
int ims_format_imei(const char *imei, char *out, size_t n);
#endif
