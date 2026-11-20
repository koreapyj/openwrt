/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdlib.h>
#include "test.h"
#include "../util/addr.h"
#include "../util/buf.h"
#include "../util/codec.h"
#include "../util/md5.h"
#include "../util/sys.h"

void test_util(void)
{
	char h[33], e[64], s[80];
	uint8_t b[64];
	struct md5_ctx c;
	uint8_t d[16];
	struct buf bf;
	struct addr a, a2;
	char big[600];
	int i;

	/* md5: RFC 1321 vectors, incremental updates crossing block boundaries */
	md5_hex("", 0, h); CHECK_STR(h, "d41d8cd98f00b204e9800998ecf8427e");
	md5_hex("abc", 3, h); CHECK_STR(h, "900150983cd24fb0d6963f7d28e17f72");
	md5_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, h);
	CHECK_STR(h, "57edf4a22be3c955ac49da2e2107b67a");
	md5_init(&c);
	for (i = 0; i < 80; i++)
		md5_update(&c, "1234567890" + i % 10, 1);
	md5_final(&c, d);
	hex_encode(d, 16, h);
	CHECK_STR(h, "57edf4a22be3c955ac49da2e2107b67a");
	memset(big, 'a', 56);	/* length 56 needs a second padding block */
	md5_hex(big, 56, h); CHECK_STR(h, "3b0c8ac703f828b04c6c197006d17218");
	md5_hex(big, 55, h); CHECK_STR(h, "ef1772b6dff9a122358552954ad0df65");

	/* base64 / hex */
	CHECK_EQ(b64_encode((const uint8_t *)"foobar", 6, e, sizeof(e)), 8); CHECK_STR(e, "Zm9vYmFy");
	CHECK_EQ(b64_encode((const uint8_t *)"fo", 2, e, sizeof(e)), 4); CHECK_STR(e, "Zm8=");
	CHECK_EQ(b64_encode((const uint8_t *)"foobar", 6, e, 8), -1);
	CHECK_EQ(b64_decode("MRTdOIZ7hwcN/iIcq7/KRmcd8nPtUoAA4+bwhST7kMM=", b, sizeof(b)), 32);
	CHECK(b[0] == 0x31 && b[1] == 0x14 && b[31] == 0xc3);
	CHECK_EQ(b64_decode("Zm9v!mFy", b, sizeof(b)), -1);
	CHECK_EQ(b64_decode("Zm9vYmFy", b, 3), -1);
	CHECK_EQ(hex_decode("00ff10", b, 8), 3); CHECK_EQ(b[1], 0xff);
	CHECK_EQ(hex_decode("00 ff 10", b, 8), 3);
	CHECK_EQ(hex_decode("0g", b, 8), -1);
	CHECK_EQ(hex_decode("001122", b, 2), -1);

	/* buf: growth, overflow flag, no silent truncation */
	buf_init(&bf, 10);
	CHECK(!buf_puts(&bf, "12345")); CHECK(!buf_puts(&bf, "67890")); CHECK(buf_ok(&bf));
	CHECK_STR(buf_cstr(&bf), "1234567890");
	CHECK(buf_puts(&bf, "x") < 0); CHECK(!buf_ok(&bf));
	CHECK_STR(buf_cstr(&bf), "1234567890");	/* nothing partial was written */
	buf_free(&bf);
	buf_init(&bf, 0);
	memset(big, 'z', sizeof(big) - 1); big[sizeof(big) - 1] = 0;
	CHECK(!buf_printf(&bf, "%s%s", big, big)); CHECK_EQ(bf.len, 1198);	/* longer than the stack temp in buf_printf */
	buf_free(&bf);
	buf_init(&bf, 0);
	CHECK(!buf_add(&bf, "a\0b", 3)); CHECK_EQ(bf.len, 3); CHECK(bf.p[1] == 0 && bf.p[2] == 'b');
	buf_free(&bf);
	buf_init_fixed(&bf, s, 8);
	CHECK(!buf_puts(&bf, "1234567")); CHECK(buf_putc(&bf, '8') < 0); CHECK(!buf_ok(&bf));
	buf_free(&bf);

	/* addr: v4 bare, v6 bracketed, v4-mapped detection */
	CHECK(!addr_set(&a, "2001:4430:4:405::43", 5071));
	CHECK(!addr_is_v4(&a)); CHECK_EQ(addr_family(&a), AF_INET6); CHECK_EQ(addr_port(&a), 5071);
	CHECK(!addr_str(&a, s, sizeof(s))); CHECK_STR(s, "[2001:4430:4:405::43]:5071");
	CHECK(!addr_host(&a, s, sizeof(s))); CHECK_STR(s, "2001:4430:4:405::43");
	CHECK(!addr_uri_host(&a, s, sizeof(s))); CHECK_STR(s, "[2001:4430:4:405::43]");
	CHECK(!addr_sdp(&a, s, sizeof(s))); CHECK_STR(s, "IP6 2001:4430:4:405::43");
	CHECK(!addr_set(&a, "[2001:db8::1]", 1)); CHECK(!addr_host(&a, s, sizeof(s))); CHECK_STR(s, "2001:db8::1");
	CHECK(!addr_set(&a, "10.113.151.70", 5060));
	CHECK(addr_is_v4(&a)); CHECK_EQ(addr_family(&a), AF_INET);
	CHECK(!addr_str(&a, s, sizeof(s))); CHECK_STR(s, "10.113.151.70:5060");
	CHECK(!addr_uri_host(&a, s, sizeof(s))); CHECK_STR(s, "10.113.151.70");
	CHECK(!addr_sdp(&a, s, sizeof(s))); CHECK_STR(s, "IP4 10.113.151.70");
	CHECK_EQ(addr_raw(&a, b), 4); CHECK(b[0] == 10 && b[3] == 70);
	CHECK(!addr_set(&a2, "::ffff:10.113.151.70", 5060)); CHECK(addr_equal(&a, &a2));
	addr_set_port(&a2, 1); CHECK(!addr_equal(&a, &a2)); CHECK(addr_equal_ip(&a, &a2));
	CHECK(addr_set(&a, "not-an-ip", 1) < 0);
	CHECK(addr_set(&a, "example.com", 1) < 0);
	CHECK(host_is_v6("::1") && !host_is_v6("1.2.3.4"));
	CHECK(addr_str(&a2, s, 5) < 0);

	/* random helpers */
	{
		char t1[17], t2[17];

		rnd_token(t1, 16); rnd_token(t2, 16);
		CHECK_EQ(strlen(t1), 16); CHECK(strcmp(t1, t2));
		for (i = 0; i < 100; i++) { uint32_t v = rnd_range(5, 7); CHECK(v >= 5 && v <= 7); }
	}
}
