/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdlib.h>
#include <string.h>
#include "cstest.h"

int t_checks, t_fails;

int main(int argc, char **argv)
{
	static const struct { const char *name; void (*fn)(void); } T[] = {
		{ "backend", test_backend }, { "misc", test_misc }, { "line", test_line }, { "call", test_call }, { "sms", test_sms },
	};
	size_t i;
	int a;

	for (i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
		bool run = argc == 1;
		int bc = t_checks, bf = t_fails;

		for (a = 1; a < argc; a++)
			if (!strcmp(argv[a], T[i].name))
				run = true;
		if (!run)
			continue;
		T[i].fn();
		printf("%-8s %5d checks, %d failed\n", T[i].name, t_checks - bc, t_fails - bf);
		fflush(stdout);
	}
	printf("TOTAL %d checks, %d failed\n", t_checks, t_fails);
	return t_fails ? 1 : 0;
}
