/*
 * fuzz_hba - the HBA file (auth_hba_file) and ident map (auth_ident_file).
 *
 * Input: HBA rules, optionally followed by a NUL byte and an ident map.
 * Both are written to files and loaded with ident_load_map() and
 * hba_load_rules() - what load_config() does for auth_type=hba - then the
 * rules are evaluated with hba_eval() for a fixed set of connections
 * (unix/IPv4/IPv6, TLS on/off, replication modes, several db/user names),
 * like pgbouncer does on every login.
 * Entry: hba_load_rules(), ident_load_map(), hba_eval().
 */
#include "pgb_fuzz.h"
#include "pgb_common_ini.h"

static const char ini[] =
	"[databases]\n"
	"db1 = host=@DIR@/be port=6000 dbname=db1\n"
	"[pgbouncer]\n"
	"auth_type = trust\n"
	FZ_INI_COMMON;

static char hba_path[512], ident_path[512];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fz_boot(ini, NULL);
	fz_path(hba_path, sizeof(hba_path), "fuzz_hba.conf");
	fz_path(ident_path, sizeof(ident_path), "fuzz_ident.conf");
	return 0;
}

static void eval_all(struct HBA *hba)
{
	static const char *const addrs[] = { "unix", "127.0.0.1", "10.1.2.3", "::1", "fe80::1", "192.168.0.200" };
	static const char *const dbs[] = { "db1", "postgres", "replication", "pgbouncer", "sameuser" };
	static const char *const users[] = { "fuzz", "postgres", "admin", "sameuser" };
	static const ReplicationType repl[] = { REPLICATION_NONE, REPLICATION_LOGICAL, REPLICATION_PHYSICAL };
	size_t a, d, u, r;

	for (a = 0; a < sizeof(addrs) / sizeof(addrs[0]); a++) {
		PgAddr addr;
		memset(&addr, 0, sizeof(addr));
		if (strcmp(addrs[a], "unix") == 0)
			pga_set(&addr, AF_UNIX, 6432);
		else if (!pga_pton(&addr, addrs[a], 6432))
			continue;
		for (d = 0; d < sizeof(dbs) / sizeof(dbs[0]); d++)
			for (u = 0; u < sizeof(users) / sizeof(users[0]); u++)
				for (r = 0; r < sizeof(repl) / sizeof(repl[0]); r++) {
					hba_eval(hba, &addr, (a + d + u) & 1, repl[r], dbs[d], users[u]);
				}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *nul = memchr(data, 0, size);
	size_t hlen = nul ? (size_t)(nul - data) : size;
	struct Ident *ident;
	struct HBA *hba;

	fz_begin_input();
	fz_write_file("fuzz_hba.conf", data, hlen);
	fz_write_file("fuzz_ident.conf", nul ? nul + 1 : data, nul ? size - hlen - 1 : 0);
	ident = ident_load_map(ident_path);
	hba = hba_load_rules(hba_path, ident);
	if (hba) {
		eval_all(hba);
		hba_free(hba);
	}
	ident_free(ident);
	return 0;
}
