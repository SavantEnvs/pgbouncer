/*
 * fuzz_auth_file - the auth_file (userlist.txt): quoted "user" "password"
 * lines with plain, md5 and SCRAM secrets.
 *
 * Each input is written to a file and loaded with load_auth_file(), the
 * function load_config()/loader_users_check() calls at startup and on
 * reload; the fixed userlist is reloaded afterwards so the next input starts
 * from the same credentials.  A running pgbouncer keeps a user that vanished
 * from the file as a disabled object forever; here every user only an input
 * added (no pools: nothing logs in in this target) is unlinked from
 * user_list/user_tree and freed after the input, or the fuzzer's memory
 * would grow with every new user name it tries.
 * Entry: load_auth_file().
 */
#include "pgb_fuzz.h"
#include "pgb_common_ini.h"

static const char ini[] =
	"[databases]\n"
	"db1 = host=@DIR@/be port=6000 dbname=db1\n"
	"[pgbouncer]\n"
	"auth_type = scram-sha-256\n"
	FZ_INI_COMMON;

static char fuzz_path[512], base_path[512];

static int is_base_user(const char *name)
{
	static const char *const base[] = { "scramuser", "md5user", "plainuser", "admin", "fuzz", "bob" };
	size_t i;
	for (i = 0; i < sizeof(base) / sizeof(base[0]); i++) {
		if (strcmp(name, base[i]) == 0)
			return 1;
	}
	return 0;
}

static void prune_input_users(void)
{
	struct List *item, *tmp;

	statlist_for_each_safe(item, &user_list, tmp) {
		PgGlobalUser *user = container_of(item, PgGlobalUser, head);
		if (is_base_user(user->credentials.name) || !list_empty(&user->pool_list))
			continue;
		free(user->credentials.scram_SaltKey);
		user->credentials.scram_SaltKey = NULL;
		aatree_remove(&user_tree, (uintptr_t)user->credentials.name);
		statlist_remove(&user_list, &user->head);
		slab_free(user_cache, user);
	}
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fz_boot(ini, NULL);
	fz_path(fuzz_path, sizeof(fuzz_path), "fuzz_userlist.txt");
	fz_path(base_path, sizeof(base_path), "userlist.txt");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_begin_input();
	fz_write_file("fuzz_userlist.txt", data, size);
	load_auth_file(fuzz_path);
	load_auth_file(base_path);
	prune_input_users();
	return 0;
}
