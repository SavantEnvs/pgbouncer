/*
 * fuzz_admin - admin console commands.
 *
 * The harness logs in to the special "pgbouncer" database as an admin user
 * (auth_type=trust, admin_users=admin) and sends each '\n'-separated line of
 * the fuzz input as a simple Query message, which admin_handle_client() ->
 * admin_parse_query() parses with its command/SET regexes and dispatches.
 *
 * Commands are allow-listed by their command name, decoded the way the admin
 * regex and copy_arg() read it (case-insensitive, unquoted [0-9a-z_]+ or a
 * "quoted" word): every command in admin.c's cmd_list (DISABLE, ENABLE, KILL,
 * KILL_CLIENT, PAUSE, RECONNECT, RELOAD, RESUME, SELECT, SHOW, WAIT_CLOSE)
 * plus SET, except SHUTDOWN, which breaks the event loop / closes the
 * listeners, i.e. ends the process as it does in the daemon.  A quoted name
 * containing a "" escape is not decoded and the line is not sent.
 *
 * Pooler-wide state the commands change is put back after every input:
 * KILL/RECONNECT only touch pools and servers, which fz_end_input() kills and
 * closes; SET and RELOAD are undone by reloading the fixed pgbouncer.ini (the
 * SIGHUP path resets every setting); PAUSE/KILL/DISABLE/WAIT_CLOSE flags
 * (cf_pause_mode, db_paused, db_disabled, db_wait_close) are cleared for every
 * database by reset_pooler_state() - what RESUME and ENABLE do.  The socket
 * id counter (KILL_CLIENT's argument, SHOW CLIENTS' id) restarts at 0 for
 * each input so ids depend only on the input.
 * Entry: admin_handle_client() via handle_client_work().
 */
#include "pgb_fuzz.h"
#include "pgb_common_ini.h"
#include <ctype.h>

static const char ini[] =
	"[databases]\n"
	"db1 = host=@DIR@/be port=6000 dbname=db1\n"
	"db2 = host=@DIR@/be port=6000 dbname=db2 pool_size=3 user=bob password=secret\n"
	"[users]\n"
	"bob = pool_mode=transaction max_user_connections=5\n"
	"[pgbouncer]\n"
	"auth_type = trust\n"
	"admin_users = admin\n"
	"stats_users = plainuser\n"
	"pool_mode = session\n"
	"max_prepared_statements = 10\n"
	FZ_INI_COMMON;

/*
 * Is the command name of q (the first admin-regex WORD) an allowed command?
 * pgbouncer reads the Query message as a C string, so only the bytes before
 * the first NUL count.
 */
static int allowed(const uint8_t *q, size_t len)
{
	static const char *const ok[] = {
		"disable", "enable", "kill", "kill_client", "pause", "reconnect",
		"reload", "resume", "select", "set", "show", "wait_close",
	};
	const uint8_t *nul = memchr(q, 0, len);
	char word[16];
	size_t i = 0, w = 0, k;

	if (nul)
		len = (size_t)(nul - q);
	while (i < len && (q[i] == ' ' || q[i] == '\t' || q[i] == '\r' || q[i] == '\n'))
		i++;
	if (i < len && q[i] == '"') {
		/* quoted name: "..." with "" as an escaped quote (copy_arg) */
		i++;
		while (i < len && q[i] != '"') {
			if (w + 1 >= sizeof(word))
				return 0;
			word[w++] = (char)tolower(q[i++]);
		}
		if (i >= len)
			return 0;
		i++;
		if (i < len && q[i] == '"')
			return 0;	/* "" escape: not decoded, not sent */
	} else {
		while (i < len && (isalnum(q[i]) || q[i] == '_')) {
			if (w + 1 >= sizeof(word))
				return 0;
			word[w++] = (char)tolower(q[i++]);
		}
		/* the word must end here: a quote or more word chars would change it */
		if (i < len && (q[i] == '"' || q[i] >= 0x80))
			return 0;
	}
	word[w] = 0;
	for (k = 0; k < sizeof(ok) / sizeof(ok[0]); k++) {
		if (strcmp(word, ok[k]) == 0)
			return 1;
	}
	return 0;
}

/* undo PAUSE / KILL / DISABLE / WAIT_CLOSE (what RESUME and ENABLE do) */
static void reset_pooler_state(void)
{
	struct List *item;

	cf_pause_mode = P_NONE;
	statlist_for_each(item, &database_list) {
		PgDatabase *db = container_of(item, PgDatabase, head);
		db->db_paused = false;
		db->db_disabled = false;
		db->db_wait_close = false;
	}
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fz_boot(ini, NULL);
	fz_be_setup(FZ_BE_CANNED);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *buf;
	size_t n, off = 0;

	fz_begin_input();
	last_pgsocket_id = 0;
	buf = malloc(size + 256);
	if (!buf)
		abort();
	fz_connect_client();
	fz_client_send(buf, fz_startup(buf, "admin", "pgbouncer"));
	while (off < size) {
		const uint8_t *line = data + off;
		const uint8_t *nl = memchr(line, '\n', size - off);
		size_t len = nl ? (size_t)(nl - line) : size - off;
		off += len + (nl ? 1 : 0);
		if (!allowed(line, len))
			continue;
		n = fz_query(buf, (const char *)line, len);
		fz_client_send(buf, n);
	}
	free(buf);
	reset_pooler_state();
	fz_end_input();
	fz_reload_base_config();
	return 0;
}
