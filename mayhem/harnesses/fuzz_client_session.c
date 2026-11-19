/*
 * fuzz_client_session - a logged-in client session against a scripted backend.
 *
 * The harness logs a client in (StartupMessage user=fuzz, auth_type=trust)
 * and a fake backend answers pgbouncer's server login.  The fuzz input then
 * drives both peers of the session:
 *
 *   byte 0            database: 0 transaction pooling, 1 session, 2 statement
 *   then chunks       [tag:1][len:2 little-endian][len bytes]
 *                     tag even -> bytes written by the client
 *                     tag odd  -> bytes written by the backend (server replies)
 *
 * This reaches handle_client_work() (simple + extended query protocol,
 * COPY, prepared statements with max_prepared_statements>0, Close/Sync
 * ordering) and server_proto()/handle_server_work() for the replies.
 */
#include "pgb_fuzz.h"
#include "pgb_common_ini.h"

static const char ini[] =
	"[databases]\n"
	"db_tx = host=@DIR@/be port=6000 dbname=db1 pool_mode=transaction\n"
	"db_sess = host=@DIR@/be port=6000 dbname=db1 pool_mode=session\n"
	"db_stmt = host=@DIR@/be port=6000 dbname=db1 pool_mode=statement\n"
	"[pgbouncer]\n"
	"auth_type = trust\n"
	"pool_mode = transaction\n"
	"max_prepared_statements = 100\n"
	"track_extra_parameters = IntervalStyle,search_path\n"
	FZ_INI_COMMON;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fz_boot(ini, NULL);
	fz_be_setup(FZ_BE_CANNED);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const char *const dbs[] = { "db_tx", "db_sess", "db_stmt" };
	uint8_t start[128];
	size_t off = 1;

	if (size < 1)
		return -1;
	fz_begin_input();
	fz_connect_client();
	fz_client_send(start, fz_startup(start, "fuzz", dbs[data[0] % 3]));
	while (off + 3 <= size) {
		uint8_t tag = data[off];
		size_t len = data[off + 1] | ((size_t)data[off + 2] << 8);
		off += 3;
		if (len > size - off)
			len = size - off;
		if (tag & 1)
			fz_server_send(data + off, len);
		else
			fz_client_send(data + off, len);
		off += len;
	}
	fz_end_input();
	return 0;
}
