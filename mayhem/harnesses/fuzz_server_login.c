/*
 * fuzz_server_login - the backend server's replies during server login.
 *
 * A fixed client logs in (auth_type=trust) and sends "SELECT 1", so
 * pgbouncer opens a server connection to the fake backend.  After reading
 * pgbouncer's StartupMessage the backend writes the fuzz input (minus the
 * selector byte) as its replies: Authentication requests (cleartext, md5
 * salt, SASL / SCRAM-SHA-256 server-first and server-final messages),
 * ErrorResponse, NoticeResponse, ParameterStatus, BackendKeyData,
 * ReadyForQuery and whatever follows.  pgbouncer answers with the password
 * from the connection string or auth_file.  Randomness is deterministic, so
 * the client nonce pgbouncer sends in SCRAM is the same for every input.
 *
 *   byte 0   database: 0 user=bob password=secret (connstr),
 *            1 user=plainuser (plain password from auth_file),
 *            2 user=md5user (md5 secret from auth_file),
 *            3 user=scramuser (SCRAM secret from auth_file)
 * Entry: server_proto() -> handle_server_startup() -> answer_authreq().
 */
#include "pgb_fuzz.h"
#include "pgb_common_ini.h"

static const char ini[] =
	"[databases]\n"
	"db_pw = host=@DIR@/be port=6000 dbname=db1 user=bob password=secret\n"
	"db_plain = host=@DIR@/be port=6000 dbname=db1 user=plainuser\n"
	"db_md5 = host=@DIR@/be port=6000 dbname=db1 user=md5user\n"
	"db_scram = host=@DIR@/be port=6000 dbname=db1 user=scramuser\n"
	"[pgbouncer]\n"
	"auth_type = trust\n"
	"pool_mode = session\n"
	"track_extra_parameters = IntervalStyle,search_path\n"
	FZ_INI_COMMON;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fz_boot(ini, NULL);
	fz_be_setup(FZ_BE_SCRIPT);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const char *const dbs[] = { "db_pw", "db_plain", "db_md5", "db_scram" };
	uint8_t buf[256];
	size_t n;

	if (size < 1)
		return -1;
	fz_begin_input();
	fz_be_script = data + 1;
	fz_be_script_len = size - 1;
	fz_be_script_used = 0;
	fz_connect_client();
	n = fz_startup(buf, "fuzz", dbs[data[0] % 4]);
	n += fz_query(buf + n, "SELECT 1", 8);
	fz_client_send(buf, n);
	fz_settle();
	fz_end_input();
	return 0;
}
