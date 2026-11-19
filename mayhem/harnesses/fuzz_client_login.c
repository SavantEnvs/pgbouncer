/*
 * fuzz_client_login - the client wire stream before and during login.
 *
 * The fuzz input is written, unmodified, to a fresh connection on
 * pgbouncer's unix listen socket: StartupMessage / SSLRequest /
 * CancelRequest / GSSENCRequest, startup options, then password, md5 or SCRAM
 * (SASLInitialResponse / SASLResponse) messages, then anything after login.
 * auth_type=hba selects trust/md5/password/scram-sha-256/reject per database,
 * and a fake backend accepts the server login so post-auth paths run too.
 * Entry: pool_accept() -> client_proto() -> handle_client_startup().
 */
#include "pgb_fuzz.h"
#include "pgb_common_ini.h"

static const char ini[] =
	"[databases]\n"
	"db1 = host=@DIR@/be port=6000 dbname=db1\n"
	"db_trust = host=@DIR@/be port=6000 dbname=db1\n"
	"db_md5 = host=@DIR@/be port=6000 dbname=db1\n"
	"db_plain = host=@DIR@/be port=6000 dbname=db1\n"
	"db_reject = host=@DIR@/be port=6000 dbname=db1\n"
	"db_forced = host=@DIR@/be port=6000 dbname=db1 user=bob password=secret\n"
	"[pgbouncer]\n"
	"auth_type = hba\n"
	"auth_hba_file = @DIR@/hba.conf\n"
	"admin_users = admin\n"
	"stats_users = plainuser\n"
	"pool_mode = session\n"
	"max_prepared_statements = 100\n"
	"ignore_startup_parameters = extra_float_digits,search_path\n"
	"track_extra_parameters = IntervalStyle,search_path\n"
	FZ_INI_COMMON;

static const char hba[] =
	"local db_trust all trust\n"
	"local db_md5 all md5\n"
	"local db_plain all password\n"
	"local db_reject all reject\n"
	"local pgbouncer all trust\n"
	"local all all scram-sha-256\n";

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	static const char *const extra[] = { "hba.conf", hba, NULL };
	fz_boot(ini, extra);
	fz_be_setup(FZ_BE_CANNED);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_begin_input();
	fz_connect_client();
	fz_settle();
	fz_client_send(data, size);
	fz_end_input();
	return 0;
}
