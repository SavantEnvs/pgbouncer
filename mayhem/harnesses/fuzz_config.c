/*
 * fuzz_config - pgbouncer.ini, as `pgbouncer <file>` reads it (raw file-input
 * target: `fuzz_config <file>`).
 *
 * Runs main()'s startup config path on the input file - init_objects(),
 * load_config() (libusual cfparser parse_ini_file, %include, every setting's
 * value parser, [databases] connection strings, [users], [peers], then the
 * auth_file / HBA / ident files the config names) and init_var_lookup() -
 * then load_config() again, the SIGHUP/RELOAD path, over the same file.
 *
 * pgbouncer die()s (exit 1) on a config it cannot load and log_fatal()s when
 * the logfile it names cannot be opened, exactly like the real daemon at
 * startup.  Those exits are normal outcomes for a file-input target, which is
 * why this one is not an in-process libFuzzer harness.  It stops before
 * opening sockets or entering the event loop.
 */
#define main pgbouncer_upstream_main
#include "../../src/main.c"
#undef main

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s CONFIG_FILE\n", argv[0]);
		return 2;
	}
	setprogname("pgbouncer");
	cf_quiet = 1;
	cf_config_file = xstrdup(argv[1]);

	init_objects();
	load_config();
	main_config.loaded = true;
	init_var_lookup(cf_track_extra_parameters);

	/* the reload path (SIGHUP / admin RELOAD) over the same file */
	load_config();
	return 0;
}
