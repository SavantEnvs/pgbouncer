/*
 * pgb_fuzz.h - shared in-process engine for the pgbouncer fuzz harnesses.
 *
 * The harnesses boot a real pgbouncer inside the fuzzer process, from a fixed
 * pgbouncer.ini written to a private scratch directory, the same way main()
 * does (init_objects, load_config, init_var_lookup, init_caches, TLS setup,
 * admin_setup, event base, dns, janitor, stats, pooler).  Untrusted bytes then
 * reach pgbouncer only through its public interfaces:
 *
 *   - the client side: a real connect() to pgbouncer's unix listen socket;
 *   - the server side: a fake PostgreSQL backend listening on a unix socket
 *     that the [databases] entries point at, so pgbouncer connects to it;
 *   - files pgbouncer is told to (re)load (pgbouncer.ini, auth_file, HBA).
 *
 * The event loop is pumped with EVLOOP_NONBLOCK in a bounded number of
 * iterations (no timers, no alarms): main_loop_once() is the same sequence
 * with EVLOOP_ONCE, which would block when pgbouncer has nothing to do.
 *
 * State between inputs: after every input all client and server connections
 * are closed and every non-admin pool is killed (the same kill_pool() pgbouncer
 * runs when a database disappears), so the next input starts with no sockets
 * and fresh pools.  Global objects that pgbouncer keeps for its whole life
 * (databases and users from the fixed config, the admin pool, statistics
 * counters, the prepared-statement cache) persist, exactly as in a running
 * pgbouncer serving many clients.  Randomness (SCRAM nonces, md5 salts,
 * cancel keys) comes from arc4random_buf(), which is replaced below by a
 * deterministic generator reset before each input, so an input always sees
 * the same nonces/salts and can complete SCRAM/md5 exchanges.
 *
 * main.c is #included (with its main() renamed) so the harness can run the
 * same static init/loop helpers main() uses, without modifying upstream.
 */
#ifndef PGB_FUZZ_H
#define PGB_FUZZ_H

#define main pgbouncer_upstream_main
#include "../../src/main.c"
#undef main

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ---------------------------------------------------------------------- */
/* deterministic randomness (environment mock: replaces the libc PRNG)    */
/* ---------------------------------------------------------------------- */

static uint64_t fz_rng = 0x9e3779b97f4a7c15ULL;

static uint64_t fz_rng_next(void)
{
	uint64_t z = (fz_rng += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static void fz_rng_reset(void)
{
	fz_rng = 0x9e3779b97f4a7c15ULL;
	srandom(1);
}

void arc4random_buf(void *buf, size_t n)
{
	uint8_t *p = buf;
	while (n > 0) {
		uint64_t v = fz_rng_next();
		size_t k = n < 8 ? n : 8;
		memcpy(p, &v, k);
		p += k;
		n -= k;
	}
}

uint32_t arc4random(void)
{
	return (uint32_t)fz_rng_next();
}

uint32_t arc4random_uniform(uint32_t upper)
{
	return upper ? arc4random() % upper : 0;
}

/* ---------------------------------------------------------------------- */
/* scratch directory and config files                                     */
/* ---------------------------------------------------------------------- */

static char fz_dir[200];

#define FZ_LISTEN_PORT 6432
#define FZ_BACKEND_PORT 6000

/* SCRAM secret for password "secret", md5 secret for md5user/"secret" */
#define FZ_SCRAM_SECRET "SCRAM-SHA-256$4096:cGdib3VuY2VyZnV6ejEyMw==$gw2WMzU8E2AwJnMIB3Kc8J3yq5BnYnOCCuyHamEbGmI=:plHO77tp8WGOqKVvWPLAew7kuh38bwE7NbIu/l4yo20="
#define FZ_MD5_SECRET "md52aea419619857e8a27f0f7aa641db0c6"

static const char fz_default_userlist[] =
	"\"scramuser\" \"" FZ_SCRAM_SECRET "\"\n"
	"\"md5user\" \"" FZ_MD5_SECRET "\"\n"
	"\"plainuser\" \"secret\"\n"
	"\"admin\" \"secret\"\n"
	"\"fuzz\" \"secret\"\n"
	"\"bob\" \"secret\"\n";

static void fz_die(const char *what)
{
	fprintf(stderr, "pgb_fuzz: %s: %s\n", what, strerror(errno));
	abort();
}

static void fz_path(char *dst, size_t dstlen, const char *name)
{
	snprintf(dst, dstlen, "%s/%s", fz_dir, name);
}

static void fz_write_file(const char *name, const void *data, size_t len)
{
	char path[512];
	FILE *f;

	fz_path(path, sizeof(path), name);
	f = fopen(path, "wb");
	if (!f)
		fz_die(path);
	if (len && fwrite(data, 1, len, f) != len)
		fz_die(path);
	fclose(f);
}

/* replace every "@DIR@" with the scratch dir */
static char *fz_subst(const char *tmpl)
{
	size_t n = 0, dl = strlen(fz_dir);
	const char *p;
	char *out, *o;

	for (p = tmpl; *p; p++)
		n += (strncmp(p, "@DIR@", 5) == 0) ? dl : 1;
	out = malloc(n + 1);
	if (!out)
		abort();
	for (p = tmpl, o = out; *p; ) {
		if (strncmp(p, "@DIR@", 5) == 0) {
			memcpy(o, fz_dir, dl);
			o += dl;
			p += 5;
		} else {
			*o++ = *p++;
		}
	}
	*o = 0;
	return out;
}

static void fz_write_template(const char *name, const char *tmpl)
{
	char *s = fz_subst(tmpl);
	fz_write_file(name, s, strlen(s));
	free(s);
}

static void fz_make_dir(void)
{
	const char *tmp = getenv("TMPDIR");
	char be[512];

	if (!tmp || !*tmp)
		tmp = "/tmp";
	snprintf(fz_dir, sizeof(fz_dir), "%s/pgbfuzz.XXXXXX", tmp);
	if (!mkdtemp(fz_dir))
		fz_die("mkdtemp");
	fz_path(be, sizeof(be), "be");
	if (mkdir(be, 0700) < 0)
		fz_die("mkdir be");
}

/* ---------------------------------------------------------------------- */
/* boot                                                                   */
/* ---------------------------------------------------------------------- */

static char fz_config_path[512];

/*
 * Boot pgbouncer from the given ini template (with @DIR@ placeholders).
 * extra_files are written to the scratch dir first (HBA file etc).
 * Mirrors main(): everything except option parsing, setuid/root check,
 * pidfile, daemonizing, rlimit check and signal handlers (the fuzzer owns
 * signals; SIGPIPE is ignored as pgbouncer itself blocks it).
 */
static void fz_boot(const char *ini_tmpl, const char *const *extra_files)
{
	signal(SIGPIPE, SIG_IGN);
	fz_rng_reset();
	fz_make_dir();
	fz_write_template("pgbouncer.ini", ini_tmpl);
	/* extra_files: { name, template, name, template, ..., NULL } */
	for (; extra_files && extra_files[0]; extra_files += 2)
		fz_write_template(extra_files[0], extra_files[1]);
	fz_write_file("userlist.txt", fz_default_userlist, strlen(fz_default_userlist));
	fz_path(fz_config_path, sizeof(fz_config_path), "pgbouncer.ini");

	cf_quiet = 1;
	setprogname("pgbouncer");
	cf_config_file = xstrdup(fz_config_path);

	init_objects();
	load_config();
	main_config.loaded = true;
	init_var_lookup(cf_track_extra_parameters);
	init_caches();
	logging_prefix_cb = log_socket_prefix;
	if (!sbuf_tls_setup())
		die("TLS setup failed");
	admin_setup();

	if (!(pgb_event_base = event_base_new()))
		die("event_base_new() failed");
	dns_setup();
	janitor_setup();
	stats_setup();
	pooler_setup();
}

/* reload the fixed config (SIGHUP path); resets runtime SET changes */
static void fz_reload_base_config(void)
{
	free(cf_config_file);
	cf_config_file = xstrdup(fz_config_path);
	load_config();
}

/* ---------------------------------------------------------------------- */
/* event loop pump                                                        */
/* ---------------------------------------------------------------------- */

/* main_loop_once() with EVLOOP_NONBLOCK */
static void fz_loop_once(void)
{
	reset_time_cache();
	event_base_loop(pgb_event_base, EVLOOP_NONBLOCK);
	ldap_poll();
	pam_poll();
	per_loop_maint();
	reuse_just_freed_objects();
	rescue_timers();
	per_loop_pooler_maint();
	if (adns)
		adns_per_loop(adns);
}

/* ---------------------------------------------------------------------- */
/* fake backend                                                           */
/* ---------------------------------------------------------------------- */

enum fz_be_mode {
	FZ_BE_NONE,	/* no backend listening: server connects fail */
	FZ_BE_CANNED,	/* answer each login with AuthOk + params + ReadyForQuery */
	FZ_BE_SCRIPT,	/* answer the first login with the scripted bytes */
};

#define FZ_MAX_SERVERS 16

struct fz_server {
	int fd;
	int logged_in;
	size_t have;
	uint8_t hdr[8];
	uint32_t need;		/* startup packet length, 0 = unknown yet */
	uint32_t got;
};

static int fz_be_listen = -1;
static enum fz_be_mode fz_be_mode = FZ_BE_NONE;
static struct fz_server fz_servers[FZ_MAX_SERVERS];
static int fz_nservers;
static const uint8_t *fz_be_script;
static size_t fz_be_script_len;
static int fz_be_script_used;
static int fz_client_fd = -1;
static int fz_client_eof;

static void fz_set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void fz_be_setup(enum fz_be_mode mode)
{
	struct sockaddr_un sa;

	fz_be_mode = mode;
	if (mode == FZ_BE_NONE)
		return;
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s/be/.s.PGSQL.%d", fz_dir, FZ_BACKEND_PORT);
	fz_be_listen = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fz_be_listen < 0)
		fz_die("socket");
	if (bind(fz_be_listen, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		fz_die("bind backend");
	if (listen(fz_be_listen, 64) < 0)
		fz_die("listen backend");
	fz_set_nonblock(fz_be_listen);
}

/* write everything, pumping pgbouncer while the socket is full */
static void fz_loop_step(void);

static void fz_write_all(int fd, const uint8_t *p, size_t len)
{
	int stuck = 0;

	while (len > 0 && stuck < 2000) {
		ssize_t n = write(fd, p, len);
		if (n > 0) {
			p += n;
			len -= n;
			stuck = 0;
		} else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
			fz_loop_step();
			stuck++;
		} else {
			return;
		}
	}
}

static void fz_put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static size_t fz_msg(uint8_t *out, char type, const void *body, size_t blen)
{
	out[0] = type;
	fz_put32(out + 1, (uint32_t)(blen + 4));
	if (blen)
		memcpy(out + 5, body, blen);
	return blen + 5;
}

static size_t fz_param(uint8_t *out, const char *k, const char *v)
{
	uint8_t body[256];
	size_t kl = strlen(k) + 1, vl = strlen(v) + 1;
	memcpy(body, k, kl);
	memcpy(body + kl, v, vl);
	return fz_msg(out, 'S', body, kl + vl);
}

/* AuthenticationOk, ParameterStatus..., BackendKeyData, ReadyForQuery */
static size_t fz_canned_login(uint8_t *out)
{
	static const uint8_t zero4[4] = {0, 0, 0, 0};
	static const uint8_t key[8] = {0, 0, 0x30, 0x39, 0x12, 0x34, 0x56, 0x78};
	size_t n = 0;

	n += fz_msg(out + n, 'R', zero4, 4);
	n += fz_param(out + n, "server_version", "17.0");
	n += fz_param(out + n, "server_encoding", "UTF8");
	n += fz_param(out + n, "client_encoding", "UTF8");
	n += fz_param(out + n, "DateStyle", "ISO, MDY");
	n += fz_param(out + n, "TimeZone", "UTC");
	n += fz_param(out + n, "integer_datetimes", "on");
	n += fz_param(out + n, "standard_conforming_strings", "on");
	n += fz_param(out + n, "application_name", "");
	n += fz_msg(out + n, 'K', key, 8);
	n += fz_msg(out + n, 'Z', "I", 1);
	return n;
}

static int fz_service_server(struct fz_server *s)
{
	uint8_t buf[16384];
	int io = 0;

	for (;;) {
		ssize_t n = read(s->fd, buf, sizeof(buf));
		size_t i = 0;
		if (n == 0) {
			close(s->fd);
			s->fd = -1;
			return 1;
		}
		if (n < 0)
			break;
		io = 1;
		/* consume the startup packet (SSLRequest is not used: sslmode=disable) */
		while (!s->logged_in && i < (size_t)n) {
			if (s->have < 4) {
				s->hdr[s->have++] = buf[i++];
				if (s->have == 4) {
					s->need = ((uint32_t)s->hdr[0] << 24) | ((uint32_t)s->hdr[1] << 16)
						  | ((uint32_t)s->hdr[2] << 8) | s->hdr[3];
					s->got = 4;
				}
				continue;
			}
			{
				size_t take = (size_t)n - i;
				if (take > s->need - s->got)
					take = s->need - s->got;
				s->got += take;
				i += take;
			}
			if (s->got >= s->need || s->need < 4) {
				s->logged_in = 1;
				if (fz_be_mode == FZ_BE_CANNED) {
					uint8_t out[1024];
					size_t len = fz_canned_login(out);
					fz_write_all(s->fd, out, len);
				} else if (fz_be_mode == FZ_BE_SCRIPT && !fz_be_script_used) {
					fz_be_script_used = 1;
					fz_write_all(s->fd, fz_be_script, fz_be_script_len);
				}
				if (s->fd < 0)
					return 1;
			}
		}
		/* everything after login is discarded */
	}
	return io;
}

static int fz_accept_servers(void)
{
	int io = 0;

	if (fz_be_listen < 0)
		return 0;
	for (;;) {
		int fd = accept(fz_be_listen, NULL, NULL);
		struct fz_server *s;
		if (fd < 0)
			break;
		io = 1;
		if (fz_nservers >= FZ_MAX_SERVERS) {
			close(fd);
			continue;
		}
		fz_set_nonblock(fd);
		s = &fz_servers[fz_nservers++];
		memset(s, 0, sizeof(*s));
		s->fd = fd;
	}
	return io;
}

/* the most recent logged-in backend connection, or -1 */
static int fz_server_fd(void)
{
	int i;
	for (i = fz_nservers - 1; i >= 0; i--) {
		if (fz_servers[i].fd >= 0 && fz_servers[i].logged_in)
			return fz_servers[i].fd;
	}
	return -1;
}

/* ---------------------------------------------------------------------- */
/* client side                                                            */
/* ---------------------------------------------------------------------- */

static int fz_connect_client(void)
{
	struct sockaddr_un sa;
	int fd;

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s/.s.PGSQL.%d", fz_dir, FZ_LISTEN_PORT);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		fz_die("socket");
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		fz_die("connect to pgbouncer");
	fz_set_nonblock(fd);
	fz_client_fd = fd;
	fz_client_eof = 0;
	return fd;
}

static int fz_drain_client(void)
{
	uint8_t buf[16384];
	int io = 0;

	if (fz_client_fd < 0 || fz_client_eof)
		return 0;
	for (;;) {
		ssize_t n = read(fz_client_fd, buf, sizeof(buf));
		if (n > 0) {
			io = 1;
			continue;
		}
		if (n == 0) {
			fz_client_eof = 1;
			io = 1;
		}
		break;
	}
	return io;
}

/* one pgbouncer loop iteration plus the harness's side of every socket */
static int fz_step(void)
{
	int io = 0, i;

	fz_loop_once();
	io |= fz_accept_servers();
	for (i = 0; i < fz_nservers; i++) {
		if (fz_servers[i].fd >= 0)
			io |= fz_service_server(&fz_servers[i]);
	}
	io |= fz_drain_client();
	return io;
}

static void fz_loop_step(void)
{
	fz_step();
}

/* pump until nothing moved for a few iterations (bounded) */
static void fz_settle(void)
{
	int quiet = 0, i;

	for (i = 0; i < 400 && quiet < 8; i++) {
		if (fz_step())
			quiet = 0;
		else
			quiet++;
	}
}

static void fz_client_send(const uint8_t *data, size_t len)
{
	if (fz_client_fd < 0)
		return;
	fz_write_all(fz_client_fd, data, len);
	fz_settle();
}

static void fz_server_send(const uint8_t *data, size_t len)
{
	int fd = fz_server_fd();
	if (fd < 0)
		return;
	fz_write_all(fd, data, len);
	fz_settle();
}

/* StartupMessage v3.0 with user/database */
static size_t fz_startup(uint8_t *out, const char *user, const char *db)
{
	size_t n = 8;
	static const uint8_t ver[4] = {0, 3, 0, 0};

	memcpy(out + 4, ver, 4);
	memcpy(out + n, "user", 5); n += 5;
	memcpy(out + n, user, strlen(user) + 1); n += strlen(user) + 1;
	memcpy(out + n, "database", 9); n += 9;
	memcpy(out + n, db, strlen(db) + 1); n += strlen(db) + 1;
	out[n++] = 0;
	fz_put32(out, (uint32_t)n);
	return n;
}

static size_t fz_query(uint8_t *out, const char *q, size_t qlen)
{
	out[0] = 'Q';
	fz_put32(out + 1, (uint32_t)(qlen + 5));
	memcpy(out + 5, q, qlen);
	out[5 + qlen] = 0;
	return qlen + 6;
}

/* ---------------------------------------------------------------------- */
/* per-input reset                                                        */
/* ---------------------------------------------------------------------- */

static void fz_close_client_list(struct StatList *list)
{
	struct List *item, *tmp;
	statlist_for_each_safe(item, list, tmp) {
		PgSocket *client = container_of(item, PgSocket, head);
		disconnect_client(client, false, "fuzz input done");
	}
}

/*
 * disconnect_server() never frees a server's partially reassembled packet
 * (packet_cb_state.pkt; disconnect_client() does free the client's), so a
 * backend that sends a large packet header and then goes away leaks up to
 * max_packet_size bytes - an upstream leak.  Leaks are not what this fleet
 * fuzzes for (LeakSanitizer is off), but this one grows the fuzzer's RSS
 * with every input, so the server connections still open at the end of an
 * input are released here, buffer first.
 */
static void fz_close_server_list(struct StatList *list)
{
	struct List *item, *tmp;
	statlist_for_each_safe(item, list, tmp) {
		PgSocket *server = container_of(item, PgSocket, head);
		free_header(&server->packet_cb_state.pkt);
		disconnect_server(server, false, "fuzz input done");
	}
}

static void fz_close_servers(void)
{
	struct List *item, *tmp;

	statlist_for_each_safe(item, &pool_list, tmp) {
		PgPool *pool = container_of(item, PgPool, head);
		fz_close_server_list(&pool->active_server_list);
		fz_close_server_list(&pool->active_cancel_server_list);
		fz_close_server_list(&pool->being_canceled_server_list);
		fz_close_server_list(&pool->idle_server_list);
		fz_close_server_list(&pool->used_server_list);
		fz_close_server_list(&pool->tested_server_list);
		fz_close_server_list(&pool->new_server_list);
	}
}

/*
 * Close everything the input opened, then kill every non-admin pool (the
 * same teardown pgbouncer does for a removed database) so the next input
 * starts from fresh pools with no clients or servers.
 */
static void fz_end_input(void)
{
	struct List *item, *tmp;
	int i;

	fz_close_servers();
	if (fz_client_fd >= 0) {
		shutdown(fz_client_fd, SHUT_WR);
		fz_settle();
		close(fz_client_fd);
		fz_client_fd = -1;
	}
	for (i = 0; i < fz_nservers; i++) {
		if (fz_servers[i].fd >= 0)
			close(fz_servers[i].fd);
		fz_servers[i].fd = -1;
	}
	fz_settle();

	fz_close_client_list(&login_client_list);
	statlist_for_each_safe(item, &pool_list, tmp) {
		PgPool *pool = container_of(item, PgPool, head);
		if (pool->db->admin) {
			fz_close_client_list(&pool->active_client_list);
			fz_close_client_list(&pool->waiting_client_list);
		} else {
			kill_pool(pool);
		}
	}
	fz_settle();

	/* drop any backend connection pgbouncer opened while tearing down */
	fz_accept_servers();
	for (i = 0; i < fz_nservers; i++) {
		if (fz_servers[i].fd >= 0)
			close(fz_servers[i].fd);
		fz_servers[i].fd = -1;
	}
	fz_nservers = 0;
	fz_be_script = NULL;
	fz_be_script_len = 0;
	fz_be_script_used = 0;
	fz_loop_once();
	reuse_just_freed_objects();
}

static void fz_begin_input(void)
{
	fz_rng_reset();
}

#endif
