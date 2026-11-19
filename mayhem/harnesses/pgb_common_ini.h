/*
 * Settings shared by every harness's pgbouncer.ini (after the target's own keys).
 * max_packet_size: pgbouncer buffers a whole packet up front (mbuf_make_room
 * with the header's length), and the default limit is 2 GB, so any 5-byte
 * header would make the fuzzer allocate 2 GB and stop on an out-of-memory
 * report.  16 MB keeps large-packet paths reachable within the fuzzer's
 * memory limit; it is an ordinary operator setting.
 */
#define FZ_INI_COMMON \
	"listen_addr =\n" \
	"listen_port = 6432\n" \
	"unix_socket_dir = @DIR@\n" \
	"auth_file = @DIR@/userlist.txt\n" \
	"server_tls_sslmode = disable\n" \
	"server_login_retry = 0\n" \
	"logfile =\n" \
	"pidfile =\n" \
	"log_connections = 0\n" \
	"log_disconnections = 0\n" \
	"log_pooler_errors = 0\n" \
	"log_stats = 0\n" \
	"max_packet_size = 16777216\n"
