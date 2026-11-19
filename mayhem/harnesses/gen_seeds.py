#!/usr/bin/env python3
"""Regenerate the committed seed corpora under mayhem/<target>/testsuite/.

Not run by build.sh; the seeds are committed. Run from the repo root:
    python3 mayhem/harnesses/gen_seeds.py

The SCRAM seeds rely on the harness's deterministic arc4random_buf(): the
nonce pgbouncer generates first after each input reset is NONCE below, both as
a SCRAM client (server-login) and as a SCRAM server (client-login).
"""
import base64
import hashlib
import hmac
import os
import struct

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
NONCE = "9GW5oWqeeG5PRQmAGF3EBuyB"
PASSWORD = b"secret"
SALT = b"pgbouncerfuzz123"
ITER = 4096


def msg(t, body=b""):
    return t + struct.pack(">I", len(body) + 4) + body


def startup(**kv):
    body = struct.pack(">I", 196608)
    for k, v in kv.items():
        body += k.encode() + b"\0" + v.encode() + b"\0"
    body += b"\0"
    return struct.pack(">I", len(body) + 4) + body


def cstr(s):
    return s.encode() + b"\0" if isinstance(s, str) else s + b"\0"


def query(q):
    return msg(b"Q", cstr(q))


def param(k, v):
    return msg(b"S", cstr(k) + cstr(v))


def canned_login():
    out = msg(b"R", struct.pack(">I", 0))
    for k, v in [("server_version", "17.0"), ("server_encoding", "UTF8"),
                 ("client_encoding", "UTF8"), ("DateStyle", "ISO, MDY"),
                 ("TimeZone", "UTC"), ("integer_datetimes", "on"),
                 ("standard_conforming_strings", "on")]:
        out += param(k, v)
    out += msg(b"K", struct.pack(">II", 4242, 0x12345678))
    out += msg(b"Z", b"I")
    return out


def select1_reply():
    rowdesc = struct.pack(">H", 1) + cstr("?column?") + struct.pack(">IHIhih", 0, 0, 23, 4, -1, 0)
    return (msg(b"T", rowdesc) + msg(b"D", struct.pack(">HI", 1, 1) + b"1")
            + msg(b"C", cstr("SELECT 1")) + msg(b"Z", b"I"))


def error(text, code="XX000"):
    return msg(b"E", b"SERROR\0C" + cstr(code) + b"M" + cstr(text) + b"\0")


def scram_keys(iterations=ITER):
    salted = hashlib.pbkdf2_hmac("sha256", PASSWORD, SALT, iterations)
    ck = hmac.new(salted, b"Client Key", "sha256").digest()
    sk = hashlib.sha256(ck).digest()
    svk = hmac.new(salted, b"Server Key", "sha256").digest()
    return ck, sk, svk


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def write(target, name, data):
    d = os.path.join(ROOT, target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def client_login():
    t = "client-login"
    write(t, "trust_query", startup(user="fuzz", database="db_trust") + query("SELECT 1") + msg(b"X"))
    write(t, "plain_password", startup(user="plainuser", database="db_plain") + msg(b"p", cstr("secret")) + query("SELECT 1"))
    write(t, "md5_password", startup(user="md5user", database="db_md5") + msg(b"p", cstr("md5" + "0" * 32)))
    write(t, "reject", startup(user="fuzz", database="db_reject"))
    write(t, "ssl_request", struct.pack(">II", 8, 80877103) + startup(user="fuzz", database="db_trust"))
    write(t, "gssenc_request", struct.pack(">II", 8, 80877104) + startup(user="fuzz", database="db_trust"))
    write(t, "cancel_request", struct.pack(">IIII", 16, 80877102, 4242, 0x12345678))
    write(t, "startup_options", startup(user="fuzz", database="db_trust", application_name="app",
                                        options="-c search_path=public -c extra_float_digits=3 --IntervalStyle=iso_8601",
                                        client_encoding="UTF8", replication="database"))
    write(t, "startup_empty_option", startup(user="fuzz", database="db_trust", options="-c =x --=y"))
    write(t, "second_startup", startup(user="fuzz", database="db_trust") + startup(user="fuzz", database="db1"))
    write(t, "admin_console", startup(user="admin", database="pgbouncer") + query("SHOW POOLS;") + query("SHOW STATS"))
    write(t, "forced_user", startup(user="fuzz", database="db_forced") + query("SELECT 1"))
    body = struct.pack(">I", 196610) + cstr("user") + cstr("fuzz") + cstr("database") + cstr("db_trust") + cstr("_pq_.x") + cstr("1") + b"\0"
    write(t, "protocol_3_2", struct.pack(">I", len(body) + 4) + body)

    # full SCRAM-SHA-256 exchange for scramuser/secret against pgbouncer's
    # (deterministic) server nonce
    ck, sk, svk = scram_keys()
    cnonce = "clientnonceAAAAAAAAAAAAA"
    cfirst_bare = "n=,r=" + cnonce
    cfirst = "n,," + cfirst_bare
    full = cnonce + NONCE
    sfirst = "r=%s,s=%s,i=%d" % (full, base64.b64encode(SALT).decode(), ITER)
    cfinal_noproof = "c=biws,r=" + full
    auth = ",".join([cfirst_bare, sfirst, cfinal_noproof]).encode()
    proof = xor(ck, hmac.new(sk, auth, "sha256").digest())
    cfinal = cfinal_noproof + ",p=" + base64.b64encode(proof).decode()
    init = msg(b"p", cstr("SCRAM-SHA-256") + struct.pack(">I", len(cfirst)) + cfirst.encode())
    write(t, "scram_full", startup(user="scramuser", database="db1") + init + msg(b"p", cfinal.encode()) + query("SELECT 1"))
    write(t, "scram_plainuser", startup(user="plainuser", database="db1") + init + msg(b"p", cfinal.encode()))
    write(t, "scram_final_no_nonce", startup(user="scramuser", database="db1") + init + msg(b"p", b"c=biws,p=" + base64.b64encode(proof)))


def chunks(db, *parts):
    out = bytes([db])
    for who, data in parts:
        out += bytes([0 if who == "c" else 1]) + struct.pack("<H", len(data)) + data
    return out


def client_session():
    t = "client-session"
    write(t, "simple_query", chunks(0, ("c", query("SELECT 1")), ("s", select1_reply()), ("c", msg(b"X"))))
    parse = msg(b"P", cstr("s1") + cstr("SELECT $1::int") + struct.pack(">HI", 1, 23))
    bind = msg(b"B", cstr("") + cstr("s1") + struct.pack(">HhHI", 1, 0, 1, 1) + b"7" + struct.pack(">H", 0))
    desc = msg(b"D", b"P" + cstr(""))
    execm = msg(b"E", cstr("") + struct.pack(">I", 0))
    sync = msg(b"S")
    reply = msg(b"1") + msg(b"2") + select1_reply()[:-6] + msg(b"Z", b"I")
    write(t, "extended_prepared", chunks(0, ("c", parse + bind + desc + execm + sync), ("s", reply),
                                         ("c", bind + execm + sync), ("s", msg(b"2") + msg(b"C", cstr("SELECT 1")) + msg(b"Z", b"I"))))
    parse2 = msg(b"P", cstr("s2") + cstr("SELECT 2") + struct.pack(">H", 0))
    close1 = msg(b"C", b"S" + cstr("s1"))
    write(t, "batched_close", chunks(0, ("c", parse + parse2 + close1 + msg(b"C", b"S" + cstr("s2")) + sync),
                                     ("s", msg(b"1") + msg(b"1") + msg(b"3") + msg(b"3") + msg(b"Z", b"I"))))
    write(t, "copy_in", chunks(1, ("c", query("COPY t FROM STDIN")), ("s", msg(b"G", b"\0" + struct.pack(">H", 0))),
                               ("c", msg(b"d", b"1\n2\n") + msg(b"c")), ("s", msg(b"C", cstr("COPY 2")) + msg(b"Z", b"I"))))
    write(t, "copy_out", chunks(0, ("c", query("COPY t TO STDOUT")), ("s", msg(b"H", b"\0" + struct.pack(">H", 0)) + msg(b"d", b"1\n") + msg(b"c") + msg(b"C", cstr("COPY 1")) + msg(b"Z", b"I"))))
    write(t, "set_param", chunks(1, ("c", query("SET search_path = x")), ("s", param("search_path", "x") + msg(b"C", cstr("SET")) + msg(b"Z", b"I"))))
    write(t, "transaction", chunks(0, ("c", query("BEGIN")), ("s", msg(b"C", cstr("BEGIN")) + msg(b"Z", b"T")),
                                   ("c", query("SELECT 1")), ("s", select1_reply()[:-6] + msg(b"Z", b"T")),
                                   ("c", query("COMMIT")), ("s", msg(b"C", cstr("COMMIT")) + msg(b"Z", b"I"))))
    write(t, "error_reply", chunks(2, ("c", query("SELECT x")), ("s", error("column x does not exist", "42703") + msg(b"Z", b"I"))))
    write(t, "notice_notify", chunks(1, ("c", query("LISTEN c")), ("s", msg(b"N", b"SNOTICE\0Mhi\0\0") + msg(b"A", struct.pack(">I", 1) + cstr("c") + cstr("p")) + msg(b"C", cstr("LISTEN")) + msg(b"Z", b"I"))))
    write(t, "function_call", chunks(1, ("c", msg(b"F", struct.pack(">IHHIi", 1598, 0, 1, 4, 1) + b"\0\0\0\0" + struct.pack(">H", 0)))))


def server_login():
    t = "server-login"
    ok = canned_login()
    write(t, "auth_ok", bytes([0]) + ok + select1_reply())
    write(t, "cleartext", bytes([0]) + msg(b"R", struct.pack(">I", 3)) + ok)
    write(t, "md5", bytes([2]) + msg(b"R", struct.pack(">I", 5) + b"\x01\x02\x03\x04") + ok)
    write(t, "md5_plain", bytes([1]) + msg(b"R", struct.pack(">I", 5) + b"abcd") + ok)
    write(t, "error", bytes([0]) + error("password authentication failed", "28P01"))
    write(t, "notice_then_ok", bytes([0]) + msg(b"N", b"SWARNING\0Mhi\0\0") + ok)
    write(t, "negotiate_protocol", bytes([0]) + msg(b"v", struct.pack(">II", 0, 1) + cstr("_pq_.x")) + ok)
    sasl = msg(b"R", struct.pack(">I", 10) + cstr("SCRAM-SHA-256") + b"\0")
    full = NONCE + "SERVERNONCE"
    # the server picks the iteration count; a low one keeps the password-in-connstr seed fast,
    # the stored-secret user must get the secret's own salt/count (4096)
    for name, sel, it in [("scram_full", 0, 16), ("scram_secret_user", 3, ITER)]:
        ck, sk, svk = scram_keys(it)
        sfirst = "r=%s,s=%s,i=%d" % (full, base64.b64encode(SALT).decode(), it)
        auth = ",".join(["n=,r=" + NONCE, sfirst, "c=biws,r=" + full]).encode()
        sig = hmac.new(svk, auth, "sha256").digest()
        cont = msg(b"R", struct.pack(">I", 11) + sfirst.encode())
        final = msg(b"R", struct.pack(">I", 12) + b"v=" + base64.b64encode(sig))
        write(t, name, bytes([sel]) + sasl + cont + final + ok)
    bad = "r=%s,s=%s,i=%d" % (full, base64.b64encode(SALT).decode(), 2000000000)
    write(t, "scram_huge_iterations", bytes([0]) + sasl + msg(b"R", struct.pack(">I", 11) + bad.encode()))


def admin():
    t = "admin"
    write(t, "show_all", b"\n".join(b"SHOW " + w for w in [
        b"POOLS", b"STATS", b"STATS_TOTALS", b"STATS_AVERAGES", b"SERVERS", b"CLIENTS", b"DATABASES",
        b"USERS", b"CONFIG", b"LISTS", b"MEM", b"FDS", b"SOCKETS", b"ACTIVE_SOCKETS", b"DNS_HOSTS",
        b"DNS_ZONES", b"VERSION", b"STATE", b"TOTALS", b"PEERS", b"PEER_POOLS", b"HELP", b"PREPARED_STATEMENTS"]) + b"\n")
    write(t, "set_values", b"SET default_pool_size = 30;\nSET server_reset_query = 'DISCARD ALL';\n"
          b"set \"ignore_startup_parameters\" to 'extra_float_digits'\nSET query_timeout = '1.5s'\n"
          b"SET pool_mode = transaction\nSHOW CONFIG\n")
    write(t, "select_and_errors", b"select 1\nSHOW\nSHOW nothing;\nSET = 1\nshow \"pools\"\n")
    write(t, "pool_control", b"PAUSE db1;\nSHOW DATABASES\nRESUME db1\nPAUSE\nRESUME\nDISABLE db2\nSHOW DATABASES\n"
          b"ENABLE db2;\nKILL db1\nRESUME db1\nRECONNECT db2\nRECONNECT\nWAIT_CLOSE db1\nWAIT_CLOSE\n"
          b"KILL_CLIENT 99\nKILL_CLIENT x\nRELOAD\n\"pause\" \"nosuchdb\"\nENABLE nosuchdb\nKILL\nRESUME\n")


def config():
    t = "config"
    with open(os.path.join(ROOT, "..", "etc", "pgbouncer.ini"), "rb") as f:
        write(t, "upstream_pgbouncer_ini", f.read())
    write(t, "databases_users_peers", b"""[databases]
db1 = host=/tmp port=6000 dbname=db1 user=bob password=secret pool_size=5 reserve_pool=2 pool_mode=transaction
db2 = host=127.0.0.1,::1 port=5432,5433 dbname=x auth_user=bob load_balance_hosts=disable client_encoding=UTF8 datestyle=ISO timezone=UTC
db3 = connect_query='SELECT 1' application_name=app max_db_connections=3 max_db_client_connections=4 min_pool_size=1 server_lifetime=10 auth_dbname=db1
* = host=localhost
[users]
bob = pool_mode=session max_user_connections=3 pool_size=2 reserve_pool_size=1 query_timeout=10 idle_transaction_timeout=5
[peers]
1 = host=/tmp/peer port=7000 pool_size=2
[pgbouncer]
listen_port = 6432
auth_type = trust
max_client_conn = 200
default_pool_size = 20
server_reset_query = DISCARD ALL
ignore_startup_parameters = extra_float_digits, options
track_extra_parameters = IntervalStyle, search_path
server_check_delay = 30
query_wait_timeout = 1.5h
peer_id = 1
""")
    write(t, "include", b"[pgbouncer]\n%include /dev/null\nlisten_port=1\n")
    with open(os.path.join(ROOT, "..", "test", "test.ini"), "rb") as f:
        write(t, "upstream_test_ini", f.read())


def hba():
    t = "hba"
    with open(os.path.join(ROOT, "..", "test", "hba_test.rules"), "rb") as f:
        rules = f.read()
    write(t, "upstream_hba_test_rules", rules)
    with open(os.path.join(ROOT, "..", "test", "pgbouncer_hba.conf"), "rb") as f:
        conf = f.read()
    with open(os.path.join(ROOT, "..", "test", "pgident.conf"), "rb") as f:
        ident = f.read()
    write(t, "upstream_hba_with_ident", conf + b"\0" + ident)
    write(t, "map_rules", b"local all all peer map=m1\nhost all @admins 10.0.0.0/8 md5\nhostssl replication all ::1/128 cert map=m2\n"
          b"host \"db 1\",db2 u1,+grp 192.168.0.0 255.255.255.0 scram-sha-256\nhostnossl all all all trust\n"
          b"\0m1 /^(.*)$ \\1\nm2 bob postgres\nm1 all fuzz\n")


def auth_file():
    t = "auth-file"
    with open(os.path.join(ROOT, "..", "test", "userlist.txt"), "rb") as f:
        write(t, "upstream_userlist", f.read())
    write(t, "secrets", b'"scramuser" "SCRAM-SHA-256$4096:cGdib3VuY2VyZnV6ejEyMw==$gw2WMzU8E2AwJnMIB3Kc8J3yq5BnYnOCCuyHamEbGmI=:plHO77tp8WGOqKVvWPLAew7kuh38bwE7NbIu/l4yo20="\n'
          b'"md5user" "md52aea419619857e8a27f0f7aa641db0c6"\n;comment\n"quo""ted" "pa""ss"\n"empty" ""\n')


if __name__ == "__main__":
    client_login()
    client_session()
    server_login()
    admin()
    config()
    hba()
    auth_file()
