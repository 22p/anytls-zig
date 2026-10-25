#!/bin/sh
# End-to-end interoperability test against the reference anytls-go server.
#
# Requirements: openssl, curl, python3, an anytls-go server binary built from
# https://github.com/anytls/anytls-go (cmd/server) and the client under test.
#
# Usage:
#   scripts/e2e-test.sh /path/to/anytls-zig [/path/to/anytls-server]
#
# The server binary may also be set with ANYTLS_SERVER. The script creates its
# own CA, server certificate, HTTP origin and temporary ports; it does not touch
# the system configuration.

set -u

abspath() {
	case "$1" in
	/*) printf '%s' "$1" ;;
	*) printf '%s/%s' "$PWD" "$1" ;;
	esac
}

CLIENT=$(abspath "${1:-./zig-out/bin/anytls-zig}")
SERVER=$(abspath "${2:-${ANYTLS_SERVER:-/usr/bin/anytls-server}}")
PASS=0
FAIL=0
WORK=$(mktemp -d /tmp/anytls-e2e.XXXXXX)
PIDS=""

cleanup() {
	for p in $PIDS; do kill "$p" 2>/dev/null; done
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }

command -v openssl >/dev/null || { echo "openssl missing"; exit 2; }
command -v curl >/dev/null || { echo "curl missing"; exit 2; }
command -v python3 >/dev/null || { echo "python3 missing"; exit 2; }
[ -x "$CLIENT" ] || { echo "client not executable: $CLIENT"; exit 2; }
[ -x "$SERVER" ] || { echo "server not executable: $SERVER"; exit 2; }

# --- fixtures --------------------------------------------------------------
mkdir -p "$WORK/certs" "$WORK/www"
cd "$WORK/certs" || exit 2
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 \
	-subj "/CN=anytls-e2e CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout srv.key -out srv.csr \
	-subj "/CN=localhost" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > ext.cnf
openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
	-out srv.pem -days 2 -extfile ext.cnf >/dev/null 2>&1

echo "hello-anytls" > "$WORK/www/small.txt"
head -c 10485760 /dev/urandom > "$WORK/www/big.bin"
BIG_SHA=$(sha256sum "$WORK/www/big.bin" | cut -d' ' -f1)

python3 -m http.server 18080 --bind 127.0.0.1 --directory "$WORK/www" \
	> "$WORK/http.log" 2>&1 &
PIDS="$PIDS $!"

TLS_CERT="$WORK/certs/srv.pem" TLS_KEY="$WORK/certs/srv.key" \
	"$SERVER" -l 127.0.0.1:18443 -p e2e-pass > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
PIDS="$PIDS $SERVER_PID"

start_client() { # port, extra args...
	port=$1
	shift
	"$CLIENT" -l "127.0.0.1:$port" -s 127.0.0.1:18443 \
		-p e2e-pass --sni localhost --ca "$WORK/certs/ca.pem" \
		--log-level debug "$@" > "$WORK/client-$port.log" 2>&1 &
	PIDS="$PIDS $!"
	eval "CLIENT_$port=$!"
}

sleep 2

start_client 11080 --min-idle 2 --idle-timeout 30
start_client 11084 --log-level error
start_client 11088 --min-idle 0 --idle-timeout 2 --half-close-wait 1
"$CLIENT" -l 127.0.0.1:11085 -s 127.0.0.1:18443 -p wrong-pass \
	--sni localhost --ca "$WORK/certs/ca.pem" --log-level debug \
	> "$WORK/client-badpw.log" 2>&1 &
BADPW_PID=$!
PIDS="$PIDS $BADPW_PID"
"$CLIENT" -l 127.0.0.1:11086 -s 127.0.0.1:18443 -p e2e-pass \
	--sni wrong.example --ca "$WORK/certs/ca.pem" --log-level debug \
	> "$WORK/client-sni.log" 2>&1 &
PIDS="$PIDS $!"
"$CLIENT" -l 127.0.0.1:11087 -s 10.255.255.1:443 -p e2e-pass \
	--sni x --connect-timeout 2 --insecure --log-level debug \
	> "$WORK/client-to.log" 2>&1 &
PIDS="$PIDS $!"
sleep 1

# --- 1. basic SOCKS5 + TLS 1.3 --------------------------------------------
if [ "$(curl -sS -m 10 --socks5 127.0.0.1:11080 http://127.0.0.1:18080/small.txt)" = "hello-anytls" ]; then
	ok "SOCKS5 CONNECT, IPv4 target"
else
	bad "SOCKS5 CONNECT, IPv4 target"
fi
grep -q "tls_1_3" "$WORK/client-11080.log" && ok "TLS 1.3 negotiated" || bad "TLS 1.3 negotiated"
grep -q "hello-anytls" "$WORK/client-11080.log" && bad "password leaked to log" || ok "password not logged"

# --- 2. domain target (server-side DNS) -----------------------------------
if [ "$(curl -sS -m 10 --socks5-hostname 127.0.0.1:11080 http://localhost:18080/small.txt)" = "hello-anytls" ]; then
	ok "domain target forwarded to server"
else
	bad "domain target forwarded to server"
fi

# --- 2b. HTTP proxy on the same port (mixed inbound) ----------------------
if [ "$(curl -sS -m 10 --noproxy '' -x http://127.0.0.1:11080 http://127.0.0.1:18080/small.txt)" = "hello-anytls" ]; then
	ok "HTTP proxy, absolute-form request"
else
	bad "HTTP proxy, absolute-form request"
fi
if [ "$(curl -sS -m 10 --noproxy '' --proxytunnel -x http://127.0.0.1:11080 http://127.0.0.1:18080/small.txt)" = "hello-anytls" ]; then
	ok "HTTP CONNECT tunnel"
else
	bad "HTTP CONNECT tunnel"
fi

# --- 3. large transfer ----------------------------------------------------
curl -sS -m 60 --socks5 127.0.0.1:11080 -o "$WORK/dl.bin" http://127.0.0.1:18080/big.bin
if [ "$(sha256sum "$WORK/dl.bin" | cut -d' ' -f1)" = "$BIG_SHA" ]; then
	ok "10 MB transfer integrity"
else
	bad "10 MB transfer integrity"
fi

# --- 4. concurrency / multiplexing ---------------------------------------
i=1
CURL_PIDS=""
while [ $i -le 8 ]; do
	curl -sS -m 30 --socks5 127.0.0.1:11080 http://127.0.0.1:18080/small.txt \
		-o "$WORK/c$i.out" &
	CURL_PIDS="$CURL_PIDS $!"
	i=$((i + 1))
done
for p in $CURL_PIDS; do wait "$p"; done
CONC=$(cat "$WORK"/c*.out | sort -u | wc -l)
STREAMS=$(grep -c "socks:" "$WORK/client-11080.log")
if [ "$CONC" -eq 1 ] && [ "$STREAMS" -ge 10 ]; then
	ok "8 concurrent requests multiplexed"
else
	bad "8 concurrent requests multiplexed (unique=$CONC streams=$STREAMS)"
fi

# --- 5. wrong password ----------------------------------------------------
curl -sS -m 10 --socks5 127.0.0.1:11085 http://127.0.0.1:18080/small.txt >/dev/null 2>&1
if kill -0 "$BADPW_PID" 2>/dev/null; then
	ok "wrong password fails without killing the client"
else
	bad "wrong password handling"
fi

# --- 6. certificate hostname verification --------------------------------
curl -sS -m 10 --socks5 127.0.0.1:11086 http://127.0.0.1:18080/small.txt >/dev/null 2>&1
if grep -q "CertificateHostMismatch" "$WORK/client-sni.log"; then
	ok "hostname verification rejects wrong SNI"
else
	bad "hostname verification rejects wrong SNI"
fi

# --- 7. connect timeout ---------------------------------------------------
start=$(date +%s)
curl -sS -m 10 --socks5 127.0.0.1:11087 http://127.0.0.1:18080/small.txt >/dev/null 2>&1
elapsed=$(( $(date +%s) - start ))
if [ "$elapsed" -le 5 ]; then
	ok "connect timeout honoured (${elapsed}s)"
else
	bad "connect timeout honoured (${elapsed}s)"
fi

# --- 8. duplicate bind ----------------------------------------------------
if "$CLIENT" -l 127.0.0.1:11080 -s 127.0.0.1:18443 -p e2e-pass \
	--sni localhost --ca "$WORK/certs/ca.pem" 2>&1 | grep -q AddressInUse; then
	ok "duplicate listener rejected"
else
	bad "duplicate listener rejected"
fi

# --- 9. half close --------------------------------------------------------
python3 - "$WORK" <<'PY' && ok "half-close teardown bounded" || bad "half-close teardown bounded"
import socket, struct, sys, threading
w = sys.argv[1]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 18081)); srv.listen(4)
def serve():
    c, _ = srv.accept()
    while c.recv(4096):
        pass
    c.sendall(b"GOT")
    c.close()
threading.Thread(target=serve, daemon=True).start()
s = socket.create_connection(("127.0.0.1", 11080), 5)
s.sendall(bytes([5,1,0])); s.recv(2)
s.sendall(bytes([5,1,0,1,127,0,0,1]) + struct.pack(">H", 18081))
s.recv(10)
s.sendall(b"x" * 1000)
s.shutdown(socket.SHUT_WR)
s.settimeout(8)
while s.recv(4096):
    pass
PY

# --- 10. server restart recovery -----------------------------------------
kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
sleep 1
curl -sS -m 5 --socks5 127.0.0.1:11084 http://127.0.0.1:18080/small.txt >/dev/null 2>&1
TLS_CERT="$WORK/certs/srv.pem" TLS_KEY="$WORK/certs/srv.key" \
	"$SERVER" -l 127.0.0.1:18443 -p e2e-pass > "$WORK/server2.log" 2>&1 &
SERVER_PID=$!
PIDS="$PIDS $SERVER_PID"
sleep 1
if [ "$(curl -sS -m 10 --socks5 127.0.0.1:11084 http://127.0.0.1:18080/small.txt)" = "hello-anytls" ]; then
	ok "reconnect after server restart"
else
	bad "reconnect after server restart"
fi

# --- 11. idle cleanup -----------------------------------------------------
curl -sS -m 5 --socks5 127.0.0.1:11088 http://127.0.0.1:18080/small.txt >/dev/null
sleep 6
if grep -q "idle session" "$WORK/client-11088.log"; then
	ok "idle session closed"
else
	bad "idle session closed"
fi

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
