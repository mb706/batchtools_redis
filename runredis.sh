#!/bin/bash
set -Eeuo pipefail

if [ "$#" -lt 1 ] || ! [ -d "$1" ] ; then
  echo "First argument must be the directory from which to run." >&2
  exit 1
fi

if [ "$#" -lt 2 ] || ! [ "$2" -gt 1023 ] ; then
  echo "Second argument must be port to listen from, > 1023." >&2
  exit 2
fi

cd "$1"

export REDISHOST="$(hostname)"
export REDISPW="$(head -c 128 /dev/urandom | sha1sum -b - | cut -c -40)"
export REDISCONF=redis.conf
export REDISPORT="$2"

cat <<EOF >"$REDISCONF"
save 6000 10
rdbcompression yes
tcp-backlog 511
timeout 0
tcp-keepalive 120
daemonize no
supervised no
loglevel notice
logfile ""
databases 1
stop-writes-on-bgsave-error yes
rdbchecksum yes
dbfilename "redisschedulerdump.rdb"

maxclients 10000
appendonly no
appendfsync no
port 0
unixsocket redis.sock
unixsocketperm 700

EOF

chmod 600 "$REDISCONF"

echo "${REDISHOST}:$REDISPORT" > instance.info
chmod 600 instance.info
echo -n "requirepass " >> "$REDISCONF"
head -c 128 /dev/urandom | sha1sum -b - | cut -c -40 | tee -a instance.info >> "$REDISCONF"
# echo "port $2" >> "$REDISCONF"

# generate server key
openssl genrsa -out server.key 4096
# generate server certificate
openssl req -new -key server.key -x509 -days 36525 -out server.crt -subj "/CN=."
# get server pem file
touch server.pem
# make sure only our user can read it before giving it the private key
chmod 600 server.key server.pem
cat server.key server.crt > server.pem

trap "exit 99" INT TERM
trap "pkill -P $$" EXIT

if [ -e redis.sock ] ; then
  echo "redis.sock exists, is redis already running in ${1}?" >&2
  exit 4
fi

redis-server redis.conf &
REDISPID=$!
while ! [ -S redis.sock ] ; do
  if ! jobs %% ; then
    echo "RUNREDIS: redis failed to launch" >&2
    exit 3
  fi
  sleep 1
done

socat "ssl-l:${REDISPORT},fork,reuseaddr,cert=server.pem,cafile=server.crt,verify=1" UNIX-CONNECT:redis.sock &

# socat uses the given port, but that one may be blocked, in which case we exit immediately
# also when redis exits we want to exit
# luckily 'wait' has the -n option

wait -n



## client:
## socat tcp-l:<PORT>,bind=localhost ssl:bioinf001.helmholtz-hzi.de:7778,cert=server.pem,cafile=server.crt,commonname=.
## better with socket:
## socat unix-listen:test.sock ssl:bioinf001.helmholtz-hzi.de:9999,cert=server.pem,cafile=server.crt,commonname=.

## killing something in background in R:
## dummyvar to prevent gc from doing annoying things
## dummyvar <- pipe("sh -c 'set -o monitor; <COMMAND> & read dummy; echo killing sleep ; kill %1'", "w")



