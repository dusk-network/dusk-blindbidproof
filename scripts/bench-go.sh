#!/bin/bash
./target/release/dusk-blindbidproof &
SOCKET_PID=$!
go test ./blindbidproof -bench .
BID_STATUS=$?
kill -15 $SOCKET_PID
exit $BID_STATUS
