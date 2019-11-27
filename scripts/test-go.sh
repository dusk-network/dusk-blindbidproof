#!/bin/bash
./target/debug/dusk-blindbidproof &
SOCKET_PID=$!
go test ./blindbidproof
BID_STATUS=$?
kill -15 $SOCKET_PID
exit $BID_STATUS
