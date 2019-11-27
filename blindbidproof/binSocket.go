package blindbidproof

import (
	"net"
)

func createSocket(path string) (net.Conn, error) {
	return net.Dial("unix", "/tmp/dusk-uds-blindbid")
}
