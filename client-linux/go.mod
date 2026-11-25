module tordns/client-linux

go 1.25.0

require (
	github.com/miekg/dns v1.1.73
	tordns/manifeste v0.0.0
)

require (
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace tordns/manifeste => ../outils/manifeste
