module tordns/client-macos

go 1.23.0
toolchain go1.23.7

require (
	tordns/client-linux v0.0.0
	tordns/manifeste v0.0.0
)

require (
	github.com/miekg/dns v1.1.68 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sync v0.14.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
)

replace tordns/client-linux => ../client-linux

replace tordns/manifeste => ../outils/manifeste
