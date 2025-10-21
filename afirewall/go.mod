module afirewall

go 1.25

replace (
	futils => ../futils
	sockets => ../sockets
)

require (
	futils v0.0.0-00010101000000-000000000000
	github.com/coreos/go-iptables v0.8.0
	github.com/leeqvip/gophp v1.2.0
	github.com/lrh3321/ipset-go v0.0.0-20241217055026-1bcc66040f01
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/rs/zerolog v1.34.0
	github.com/vishvananda/netlink v1.3.0
	sockets v0.0.0-00010101000000-000000000000
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/elliotchance/phpserialize v1.4.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/jsgilmore/mount v0.0.0-20140524020641-fb33415ae3d4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/lufia/plan9stats v0.0.0-20250317134145-8bc96cf8fc35 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/redis/go-redis/v9 v9.7.3 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/shirou/gopsutil/v3 v3.24.5 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
