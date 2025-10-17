module futils

go 1.25

replace sockets => ../sockets

require (
	github.com/jsgilmore/mount v0.0.0-20140524020641-fb33415ae3d4
	github.com/klauspost/cpuid/v2 v2.2.8
	github.com/leeqvip/gophp v1.1.1
	github.com/rs/zerolog v1.31.0
	github.com/shirou/gopsutil v3.21.11+incompatible
	golang.org/x/net v0.26.0
	golang.org/x/sys v0.21.0
	golang.org/x/text v0.16.0
	sockets v0.0.0-00010101000000-000000000000
)

require (
	github.com/bradfitz/gomemcache v0.0.0-20230905024940-24af94b03874 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
)
