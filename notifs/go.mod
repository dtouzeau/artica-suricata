module notifs

go 1.25

replace (
	articasys => ../articasys
	futils => ../futils
	sockets => ../sockets
)

require (
	articasys v0.0.0-00010101000000-000000000000
	futils v0.0.0-00010101000000-000000000000
	github.com/leeqvip/gophp v1.1.1
	github.com/rs/zerolog v1.31.0
	sockets v0.0.0-00010101000000-000000000000
)

require (
	github.com/bradfitz/gomemcache v0.0.0-20230905024940-24af94b03874 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/shirou/gopsutil/v3 v3.23.11 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	golang.org/x/sys v0.15.0 // indirect
)
