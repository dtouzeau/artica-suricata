module suricata

go 1.25

replace (
	articasys => ../articasys
	articaunix => ../articaunix
	futils => ../futils
	notifs => ../notifs
	sockets => ../sockets
)

require (
	articaunix v0.0.0-00010101000000-000000000000
	futils v0.0.0-00010101000000-000000000000
	notifs v0.0.0-00010101000000-000000000000
	sockets v0.0.0-00010101000000-000000000000
)

require (
	articasys v0.0.0-00010101000000-000000000000 // indirect
	github.com/bradfitz/gomemcache v0.0.0-20230905024940-24af94b03874 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/leeqvip/gophp v1.1.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mattn/go-sqlite3 v1.14.18 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/rs/zerolog v1.31.0 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/shirou/gopsutil/v3 v3.23.11 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	golang.org/x/sys v0.15.0 // indirect
)
