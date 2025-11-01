module monit

go 1.25

replace (
	afirewall => ../afirewall
	articasys => ../articasys
	articaunix => ../articaunix
	csqlite => ../csqlite
	futils => ../futils
	ipclass => ../ipclass
	logsink => ../logsink
	notifs => ../notifs
	sockets => ../sockets
)

require (
	articaunix v0.0.0-00010101000000-000000000000
	futils v0.0.0-00010101000000-000000000000
	github.com/rs/zerolog v1.31.0
	ipclass v0.0.0-00010101000000-000000000000
	logsink v0.0.0-00010101000000-000000000000
	sockets v0.0.0-00010101000000-000000000000
)

require (
	afirewall v0.0.0-00010101000000-000000000000 // indirect
	articasys v0.0.0-00010101000000-000000000000 // indirect
	csqlite v0.0.0-00010101000000-000000000000 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/bradfitz/gomemcache v0.0.0-20230905024940-24af94b03874 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.5.0 // indirect
	github.com/jaypipes/ghw v0.12.0 // indirect
	github.com/jaypipes/pcidb v1.0.0 // indirect
	github.com/jsgilmore/mount v0.0.0-20140524020641-fb33415ae3d4 // indirect
	github.com/leeqvip/gophp v1.1.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mattn/go-sqlite3 v1.14.18 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/shirou/gopsutil/v3 v3.23.11 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	golang.org/x/sys v0.15.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	howett.net/plist v1.0.0 // indirect
	notifs v0.0.0-00010101000000-000000000000 // indirect

)
