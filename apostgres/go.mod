module apostgres

go 1.25

replace (
	articasys => ../articasys
	articaunix => ../articaunix
	classcerts => ../classcerts
	csqlite => ../csqlite
	futils => ../futils
	httpclient => ../httpclient
	ipclass => ../ipclass
	notifs => ../notifs
	sockets => ../sockets
)

require (
	csqlite v0.0.0-00010101000000-000000000000
	futils v0.0.0-00010101000000-000000000000
	github.com/jackc/pgx/v5 v5.7.2
	github.com/lib/pq v1.10.9
	github.com/mattn/go-sqlite3 v1.14.18
	github.com/rs/zerolog v1.31.0
	notifs v0.0.0-00010101000000-000000000000
	sockets v0.0.0-00010101000000-000000000000
)

require (
	articasys v0.0.0-00010101000000-000000000000 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/elliotchance/phpserialize v1.4.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jaypipes/ghw v0.12.0 // indirect
	github.com/jaypipes/pcidb v1.0.0 // indirect
	github.com/jsgilmore/mount v0.0.0-20140524020641-fb33415ae3d4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/leeqvip/gophp v1.1.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/redis/go-redis/v9 v9.7.0 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/shirou/gopsutil/v3 v3.23.11 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	howett.net/plist v1.0.0 // indirect
)
