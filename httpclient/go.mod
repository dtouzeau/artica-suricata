module httpclient

go 1.25

replace (
	futils => ../futils
	sockets => ../sockets
)

require (
	github.com/rs/zerolog v1.31.0
	gopkg.in/ini.v1 v1.67.0
	sockets v0.0.0-00010101000000-000000000000
)

require (
	github.com/bradfitz/gomemcache v0.0.0-20230905024940-24af94b03874 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	golang.org/x/sys v0.15.0 // indirect
)
