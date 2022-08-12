module github.com/cloudflare/odoh-client-go

go 1.14

require (
	github.com/cisco/go-hpke v0.0.0-20210215210317-01c430f1f302
	github.com/cloudflare/odoh-go v1.0.0
	github.com/kr/pretty v0.1.0 // indirect
	github.com/miekg/dns v1.1.50
	github.com/urfave/cli v1.22.5
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace github.com/miekg/dns v1.1.50 => github.com/iowaguy/dns v1.1.50-serial.1
