module github.com/cloudflare/odoh-client-go

go 1.18

require (
	github.com/allegro/bigcache/v3 v3.1.0
	github.com/cloudflare/odoh-go v1.0.0
	github.com/miekg/dns v1.1.50
	github.com/urfave/cli/v2 v2.23.7
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
	golang.org/x/net v0.5.0
	golang.org/x/sync v0.0.0-20220722155255-886fb9371eb4
)

require (
	git.schwanenlied.me/yawning/x448.git v0.0.0-20170617130356-01b048fb03d6 // indirect
	github.com/cisco/go-hpke v0.0.0-20210215210317-01c430f1f302 // indirect
	github.com/cisco/go-tls-syntax v0.0.0-20200617162716-46b0cfb76b9b // indirect
	github.com/cloudflare/circl v1.0.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/sys v0.4.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	golang.org/x/tools v0.1.12 // indirect
)

replace github.com/miekg/dns v1.1.50 => github.com/iowaguy/dns v1.1.50-restructure.6

// replace github.com/miekg/dns v1.1.50 => ../dns
