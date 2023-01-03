module github.com/cloudflare/odoh-client-go

go 1.18

require (
	github.com/cloudflare/odoh-go v1.0.0
	github.com/miekg/dns v1.1.50
	github.com/urfave/cli/v2 v2.23.7
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
)

require (
	git.schwanenlied.me/yawning/x448.git v0.0.0-20170617130356-01b048fb03d6 // indirect
	github.com/cisco/go-hpke v0.0.0-20210215210317-01c430f1f302 // indirect
	github.com/cisco/go-tls-syntax v0.0.0-20200617162716-46b0cfb76b9b // indirect
	github.com/cloudflare/circl v1.0.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83 // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/net v0.0.0-20210726213435-c6fcb2dbf985 // indirect
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	golang.org/x/tools v0.1.6-0.20210726203631-07bc1bf47fb2 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace github.com/miekg/dns v1.1.50 => ../dns
