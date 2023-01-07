package resolver

import (
	"fmt"
	"github.com/allegro/bigcache/v3"
	"github.com/miekg/dns"
	"net"
	"time"
)

type resolver interface {
	name() string
	resolve(query *dns.Msg) (*dns.Msg, error)
}

type Resolver struct {
	Nameserver string
	Timeout    time.Duration
	Cache      *bigcache.BigCache
}

func (c Resolver) name() string {
	return c.Nameserver
}

func (c Resolver) resolve(query *dns.Msg) (*dns.Msg, error) {
	var err error
	// Lookup cache first
	queryFQDN := query.Question[0].Name
	queryQType := query.Question[0].Qtype
	cacheKey := fmt.Sprintf("%v|%v", queryFQDN, queryQType)
	// Greedy optimization for only caching Root, TLD and ignore others
	potentialInCache := len(dns.SplitDomainName(queryFQDN)) < 2
	if potentialInCache {
		entry, err := c.Cache.Get(cacheKey)
		if err != nil {
			goto performNetworking
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(entry); err != nil {
			goto performNetworking
		}
		resp.Id = query.Id
		return resp, err
	}

performNetworking:
	{
	}
	connection := new(dns.Conn)

	if connection.Conn, err = net.DialTimeout("tcp", c.Nameserver, 2000*time.Millisecond); err != nil {
		return nil, fmt.Errorf("failed starting resolver connection")
	}

	err = connection.SetReadDeadline(time.Now().Add(2000 * time.Millisecond))
	if err != nil {
		return nil, err
	}
	err = connection.SetWriteDeadline(time.Now().Add(2000 * time.Millisecond))
	if err != nil {
		return nil, err
	}

	if err := connection.WriteMsg(query); err != nil {
		return nil, err
	}

	response, err := connection.ReadMsg()
	if err != nil {
		return nil, err
	}

	if potentialInCache {
		respBuffer, err := response.Pack()
		if err != nil {
			fmt.Println("Unable to pack the response correctly. Malformed?")
		}
		err = c.Cache.Set(cacheKey, respBuffer)
		if err != nil {
			fmt.Println("Unable to insert data into cache.")
		}
	}

	response.Id = query.Id
	return response, nil
}
