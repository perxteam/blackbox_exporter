// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"github.com/go-kit/kit/log/level"
	"github.com/miekg/dns"
	"net"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/perxteam/blackbox_exporter/config"
)

func ProbeDomain(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	var dialProtocol string
	var dnsServerAddr string
	var ip *net.IPAddr
	if module.Domain.TransportProtocol == "" {
		module.Domain.TransportProtocol = "udp"
	}
	if module.Domain.TransportProtocol == "udp" || module.Domain.TransportProtocol == "tcp" {
		dnsAddr, port, err := net.SplitHostPort(module.Domain.DNSServerIpAddress)
		if err != nil {
			port = "53"
			dnsAddr = module.Domain.DNSServerIpAddress
		}
		ip, _, err = chooseProtocol(ctx, module.Domain.IPProtocol, module.Domain.IPProtocolFallback, dnsAddr, registry, logger)
		if err != nil {
			level.Error(logger).Log("msg", "Error resolving address", "err", err)
			return false
		}
		dnsServerAddr = net.JoinHostPort(ip.String(), port)
	} else {
		level.Error(logger).Log("msg", "Configuration error: Expected transport protocol udp or tcp", "protocol", module.DNS.TransportProtocol)
		return false
	}

	if ip.IP.To4() == nil {
		dialProtocol = module.Domain.TransportProtocol + "6"
	} else {
		dialProtocol = module.Domain.TransportProtocol + "4"
	}

	client := new(dns.Client)
	client.Net = dialProtocol

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(target), dns.TypeA)
	level.Info(logger).Log("msg", "Making DNS query", "target", target, "dial_protocol", dialProtocol, "to server", module.Domain.DNSServerIpAddress)
	timeoutDeadline, _ := ctx.Deadline()
	client.Timeout = time.Until(timeoutDeadline)
	response, _, err := client.Exchange(msg, dnsServerAddr)
	if err != nil {
		level.Error(logger).Log("msg", "Error while sending a DNS query", "err", err)
		return false
	}
	level.Info(logger).Log("msg", "Got response", "response", response)

	for _, a := range response.Answer {
		if rec, ok := a.(*dns.A); ok {
			if !in(rec.A, module.Domain.ValidRecords) {
				level.Info(logger).Log("msg", "Found invalid record", "record", rec.A)
				return false
			}
			success = true
			level.Info(logger).Log("msg", "Found valid record", "record", rec.A)
		}
	}
	return
}

func in(addr net.IP, array []string) bool {
	for _, el := range array {
		if addr.String() == el {
			return true
		}
	}
	return false
}
