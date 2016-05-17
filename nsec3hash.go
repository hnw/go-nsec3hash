package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"
)

var (
	debug bool
)

func main() {
	port := 53

	flag.BoolVar(&debug, "d", false, "enable debugging in the resolver")
	flag.BoolVar(&debug, "debug", false, "enable debugging in the resolver")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <salt> <algorithm> <iterations> <domain>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var salt, domain, nameserver string
	var algorithm, iterations int
	var args []string

Flags:
	for i := 0; i < flag.NArg(); i++ {
		// If it starts with @ it is a nameserver
		if flag.Arg(i)[0] == '@' {
			nameserver = flag.Arg(i)
			continue Flags
		}
		args = append(args, flag.Arg(i))
	}

	if len(args) == 1 {
		domain = args[0]
	} else if len(args) == 4 {
		salt = args[0]
		algorithm, _ = strconv.Atoi(args[1])
		iterations, _ = strconv.Atoi(args[2])
		domain = args[3]
	} else {
		flag.Usage()
		os.Exit(2)
	}

	re, _ := regexp.Compile(`(\.+|\.*$)`)
	domain = re.ReplaceAllString(domain, ".")

	re, _ = regexp.Compile(`^\.+`)
	domain = re.ReplaceAllString(domain, "")

	re, _ = regexp.Compile(`^[^\.]+\.`)
	parent := re.ReplaceAllString(domain, "")

	if salt == `` {
		if len(nameserver) == 0 {
			conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			nameserver = "@" + conf.Servers[0]
		}

		nameserver = string([]byte(nameserver)[1:]) // chop off @
		// if the nameserver is from /etc/resolv.conf the [ and ] are already
		// added, thereby breaking net.ParseIP. Check for this and don't
		// fully qualify such a name
		if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
			nameserver = nameserver[1 : len(nameserver)-1]
		}
		if i := net.ParseIP(nameserver); i != nil {
			nameserver = net.JoinHostPort(nameserver, strconv.Itoa(port))
		} else {
			nameserver = dns.Fqdn(nameserver) + ":" + strconv.Itoa(port)
		}

		in, _, err := dnssecQuery(nameserver, parent, dns.TypeNSEC3PARAM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		foundNSEC3PARAM := false
		for _, rr := range in.Answer {
			if rr.Header().Rrtype == dns.TypeNSEC3PARAM {
				algorithm = int(rr.(*dns.NSEC3PARAM).Hash)
				iterations = int(rr.(*dns.NSEC3PARAM).Iterations)
				salt = rr.(*dns.NSEC3PARAM).Salt
				foundNSEC3PARAM = true
			}
		}
		if !foundNSEC3PARAM {
			fmt.Fprintf(os.Stderr, "No NSEC3PARAM Record for '%v'\n", parent)
			os.Exit(2)
		}
	}

	if algorithm != 1 {
		fmt.Fprintf(os.Stderr, "Unknown hash algorithm: %v\n", algorithm)
		os.Exit(2)
	}

	nsec3 := dns.HashName(domain, dns.SHA1, uint16(iterations), salt)
	fmt.Printf("%v\n", nsec3)
}

func dnssecQuery(a string, qn string, qt uint16) (r *dns.Msg, rtt time.Duration, err error) {

	c := new(dns.Client)
	c.Net = "udp"

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = false
	m.MsgHdr.AuthenticatedData = false
	m.MsgHdr.CheckingDisabled = false
	m.MsgHdr.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	m.Opcode = dns.OpcodeQuery
	m.Rcode = dns.RcodeSuccess

	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	o.SetUDPSize(dns.DefaultMsgSize)
	m.Extra = append(m.Extra, o)

	qc := uint16(dns.ClassINET)

	m.Question[0] = dns.Question{dns.Fqdn(qn), qt, qc}
	m.Id = dns.Id()

	r, rtt, err = c.Exchange(m, a)

	if err != nil {
		if debug {
			fmt.Printf(";; %s\n", err.Error())
		}
		return
	}

	if r.Id != m.Id {
		if debug {
			fmt.Fprintln(os.Stderr, "Id mismatch")
		}
		return r, rtt, errors.New("Id mismatch")
	}

	if r.MsgHdr.Truncated {
		// First EDNS, then TCP
		c.Net = "tcp"
		r, rtt, err = c.Exchange(m, a)
	}

	return
}
