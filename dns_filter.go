package gohpts

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/vishvananda/netns"
)

const dnsFilterTimeout time.Duration = 5 * time.Second

type dnsSpoofRecord struct {
	address netip.Addr
	domain  string
}

type dnsFilter struct {
	blacklist    []string
	whitelist    []string
	blacklistAll bool
	spooflist    []dnsSpoofRecord
}

func newDNSFilter(lists *DNSFilterLists, ns netns.NsHandle, logger *zerolog.Logger) *dnsFilter {
	// TODO: make it async, add refresh
	df := new(dnsFilter)
	df.blacklistAll = lists.BlacklistAll
	var d contextDialer
	if ns > 0 {
		d = getNSDialer(ns, dnsFilterTimeout, 0)
	} else {
		d = getBaseDialer(dnsFilterTimeout, 0)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     d.DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: dnsFilterTimeout,
	}
	for _, rec := range lists.Blacklist {
		if isURL(rec) {
			data, err := getURLData(rec, httpClient)
			if err != nil {
				logger.Warn().Err(err).Msg("Failed parsing blacklist")
				continue
			}
			parseRecords(data, &df.blacklist)
		} else if isPath(rec) {
			data, err := getFileData(rec)
			if err != nil {
				logger.Warn().Err(err).Msg("Failed parsing blacklist")
				continue
			}
			parseRecords(data, &df.blacklist)
		} else {
			r, ok := parseRecord(rec)
			if !ok {
				continue
			}
			df.blacklist = append(df.blacklist, r)
		}
	}
	for _, rec := range lists.Whitelist {
		if isURL(rec) {
			data, err := getURLData(rec, httpClient)
			if err != nil {
				logger.Warn().Err(err).Msg("Failed parsing whitelist")
				continue
			}
			parseRecords(data, &df.whitelist)
		} else if isPath(rec) {
			data, err := getFileData(rec)
			if err != nil {
				logger.Warn().Err(err).Msg("Failed parsing whitelist")
				continue
			}
			parseRecords(data, &df.whitelist)
		} else {
			r, ok := parseRecord(rec)
			if !ok {
				continue
			}
			df.whitelist = append(df.whitelist, r)
		}
	}
	for _, rec := range lists.Spooflist {
		if isURL(rec) {
			data, err := getURLData(rec, httpClient)
			if err != nil {
				logger.Warn().Err(err).Msg("Failed parsing spooflist")
				continue
			}
			parseSpoofRecords(data, &df.spooflist)
		} else if isPath(rec) {
			data, err := getFileData(rec)
			if err != nil {
				logger.Warn().Err(err).Msg("Failed parsing spooflist")
				continue
			}
			parseSpoofRecords(data, &df.spooflist)
		} else {
			r, ok := parseSpoofRecord(rec)
			if !ok {
				continue
			}
			df.spooflist = append(df.spooflist, r)
		}
	}
	return df
}

func (df *dnsFilter) domainIsBlacklisted(name string) bool {
	for _, r := range df.whitelist {
		if matchDomain(name, r) {
			return false
		}
	}
	if df.blacklistAll {
		return true
	}
	for _, r := range df.blacklist {
		if matchDomain(name, r) {
			return true
		}
	}
	return false
}

func (df *dnsFilter) domainIsSpoofed(name string) (netip.Addr, bool) {
	for _, r := range df.spooflist {
		if matchDomain(name, r.domain) {
			return r.address, true
		}
	}
	return netip.Addr{}, false
}

func getURLData(url string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed connecting to %s: check your internet connection", url)
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("failed connecting to %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getFileData(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func parseRecord(r string) (string, bool) {
	r = strings.ToLower(strings.Trim(r, "\r\n "))
	if r == "" || r[0] == '#' {
		return "", false
	}
	fields := strings.Fields(r)
	if len(fields) == 0 || len(fields) > 2 {
		return "", false
	}
	if len(fields) == 1 {
		f := fields[0]
		if f == "0.0.0.0" {
			return "", false
		}
		if strings.Contains(f, "*") && (!strings.HasPrefix(f, "*.") || strings.Count(f, "*") != 1) {
			return "", false
		}
		return f, true
	}
	if fields[0] != "0.0.0.0" {
		return "", false
	}
	f := fields[1]
	if f == "0.0.0.0" {
		return "", false
	}
	if strings.Contains(f, "*") && (!strings.HasPrefix(f, "*.") || strings.Count(f, "*") != 1) {
		return "", false
	}
	return f, true
}

func parseRecords(data []byte, list *[]string) {
	for line := range strings.Lines(string(data)) {
		rec, ok := parseRecord(line)
		if !ok {
			continue
		}
		*list = append(*list, rec)
	}
}

func parseSpoofRecord(r string) (dnsSpoofRecord, bool) {
	r = strings.ToLower(strings.Trim(r, "\r\n "))
	if r == "" || r[0] == '#' {
		return dnsSpoofRecord{}, false
	}
	fields := strings.Fields(r)
	if len(fields) != 2 {
		return dnsSpoofRecord{}, false
	}
	f := fields[1]
	if f == "0.0.0.0" {
		return dnsSpoofRecord{}, false
	}
	if strings.Contains(f, "*") && (!strings.HasPrefix(f, "*.") || strings.Count(f, "*") != 1) {
		return dnsSpoofRecord{}, false
	}
	addr, err := netip.ParseAddr(fields[0])
	if err != nil {
		return dnsSpoofRecord{}, false
	}
	return dnsSpoofRecord{address: addr, domain: f}, true
}

func parseSpoofRecords(data []byte, list *[]dnsSpoofRecord) {
	for line := range strings.Lines(string(data)) {
		rec, ok := parseSpoofRecord(line)
		if !ok {
			continue
		}
		*list = append(*list, rec)
	}
}

func matchDomain(name, r string) bool {
	name = strings.ToLower(strings.Trim(name, "\r\n "))
	if r == name {
		return true
	} else if strings.HasPrefix(r, "*.") {
		wildcardDomain := r[2:]
		return strings.HasSuffix(name, fmt.Sprintf(".%s", wildcardDomain)) || name == wildcardDomain
	}
	return false
}

func isURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func isPath(s string) bool {
	_, err := os.Stat(expandPath(s))
	return err == nil
}
