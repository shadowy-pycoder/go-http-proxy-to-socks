package gohpts

import (
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRecords(t *testing.T) {
	data, err := os.ReadFile("testdata/records.txt")
	require.NoError(t, err)
	df := new(dnsFilter)
	parseRecords(data, &df.blacklist)
	require.Equal(t, df.blacklist, []string{
		"ad-assets.futurecdn.net",
		"ck.getcookiestxt.com",
		"eu1.clevertap-prod.com",
		"wizhumpgyros.com",
		"*.0pengl.com",
	})
}

func TestParseSpoofRecords(t *testing.T) {
	data, err := os.ReadFile("testdata/spoof_records.txt")
	require.NoError(t, err)
	df := new(dnsFilter)
	parseSpoofRecords(data, &df.spooflist)
	require.Equal(t, df.spooflist, []dnsSpoofRecord{
		{address: netip.IPv4Unspecified(), domain: "3lift.org"},
		{address: netip.IPv6Unspecified(), domain: "448ff4fcfcd199a.com"},
		{address: netip.MustParseAddr("127.0.0.1"), domain: "4ourkidsky.com"},
		{address: netip.MustParseAddr("8.8.8.8"), domain: "*.new.915yzt.cn"},
	})
}
