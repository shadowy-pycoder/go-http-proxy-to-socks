package gohpts

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name     string
		config   *Config
		expected *Config
	}{
		{
			name:     "empty",
			config:   &Config{},
			expected: &Config{AddrHTTP: addrHTTP, SocksProxy: []ProxyEntry{{Address: addrSOCKS}}},
		},
		{
			name:     "empty yaml",
			config:   &Config{ServerConfPath: "testdata/config_empty.yaml"},
			expected: &Config{AddrHTTP: addrHTTP, SocksProxy: []ProxyEntry{{Address: addrSOCKS}}},
		},
		{
			name:     "proxy_chain disabled",
			config:   &Config{ServerConfPath: "testdata/config_proxy_chain_disabled.yaml"},
			expected: &Config{AddrHTTP: addrHTTP, SocksProxy: []ProxyEntry{{Address: "127.0.0.1:1082", Username: "username", Password: "password"}}},
		},
		{
			name:   "proxy_chain enabled",
			config: &Config{ServerConfPath: "testdata/config_proxy_chain_enabled.yaml"},
			expected: &Config{
				AddrHTTP: addrHTTP,
				SocksProxy: []ProxyEntry{
					{Address: "127.0.0.1:1080", Username: "username", Password: "password"},
					{Address: "127.0.0.1:1081"},
					{Address: "127.0.0.1:1082"},
				},
				SocksProxyChain: ProxyChain{Enabled: true, Type: "strict", Length: 2},
			},
		},
		{
			name: "override",
			config: &Config{
				AddrHTTP:       "127.0.0.1:6969",
				KeyFile:        "/tmp/key.pem",
				ServerUser:     "user",
				ServerPass:     "secret",
				SocksProxy:     []ProxyEntry{{Address: addrSOCKS}},
				ServerConfPath: "testdata/config_override.yaml",
				Interface:      "wlan0",
				IPv6Enabled:    true,
				TProxyMode:     "tproxy",
				TProxy:         "0.0.0.0:8887",
				TProxyUDP:      "0.0.0.0:8889",
				NoHTTP:         true,
				NoSOCKS:        true,
				Auto:           true,
				Dump:           true,
				Mark:           69,
				IgnoredPorts:   "22,443",
				ARPSpoof:       "targets 192.168.10.0/24;fullduplex false;debug true;interval 10s",
			},
			expected: &Config{
				AddrHTTP:      "127.0.0.1:6969",
				CertFile:      "~/local.crt",
				KeyFile:       "/tmp/key.pem",
				ServerUser:    "user",
				ServerPass:    "secret",
				SocksProxy:    []ProxyEntry{{Address: addrSOCKS}},
				Interface:     "wlan0",
				IPv6Enabled:   true,
				TProxyMode:    "tproxy",
				TProxy:        "0.0.0.0:8887",
				TProxyWorkers: 1,
				TProxyUDP:     "0.0.0.0:8889",
				NoHTTP:        true,
				NoSOCKS:       true,
				Auto:          true,
				Dump:          true,
				Mark:          69,
				IgnoredPorts:  "22,443",
				Debug:         true,
				AddrPprof:     "127.0.0.1:8088",
				Sniff:         true,
				Body:          true,
				ARPSpoof:      "targets 192.168.10.0/24;fullduplex false;debug true;interval 10s",
				NDPSpoof:      "ra true;debug true;prefix 2001:db8:7a31:4400::/64;router_lifetime 30s;interval 10s;mtu 1500;packet HRD F2 DSDS",
			},
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			actual := testcase.config
			err := parseConfig(actual)
			require.NoError(t, err)
			require.Equal(t, actual, testcase.expected)
		})
	}
}
