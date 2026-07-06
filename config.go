package gohpts

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
)

type Config struct {
	// http server
	AddrHTTP   string
	ServerUser string
	ServerPass string
	CertFile   string
	KeyFile    string
	Mixed      bool

	// socks5
	SocksProxy      []ProxyEntry
	SocksProxyChain ProxyChain

	// misc
	Interface      string
	ServerConfPath string
	IPv4Enabled    bool
	IPv6Enabled    bool
	SOCKS4Enabled  bool
	NoHTTP         bool
	NoSOCKS        bool
	DNS            string

	// transparent proxy
	TProxyMode       string
	TProxy           string
	TProxyWorkers    uint
	TProxyUDP        string
	TProxyUDPWorkers uint
	Auto             bool
	Dump             bool
	Mark             uint
	IgnoredPorts     string

	// logging
	Debug       bool
	JSON        bool
	LogFilePath string
	NoColor     bool
	AddrPprof   string

	// sniffing
	Sniff        bool
	SniffLogFile string
	Body         bool

	// spoofing
	ARPSpoof string
	NDPSpoof string

	// DNSFilter filters
	DNSFilter DNSFilterLists

	// packet capture
	Pcap string

	// network namespaces
	InNetNS  string
	OutNetNS string
}

type ProxyEntry struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

func (pe ProxyEntry) String() string {
	return pe.Address
}

type ProxyChain struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"`
	Length  int    `yaml:"length"`
}
type DNSFilterLists struct {
	Enabled      bool     `yaml:"enabled"`
	Whitelist    []string `yaml:"whitelist"`
	Blacklist    []string `yaml:"blacklist"`
	BlacklistAll bool     `yaml:"blacklist_all"`
	Spooflist    []string `yaml:"spooflist"`
}

type yamlConfig struct {
	Interface     string `yaml:"interface"`
	IPv4Enabled   bool   `yaml:"ipv4"`
	IPv6Enabled   bool   `yaml:"ipv6"`
	NoHTTP        bool   `yaml:"disable_http"`
	NoSOCKS       bool   `yaml:"disable_socks"`
	SOCKS4Enabled bool   `yaml:"socks4"`
	DNS           string `yaml:"dns"`
	HTTPServer    struct {
		Address  string `yaml:"address"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
		Mixed    bool   `yaml:"mixed"`
	} `yaml:"http_server"`
	ProxyList  []ProxyEntry `yaml:"proxy_list"`
	ProxyChain ProxyChain   `yaml:"proxy_chain"`
	Logging    struct {
		Debug   bool   `yaml:"debug"`
		JSON    bool   `yaml:"json"`
		Logfile string `yaml:"logfile"`
		Nocolor bool   `yaml:"nocolor"`
		Pprof   string `yaml:"pprof"`
	} `yaml:"logging"`
	Sniffing struct {
		Enabled  bool   `yaml:"enabled"`
		Snifflog string `yaml:"snifflog"`
		Body     bool   `yaml:"body"`
	} `yaml:"sniffing"`
	TransparentProxy struct {
		TCP struct {
			Enabled bool   `yaml:"enabled"`
			Address string `yaml:"address"`
			Workers int    `yaml:"workers"`
		} `yaml:"tcp"`
		UDP struct {
			Enabled bool   `yaml:"enabled"`
			Address string `yaml:"address"`
			Workers int    `yaml:"workers"`
		} `yaml:"udp"`
		Mode         string `yaml:"mode"`
		Auto         bool   `yaml:"auto"`
		DumpRules    bool   `yaml:"dump_rules"`
		IgnoredPorts []int  `yaml:"ignored_ports"`
		Mark         int    `yaml:"mark"`
	} `yaml:"transparent_proxy"`
	Arpspoof struct {
		Enabled  bool   `yaml:"enabled"`
		Settings string `yaml:"settings"`
	} `yaml:"arpspoof"`
	Ndpspoof struct {
		Enabled  bool   `yaml:"enabled"`
		Settings string `yaml:"settings"`
	} `yaml:"ndpspoof"`
	DNSFilter DNSFilterLists `yaml:"dns_filter"`
	Pcap      struct {
		Enabled  bool   `yaml:"enabled"`
		Settings string `yaml:"settings"`
	} `yaml:"pcap"`
	Netns struct {
		Enabled bool   `yaml:"enabled"`
		In      string `yaml:"in"`
		Out     string `yaml:"out"`
	} `yaml:"netns"`
}

func createConfigFromPath(path string) (*Config, error) {
	yamlFile, err := os.ReadFile(expandPath(path))
	if err != nil {
		return nil, err
	}
	sconf := yamlConfig{}
	err = yaml.Unmarshal(yamlFile, &sconf)
	if err != nil {
		return nil, err
	}
	conf := Config{}

	conf.NoHTTP = sconf.NoHTTP
	conf.NoSOCKS = sconf.NoSOCKS
	if !conf.NoHTTP {
		conf.AddrHTTP = sconf.HTTPServer.Address
		conf.ServerUser = sconf.HTTPServer.Username
		conf.ServerPass = sconf.HTTPServer.Password
		conf.CertFile = sconf.HTTPServer.CertFile
		conf.KeyFile = sconf.HTTPServer.KeyFile
		conf.Mixed = sconf.HTTPServer.Mixed
	}

	conf.SocksProxy = sconf.ProxyList
	conf.SocksProxyChain = sconf.ProxyChain

	conf.Interface = sconf.Interface
	conf.IPv4Enabled = sconf.IPv4Enabled
	conf.IPv6Enabled = sconf.IPv6Enabled
	conf.SOCKS4Enabled = sconf.SOCKS4Enabled
	conf.DNS = sconf.DNS

	if sconf.TransparentProxy.TCP.Enabled || sconf.TransparentProxy.UDP.Enabled {
		if sconf.TransparentProxy.TCP.Enabled {
			conf.TProxy = sconf.TransparentProxy.TCP.Address
			conf.TProxyWorkers = uint(sconf.TransparentProxy.TCP.Workers)
		}
		if sconf.TransparentProxy.UDP.Enabled {
			conf.TProxyUDP = sconf.TransparentProxy.UDP.Address
			conf.TProxyUDPWorkers = uint(sconf.TransparentProxy.UDP.Workers)
		}
		conf.TProxyMode = sconf.TransparentProxy.Mode
		conf.Auto = sconf.TransparentProxy.Auto
		conf.Mark = uint(sconf.TransparentProxy.Mark)
		if conf.Auto {
			conf.Dump = sconf.TransparentProxy.DumpRules
			conf.IgnoredPorts = strings.Trim(strings.Join(strings.Fields(fmt.Sprint(sconf.TransparentProxy.IgnoredPorts)), ","), "[]")
		}
	}

	conf.Debug = sconf.Logging.Debug
	conf.JSON = sconf.Logging.JSON
	conf.LogFilePath = sconf.Logging.Logfile
	conf.NoColor = sconf.Logging.Nocolor
	conf.AddrPprof = sconf.Logging.Pprof

	if sconf.Sniffing.Enabled {
		conf.Sniff = true
		conf.SniffLogFile = sconf.Sniffing.Snifflog
		conf.Body = sconf.Sniffing.Body
	}
	if sconf.Arpspoof.Enabled {
		conf.ARPSpoof = sconf.Arpspoof.Settings
	}
	if sconf.Ndpspoof.Enabled {
		conf.NDPSpoof = sconf.Ndpspoof.Settings
	}
	if sconf.DNSFilter.Enabled {
		conf.DNSFilter = sconf.DNSFilter
	}
	if sconf.Pcap.Enabled {
		conf.Pcap = sconf.Pcap.Settings
	}
	if sconf.Netns.Enabled {
		conf.InNetNS = sconf.Netns.In
		conf.OutNetNS = sconf.Netns.Out
	}
	return &conf, nil
}

func parseConfig(conf *Config) error {
	if len(conf.SocksProxy) == 0 {
		conf.SocksProxy = []ProxyEntry{{Address: ""}}
	}
	if conf.ServerConfPath != "" {
		yamlConf, err := createConfigFromPath(conf.ServerConfPath)
		if err != nil {
			return err
		}
		conf.ServerConfPath = ""
		if !conf.NoHTTP {
			conf.NoHTTP = yamlConf.NoHTTP
		}
		if !conf.NoSOCKS {
			conf.NoSOCKS = yamlConf.NoSOCKS
		}
		if !conf.IPv4Enabled {
			conf.IPv4Enabled = yamlConf.IPv4Enabled
		}

		if !conf.IPv6Enabled {
			conf.IPv6Enabled = yamlConf.IPv6Enabled
		}
		var ipv6only bool
		if conf.IPv6Enabled && !conf.IPv4Enabled {
			ipv6only = true
		}
		// if user did not specify http address (from CLI), use address from config or default
		if conf.AddrHTTP == "" {
			if yamlConf.AddrHTTP == "" {
				if ipv6only {
					conf.AddrHTTP = addr6HTTP
				} else {
					conf.AddrHTTP = addrHTTP
				}
			} else {
				conf.AddrHTTP = yamlConf.AddrHTTP
			}
		}
		// the same for all other http settings
		if conf.ServerUser == "" {
			conf.ServerUser = yamlConf.ServerUser
		}
		if conf.ServerPass == "" {
			conf.ServerPass = yamlConf.ServerPass
		}
		if conf.CertFile == "" {
			conf.CertFile = yamlConf.CertFile
		}
		if conf.KeyFile == "" {
			conf.KeyFile = yamlConf.KeyFile
		}
		if !conf.Mixed {
			conf.Mixed = yamlConf.Mixed
		}

		// proxy chain can only be enabled via yaml config (providing socks5 address via cli disables it)
		conf.SocksProxyChain.Enabled = false
		if conf.SocksProxy[0].Address == "" {
			if yamlConf.SocksProxyChain.Enabled && len(yamlConf.SocksProxy) > 0 {
				conf.SocksProxy = yamlConf.SocksProxy
				conf.SocksProxyChain = yamlConf.SocksProxyChain
			} else if len(yamlConf.SocksProxy) > 0 {
				// proxychain disabled, use first address from config
				conf.SocksProxy = yamlConf.SocksProxy
			} else {
				// fallback to default address
				if ipv6only {
					conf.SocksProxy[0].Address = addr6SOCKS
				} else {
					conf.SocksProxy[0].Address = addrSOCKS
				}
			}
		}

		if conf.Interface == "" {
			conf.Interface = yamlConf.Interface
		}

		if !conf.SOCKS4Enabled {
			conf.SOCKS4Enabled = yamlConf.SOCKS4Enabled
		}

		if conf.DNS == "" {
			conf.DNS = yamlConf.DNS
		}

		if !conf.Debug {
			conf.Debug = yamlConf.Debug
		}

		if !conf.JSON {
			conf.JSON = yamlConf.JSON
		}

		if conf.LogFilePath == "" {
			conf.LogFilePath = yamlConf.LogFilePath
		}

		if !conf.NoColor {
			conf.NoColor = yamlConf.NoColor
		}

		if conf.AddrPprof == "" {
			conf.AddrPprof = yamlConf.AddrPprof
		}

		if !conf.Sniff {
			conf.Sniff = yamlConf.Sniff
		}

		if conf.SniffLogFile == "" {
			conf.SniffLogFile = yamlConf.SniffLogFile
		}

		if !conf.Body {
			conf.Body = yamlConf.Body
		}

		if conf.TProxyMode == "" {
			conf.TProxyMode = yamlConf.TProxyMode
		}

		if conf.TProxy == "" {
			conf.TProxy = yamlConf.TProxy
		}

		if conf.TProxyWorkers == 0 {
			conf.TProxyWorkers = yamlConf.TProxyWorkers
		}

		if conf.TProxyUDP == "" {
			conf.TProxyUDP = yamlConf.TProxyUDP
		}

		if conf.TProxyUDPWorkers == 0 {
			conf.TProxyUDPWorkers = yamlConf.TProxyUDPWorkers
		}

		if !conf.Auto {
			conf.Auto = yamlConf.Auto
		}

		if !conf.Dump {
			conf.Dump = yamlConf.Dump
		}

		if conf.Mark == 0 {
			conf.Mark = yamlConf.Mark
		}

		if conf.ARPSpoof == "" {
			conf.ARPSpoof = yamlConf.ARPSpoof
		}

		if conf.NDPSpoof == "" {
			conf.NDPSpoof = yamlConf.NDPSpoof
		}

		if conf.Pcap == "" {
			conf.Pcap = yamlConf.Pcap
		}

		if conf.InNetNS == "" {
			conf.InNetNS = yamlConf.InNetNS
		}

		if conf.OutNetNS == "" {
			conf.OutNetNS = yamlConf.OutNetNS
		}

		if conf.IgnoredPorts == "" {
			conf.IgnoredPorts = yamlConf.IgnoredPorts
		}
		conf.DNSFilter = yamlConf.DNSFilter
	} else {
		var ipv6only bool
		if conf.IPv6Enabled && !conf.IPv4Enabled {
			ipv6only = true
		}
		// only set defaults for http and socks
		if conf.AddrHTTP == "" {
			if ipv6only {
				conf.AddrHTTP = addr6HTTP
			} else {
				conf.AddrHTTP = addrHTTP
			}
		}
		if conf.SocksProxy[0].Address == "" {
			if ipv6only {
				conf.SocksProxy[0].Address = addr6SOCKS
			} else {
				conf.SocksProxy[0].Address = addrSOCKS
			}
		}
	}
	if !slices.Contains(SupportedTProxyOS, runtime.GOOS) {
		if conf.TProxy != "" {
			return fmt.Errorf("option `TProxy` is available only on linux/android systems")
		}
		if conf.TProxyWorkers > 0 {
			return fmt.Errorf("option `TProxyWorkers` is available only on linux/android systems")
		}
		if conf.TProxyMode != "" {
			return fmt.Errorf("option `TProxyMode` is available only on linux/android systems")
		}
		if conf.TProxyUDP != "" {
			return fmt.Errorf("option `TProxyUDP` is available only on linux/android systems")
		}
		if conf.TProxyUDPWorkers > 0 {
			return fmt.Errorf("option `TProxyUDPWorkers` is available only on linux/android systems")
		}
		if conf.Auto {
			return fmt.Errorf("option `Auto` is available only on linux/android systems")
		}
		if conf.Dump {
			return fmt.Errorf("option `Dump` is available only on linux/android systems")
		}
		if conf.Mark > 0 {
			return fmt.Errorf("option `Mark` is available only on linux/android systems")
		}
		if conf.ARPSpoof != "" {
			return fmt.Errorf("option `ARPSpoof` is available only on linux/android systems")
		}
		if conf.NDPSpoof != "" {
			return fmt.Errorf("option `NDPSpoof` is available only on linux/android systems")
		}
		if conf.Pcap != "" {
			return fmt.Errorf("option `Pcap` is available only on linux/android systems")
		}
		if conf.InNetNS != "" {
			return fmt.Errorf("option `InNetNS` is available only on linux/android systems")
		}
		if conf.OutNetNS != "" {
			return fmt.Errorf("option `OutNetNS` is available only on linux/android systems")
		}
		if conf.IgnoredPorts != "" {
			return fmt.Errorf("option `IgnoredPorts` is available only on linux/android systems")
		}
		if conf.DNSFilter.Enabled {
			return fmt.Errorf("option `DNSFilter` is available only on linux/android systems")
		}
	} else if conf.TProxyMode == "" {
		conf.TProxy = ""
		conf.TProxyUDP = ""
	}
	return nil
}
