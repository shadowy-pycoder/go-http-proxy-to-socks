package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"

	gohpts "github.com/shadowy-pycoder/go-http-proxy-to-socks"
	"golang.org/x/term"
)

const (
	app       string = "gohpts"
	addrSOCKS        = "127.0.0.1:1080"
	addrHTTP         = "127.0.0.1:8080"
	tproxyOS         = "linux"
)
const usagePrefix string = `                                                                  
    _____       _    _ _____ _______ _____ 
  / ____|     | |  | |  __ \__   __/ ____|
 | |  __  ___ | |__| | |__) | | | | (___  
 | | |_ |/ _ \|  __  |  ___/  | |  \___ \ 
 | |__| | (_) | |  | | |      | |  ____) |
  \_____|\___/|_|  |_|_|      |_| |_____/ 
                                          
GoHPTS (HTTP(S) Proxy to SOCKS5 proxy) by shadowy-pycoder                         
GitHub: https://github.com/shadowy-pycoder/go-http-proxy-to-socks

Usage: gohpts [OPTIONS] 
Options:
  -h    Show this help message and exit.
`

func root(args []string) error {
	conf := gohpts.Config{}
	flags := flag.NewFlagSet(app, flag.ExitOnError)
	flags.StringVar(&conf.AddrSOCKS, "s", addrSOCKS, "Address of SOCKS5 proxy server")
	flags.StringVar(&conf.User, "u", "", "User for SOCKS5 proxy authentication. This flag invokes prompt for password (not echoed to terminal)")
	flags.StringVar(&conf.AddrHTTP, "l", addrHTTP, "Address of HTTP proxy server")
	flags.StringVar(&conf.ServerUser, "U", "", "User for HTTP proxy (basic auth). This flag invokes prompt for password (not echoed to terminal)")
	flags.StringVar(&conf.CertFile, "c", "", "Path to certificate PEM encoded file")
	flags.StringVar(&conf.KeyFile, "k", "", "Path to private key PEM encoded file")
	flags.StringVar(&conf.ServerConfPath, "f", "", "Path to server configuration file in YAML format")
	if runtime.GOOS == tproxyOS {
		flags.StringVar(&conf.TProxy, "t", "", "Address of transparent proxy server (it starts along with HTTP proxy server)")
		flags.StringVar(&conf.TProxyOnly, "T", "", "Address of transparent proxy server (no HTTP)")
		flags.Func("M", fmt.Sprintf("Transparent proxy mode: %s", gohpts.SupportedTProxyModes), func(flagValue string) error {
			if !slices.Contains(gohpts.SupportedTProxyModes, flagValue) {
				fmt.Fprintf(os.Stderr, "%s: %s is not supported (type '%s -h' for help)\n", app, flagValue, app)
				os.Exit(2)
			}
			conf.TProxyMode = flagValue
			return nil
		})
	}
	flags.BoolFunc("d", "Show logs in DEBUG mode", func(flagValue string) error {
		conf.Debug = true
		return nil
	})
	flags.BoolFunc("j", "Show logs in JSON format", func(flagValue string) error {
		conf.Json = true
		return nil
	})
	flags.BoolFunc("v", "print version", func(flagValue string) error {
		fmt.Println(gohpts.Version)
		os.Exit(0)
		return nil
	})

	flags.Usage = func() {
		fmt.Print(usagePrefix)
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return err
	}
	seen := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if seen["t"] && seen["T"] {
		return fmt.Errorf("cannot specify both -t and -T flags")
	}
	if seen["t"] {
		if !seen["M"] {
			return fmt.Errorf("Transparent proxy mode is not provided: -M flag")
		}
	}
	if seen["T"] {
		for _, da := range []string{"U", "c", "k", "l"} {
			if seen[da] {
				return fmt.Errorf("-T flag only works with -s, -u, -f, -M, -d and -j flags")
			}
		}
		if !seen["M"] {
			return fmt.Errorf("Transparent proxy mode is not provided: -M flag")
		}
	}
	if seen["M"] {
		if !seen["t"] && !seen["T"] {
			return fmt.Errorf("Transparent proxy mode requires -t or -T flag")
		}
	}
	if seen["f"] {
		for _, da := range []string{"s", "u", "U", "c", "k", "l"} {
			if seen[da] {
				if runtime.GOOS == tproxyOS {
					return fmt.Errorf("-f flag only works with -t, -T, -M, -d and -j flags")
				}
				return fmt.Errorf("-f flag only works with -d and -j flags")
			}
		}
	}
	if seen["u"] {
		fmt.Print("SOCKS5 Password: ")
		bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		conf.Pass = string(bytepw)
		fmt.Print("\033[2K\r")
	}
	if seen["U"] {
		fmt.Print("HTTP Password: ")
		bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		conf.ServerPass = string(bytepw)
		fmt.Print("\033[2K\r")
	}

	p := gohpts.New(&conf)
	p.Run()
	return nil
}
