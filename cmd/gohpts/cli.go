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
	daemon := flags.Bool("D", false, "Run as a daemon (provide -logfile to see logs)")
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
	flags.StringVar(&conf.LogFilePath, "logfile", "", "Log file path (Default: stdout)")
	flags.BoolVar(&conf.Debug, "d", false, "Show logs in DEBUG mode")
	flags.BoolVar(&conf.Json, "j", false, "Show logs in JSON format")
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
				return fmt.Errorf("-T flag only works with -s, -u, -f, -M, -d, -D, -logfile and -j flags")
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
					return fmt.Errorf("-f flag only works with -t, -T, -M, -d, -D, -logfile and -j flags")
				}
				return fmt.Errorf("-f flag only works with -d, -D, -logfile and -j flags")
			}
		}
	}
	if seen["D"] {
		if seen["u"] || seen["U"] {
			return fmt.Errorf("-u and -U flags do not work in daemon mode")
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

	if *daemon {
		if os.Getenv("GOHPTS_DAEMON") != "1" {
			env := os.Environ()
			files := [3]*os.File{}
			env = append(env, "GOHPTS_DAEMON=1")
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
			attr := &os.ProcAttr{
				Files: []*os.File{
					files[0], // stdin
					files[1], // stdout
					files[2], // stderr
				},
				Dir: ".",
				Env: env,
			}
			path, err := os.Executable()
			if err != nil {
				return err
			}
			process, err := os.StartProcess(
				path,
				os.Args,
				attr,
			)
			if err != nil {
				return err
			}
			fmt.Printf("%s pid: %d\n", app, process.Pid)
			process.Release()
			os.Exit(0)
		}
	}
	p := gohpts.New(&conf)
	p.Run()
	return nil
}
