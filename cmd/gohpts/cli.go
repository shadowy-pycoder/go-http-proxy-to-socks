package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	gohpts "github.com/shadowy-pycoder/go-http-proxy-to-socks"
)

const (
	app       string = "gohpts"
	addrSOCKS        = ":1080"
	addrHTTP         = ":8080"
)
const usagePrefix string = `                                                                  
    _____       _    _ _____ _______ _____ 
  / ____|     | |  | |  __ \__   __/ ____|
 | |  __  ___ | |__| | |__) | | | | (___  
 | | |_ |/ _ \|  __  |  ___/  | |  \___ \ 
 | |__| | (_) | |  | | |      | |  ____) |
  \_____|\___/|_|  |_|_|      |_| |_____/ 
                                          
GoHPTS (HTTP Proxy to SOCKS5) by shadowy-pycoder                         
GitHub: https://github.com/shadowy-pycoder/go-http-proxy-to-socks

Usage: gohpts [OPTIONS] 
Options:
  -h    Show this help message and exit.
`

func root(args []string) error {
	conf := gohpts.Config{AddrSOCKS: addrSOCKS, AddrHTTP: addrHTTP}
	flags := flag.NewFlagSet(app, flag.ExitOnError)
	flags.Func("s", "Address of SOCKS5 proxy server (Default: localhost:1080)", func(flagValue string) error {
		i, err := strconv.Atoi(flagValue)
		if err == nil {
			conf.AddrSOCKS = fmt.Sprintf(":%d", i)
		} else {
			conf.AddrSOCKS = flagValue
		}
		return nil
	})
	flags.Func("l", "Address of HTTP proxy server (Default: localhost:8080)", func(flagValue string) error {
		i, err := strconv.Atoi(flagValue)
		if err == nil {
			conf.AddrHTTP = fmt.Sprintf(":%d", i)
		} else {
			conf.AddrHTTP = flagValue
		}
		return nil
	})
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
	app := gohpts.New(&conf)
	app.Run()
	return nil
}
