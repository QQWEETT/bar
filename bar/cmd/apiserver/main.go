package main

import (
	"bar/internal/app/apiserver"
	"flag"
	"github.com/BurntSushi/toml"
	"log"
)

var (
	configPath string
)

// update users  SET ppm = ppm - case   when ppm > 1 then 1 else ppm end

func init() {
	flag.StringVar(&configPath, "config-path", "configs/apiserver.toml", "path to config file")
}

func main() {

	flag.Parse()
	config := apiserver.NewConfig()
	_, err := toml.DecodeFile(configPath, config)
	if err != nil {
		log.Fatal(err)
	}
	if err := apiserver.Start(config); err != nil {
		log.Fatal(err)
	}
}
