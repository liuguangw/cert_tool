package main

import (
	"github.com/liuguangw/cert_tool/internal/commands"
	"log"
)

func main() {
	if err := commands.Execute(); err != nil {
		log.Fatalln(err)
	}
}
