package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/libsingularity/src/system/core/go/sintysystem"

	"github.com/singularityos-lab/sinty-firewalld/internal/kernel"
	"github.com/singularityos-lab/sinty-firewalld/internal/service"
)

func main() {
	statePath := flag.String("state", "/var/lib/sinty-firewalld/state.json", "where the firewall settings are kept")
	show := flag.Bool("show", false, "print the ruleset the kernel holds and exit")
	flag.Parse()
	log.SetFlags(0)

	if *show {
		sum, err := sintysystem.FirewallState()
		if err != nil {
			log.Fatalf("reading the ruleset: %v", err)
		}
		fmt.Printf("table %v, input chain %v, drops by default %v, %d rules\n", sum.TablePresent, sum.ChainPresent, sum.PolicyDrop, sum.Rules)
		for _, c := range sum.Comments {
			if c != "" {
				fmt.Println(" ", c)
			}
		}
		return
	}

	svc, err := service.New(*statePath, kernel.Nftables{})
	if err != nil {
		log.Fatal(err)
	}
	if err := svc.Start(); err != nil {
		log.Printf("applying the saved ruleset: %v", err)
	}
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Fatalf("system bus: %v", err)
	}
	defer conn.Close()
	if err := svc.Export(conn); err != nil {
		log.Fatalf("export: %v", err)
	}
	reply, err := conn.RequestName(service.Name, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("cannot own %s: %v", service.Name, err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
