package main

import (
	"fmt"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas"
)

func main() {
	fmt.Println("Welcome to CyberArk AAM PKI-as-a-Service, brought to you by Sales Engineers.  Sales Engineers... doing our own shit since 2010.")
	fmt.Printf("pkiaas v%s\n", pkiaas.FullVersionName)
}
