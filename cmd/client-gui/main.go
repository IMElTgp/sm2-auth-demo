package main

import (
	"log"

	"task1-1/internal/gui"
)

func main() {
	if err := gui.Run(); err != nil {
		log.Fatalf("client exited with error: %v", err)
	}
}
