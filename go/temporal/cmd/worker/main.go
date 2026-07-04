// Command worker runs the Lifecycle Guard Temporal worker. It reads the Temporal
// address/namespace from the environment (Kubernetes-friendly) and serves the
// JML, JIT, and lockout workflows.
//
//	TEMPORAL_ADDRESS   default 127.0.0.1:7233
//	TEMPORAL_NAMESPACE default "default"
package main

import (
	"log"
	"os"

	"go.temporal.io/sdk/client"

	"github.com/harshini2212/teleport-lifecycle-guard/go/temporal/worker"
)

func main() {
	hostPort := envOr("TEMPORAL_ADDRESS", client.DefaultHostPort)
	namespace := envOr("TEMPORAL_NAMESPACE", client.DefaultNamespace)

	log.Printf("lifecycle-guard worker: temporal=%s namespace=%s queue=%s", hostPort, namespace, worker.TaskQueue)
	if err := worker.Run(hostPort, namespace); err != nil {
		log.Fatalf("worker exited: %v", err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
