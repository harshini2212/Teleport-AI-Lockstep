// Nested module: the Temporal-dependent code lives here so the ROOT module
// (../) stays stdlib-only and offline-buildable. This module imports the root
// packages via the replace directive below.
//
// Verified with `go mod tidy && go build ./... && go vet ./...` (Go 1.23) — all
// clean. If go.sum is ever missing, `go mod tidy` regenerates it from the
// pinned versions here.
module github.com/harshini2212/teleport-lifecycle-guard/go/temporal

go 1.22

require (
	github.com/harshini2212/teleport-lifecycle-guard/go v0.0.0
	go.temporal.io/sdk v1.30.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/facebookgo/clock v0.0.0-20150410010913-600d898af40a // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.22.0 // indirect
	github.com/nexus-rpc/sdk-go v0.0.11 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/robfig/cron v1.2.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	go.temporal.io/api v1.40.0 // indirect
	golang.org/x/exp v0.0.0-20231127185646-65229373498e // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240827150818-7e3bb234dfed // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240827150818-7e3bb234dfed // indirect
	google.golang.org/grpc v1.66.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/harshini2212/teleport-lifecycle-guard/go => ../
