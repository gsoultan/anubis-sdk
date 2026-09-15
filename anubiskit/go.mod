module github.com/gsoultan/anubis-sdk/anubiskit

go 1.26.6

require (
	github.com/go-kit/kit v0.13.0
	github.com/gsoultan/anubis-sdk v0.1.0
	github.com/rabbitmq/amqp091-go v1.13.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/go-kit/log v0.2.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260807164820-c8921c73eeea // indirect
)

// No replace directives, deliberately: they are ignored in a module that is
// being CONSUMED, so anything this module needs to resolve has to be a
// require. It required github.com/gsoultan/anubis-sdk v0.0.0 with a local
// replace until v0.1.0 existed to point at, which meant the tag would not have
// resolved for anybody.
//
// A second replace here pinned google.golang.org/genproto, because go-kit
// v0.13.0 requires the pre-split monolith and grpc/status then finds
// googleapis/rpc in two modules. That ambiguity is real, but it is a WORKSPACE
// one: a workspace resolves a single build list across every module in it.
// Standalone, the longer module path google.golang.org/genproto/googleapis/rpc
// wins for the packages beneath it and nothing is ambiguous.
//
// The pin therefore lives in go.work, which is not published. Verified both
// ways: the workspace build, and this module with GOWORK=off.
