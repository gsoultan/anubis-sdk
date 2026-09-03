module github.com/gsoultan/anubis-sdk/anubiskit

go 1.26.6

require (
	github.com/go-kit/kit v0.13.0
	github.com/gsoultan/anubis-sdk v0.0.0
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

replace github.com/gsoultan/anubis-sdk => ../

// go-kit v0.13.0 pins the monolithic google.golang.org/genproto, which still
// contains googleapis/rpc — the same packages the split-out
// genproto/googleapis/rpc module now provides. grpc/status then resolves to
// two modules at once and nothing builds.
//
// A plain require does not survive `go mod tidy`, which sees nothing importing
// genproto directly and drops it. A replace does, and it is the honest
// statement anyway: this is not a version preference, it is a rule that the
// pre-split module must never be selected.
replace google.golang.org/genproto => google.golang.org/genproto v0.0.0-20260810153831-ec0a7760b754
