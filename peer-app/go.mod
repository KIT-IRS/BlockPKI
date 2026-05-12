module peer-app

go 1.24.0

toolchain go1.24.12

require (
	github.com/bnb-chain/tss-lib v1.5.0
	github.com/hyperledger/fabric-gateway v1.10.1
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.7
	google.golang.org/grpc v1.78.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/btcsuite/btcd v0.0.0-20190629003639-c26ffa870fd8 // indirect
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d // indirect
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.0 // indirect
	github.com/gogo/protobuf v1.2.1 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.0.0 // indirect
	github.com/ipfs/go-log v0.0.1 // indirect
	github.com/mattn/go-colorable v0.1.2 // indirect
	github.com/mattn/go-isatty v0.0.8 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/opentracing/opentracing-go v1.1.0 // indirect
	github.com/otiai10/primes v0.0.0-20180210170552-f6d2a1ba97c4 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/whyrusleeping/go-logging v0.0.0-20170515211332-0457bb6b88fc // indirect
	golang.org/x/crypto v0.44.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
)

// Fix protobuf conflicts - use standard versions that work together
replace (
	github.com/golang/protobuf => github.com/golang/protobuf v1.5.4
	google.golang.org/protobuf => google.golang.org/protobuf v1.33.0
)
