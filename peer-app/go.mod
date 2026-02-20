module peer-app

go 1.24.0

toolchain go1.24.12

require (
	github.com/bnb-chain/tss-lib v1.5.0
	github.com/hyperledger/fabric-gateway v1.10.1
	github.com/hyperledger/fabric-sdk-go v1.0.1-0.20220117114400-c848d119936b
	github.com/stretchr/testify v1.11.1
	google.golang.org/grpc v1.78.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible // indirect
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/btcsuite/btcd v0.0.0-20190629003639-c26ffa870fd8 // indirect
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/cfssl v1.4.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.0 // indirect
	github.com/fsnotify/fsnotify v1.4.7 // indirect
	github.com/go-kit/kit v0.10.0 // indirect
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/gogo/protobuf v1.2.1 // indirect
	github.com/golang/mock v1.4.3 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.0.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hyperledger/fabric-config v0.0.5 // indirect
	github.com/hyperledger/fabric-lib-go v1.0.0 // indirect
	github.com/hyperledger/fabric-protos-go v0.3.0 // indirect
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.7 // indirect
	github.com/ipfs/go-log v0.0.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mattn/go-colorable v0.1.2 // indirect
	github.com/mattn/go-isatty v0.0.8 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/mitchellh/mapstructure v1.3.2 // indirect
	github.com/opentracing/opentracing-go v1.1.0 // indirect
	github.com/otiai10/primes v0.0.0-20180210170552-f6d2a1ba97c4 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.3.0 // indirect
	github.com/prometheus/client_model v0.1.0 // indirect
	github.com/prometheus/common v0.7.0 // indirect
	github.com/prometheus/procfs v0.0.8 // indirect
	github.com/rogpeppe/go-internal v1.11.0 // indirect
	github.com/spf13/afero v1.6.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.3.2 // indirect
	github.com/weppos/publicsuffix-go v0.5.0 // indirect
	github.com/whyrusleeping/go-logging v0.0.0-20170515211332-0457bb6b88fc // indirect
	github.com/zmap/zcrypto v0.0.0-20190729165852-9051775e6a2e // indirect
	github.com/zmap/zlint v0.0.0-20190806154020-fd021b4cfbeb // indirect
	golang.org/x/crypto v0.44.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Fix protobuf conflicts - use standard versions that work together
replace (
	github.com/golang/protobuf => github.com/golang/protobuf v1.5.4
	google.golang.org/protobuf => google.golang.org/protobuf v1.33.0
)
