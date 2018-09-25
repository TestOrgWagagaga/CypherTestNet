.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/cyphertestnet/go-cypherium/cmd/swarm
	go build -o bin/cypher     github.com/cyphertestnet/go-cypherium/cmd/cypher
	go build -o bin/bootnode github.com/cyphertestnet/go-cypherium/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/cyphertestnet/go-cypherium/swarm/...
