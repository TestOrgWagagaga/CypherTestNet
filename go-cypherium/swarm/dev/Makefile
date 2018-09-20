.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/cypherium_private/go-cypherium/cmd/swarm
	go build -o bin/cypher     github.com/cypherium_private/go-cypherium/cmd/cypher
	go build -o bin/bootnode github.com/cypherium_private/go-cypherium/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/cypherium_private/go-cypherium/swarm/...
