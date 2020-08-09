.PHONY: client

build-dir:
	mkdir -p build

client:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -ldflags '-extldflags "-static"' -o builds/simplepki cli/*.go
