APP_NAME=gohpts

.PHONY: all
all: build

.PHONY: build
build:
	CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o ./bin/${APP_NAME} ./cmd/${APP_NAME}/*.go

.PHONY: test
test:
	go test ./... -v

.PHONY: clean
clean:
	find ./bin ! -name '.gitignore' -type f -exec rm -vrf {} +
	rm -vf *.pcap*
	rm -vf *.txt

