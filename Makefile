APP_NAME=gohpts
GOOS=linux
GOARCH=amd64

.PHONY: all
all: build

.PHONY: build
build:
	GOOS=${GOOS} GOARCH=${GOARCH} CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o ./bin/${APP_NAME} ./cmd/${APP_NAME}/*.go

.PHONY: test
test:
	go test ./... -v

.PHONY: clean
clean:
	find ./bin ! -name '.gitignore' -type f -exec rm -vrf {} +
	rm -vf *.pcap*
	rm -vf *.txt

