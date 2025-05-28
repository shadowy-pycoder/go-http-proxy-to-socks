APP_NAME=gohpts
TEST_FILE=${APP_NAME}.test

.PHONY: all 
all: build

.PHONY: build
build: 
	go build -ldflags "-s -w" -trimpath -o ./bin/${APP_NAME} ./cmd/${APP_NAME}/*.go

.PHONY: bench test
bench: 
	go test -bench=. -benchmem -run=^$$ -benchtime 512x -cpuprofile='cpu.prof' -memprofile='mem.prof'

.PHONY: clean
clean:
	find ./bin ! -name '.gitignore' -type f -exec rm -vrf {} +

