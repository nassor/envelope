all: test lint

build:
	@go build ./...

test:
	@go test ./...

lint:
	@golangci-lint -c .golangci.yml run