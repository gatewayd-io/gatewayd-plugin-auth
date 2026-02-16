tidy:
	@go mod tidy

build: tidy
	@go build -ldflags "-s -w"

build-dev: tidy
	@CGO_ENABLED=0 go build

checksum:
	@sha256sum -b gatewayd-plugin-auth

update-all:
	@go get -u ./...

# https://groups.google.com/g/golang-nuts/c/FrWNhWsLDVY/m/CVd_iRedBwAJ
update-direct-deps:
	@go list -f '{{if not (or .Main .Indirect)}}{{.Path}}{{end}}' -m all | xargs -n1 go get
	@go mod tidy

test:
	@go test -v -race ./...

test-cover:
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

lint:
	@golangci-lint run

.PHONY: tidy build build-dev checksum update-all test test-cover lint
