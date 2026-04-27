.PHONY: build run test clean docker-build docker-run deps generate

BINARY_NAME=shannon
BUILD_DIR=build
CMD_PATH=./cmd/server

deps:
	go mod tidy
	go mod download

build: deps
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)

run: deps
	CGO_ENABLED=1 go run $(CMD_PATH)/main.go

test:
	go test -v -race -coverprofile=coverage.out ./...

clean:
	rm -rf $(BUILD_DIR) coverage.out

docker-build:
	docker build -t shannon-pro-max .

docker-run:
	docker run -p 8080:8080 --env-file .env shannon-pro-max

generate:
	go generate ./...
