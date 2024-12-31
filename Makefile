.PHONY: test lint coverage build clean fmt

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=jwt-vault-go

all: test build

build:
	$(GOBUILD) -v ./...

test:
	$(GOTEST) -v -race ./...

coverage:
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out

fmt:
	@go fmt ./...

lint: fmt
	golangci-lint run --fix

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.out

deps:
	$(GOMOD) download

tidy:
	$(GOMOD) tidy

verify: lint test
