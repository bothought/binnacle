.PHONY: build test race vet fmt demo check clean

build:
	go build -trimpath -o binnacle ./cmd/binnacle

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

demo:
	go run ./cmd/binnacle serve --demo

check:
	go run ./cmd/binnacle check --config config.example.yaml

clean:
	rm -f binnacle
	rm -rf dist
