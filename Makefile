TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=github.com
NAMESPACE=aliakseiyanchuk
BINARY=mashery-api-auth
VERSION=0.1

default: install

build:
	go build -o ${BINARY} cmd/main.go

release:
	GOOS=darwin GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_darwin_amd64 		cmd/main.go
	GOOS=freebsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_freebsd_386 			cmd/main.go
	GOOS=freebsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_freebsd_amd64		cmd/main.go
	GOOS=freebsd GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_freebsd_arm 			cmd/main.go
	GOOS=linux GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_linux_386 				cmd/main.go
	GOOS=linux GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_linux_amd64 			cmd/main.go
	GOOS=linux GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_linux_arm 				cmd/main.go
	GOOS=openbsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_openbsd_386 			cmd/main.go
	GOOS=openbsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_openbsd_amd64 		cmd/main.go
	GOOS=solaris GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_solaris_amd64 		cmd/main.go
	GOOS=windows GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_windows_386 			cmd/main.go
	GOOS=windows GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_windows_amd64 		cmd/main.go

install: build
	mkdir -p ./vault/plugins
	mv ${BINARY} ./vault/plugins

test:
	go test -i $(TEST) || exit 1
	echo $(TEST) | xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4

vendor:
	go vendor

#testacc:
#	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m