BIN := sinty-firewalld
PREFIX ?= /usr

.PHONY: all build release test vet install clean

all: build

build:
	CGO_ENABLED=1 go build -o $(BIN) ./cmd/sinty-firewalld

release:
	CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/sinty-firewalld

test:
	go test ./...

vet:
	go vet ./...

install: release
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/libexec/$(BIN)
	install -Dm644 packaging/sinty-firewalld.service $(DESTDIR)$(PREFIX)/lib/systemd/system/sinty-firewalld.service
	install -Dm644 packaging/sinty-firewalld.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/sinty-firewalld.conf
	install -Dm644 packaging/dev.sinty.Firewall1.service $(DESTDIR)$(PREFIX)/share/dbus-1/system-services/dev.sinty.Firewall1.service

clean:
	rm -f $(BIN)
