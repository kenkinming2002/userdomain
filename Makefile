PREFIX?=/usr/local
TARGET?=release

.PHONY: all
all:
	cargo build --profile $(TARGET)

.PHONY: install
install:
	install -D -m755 ./target/$(TARGET)/userdomain-daemon    "$(PREFIX)/bin/userdomain-daemon"
	install -D -m755 ./target/$(TARGET)/userdomain           "$(PREFIX)/bin/userdomain"
	install -D -m755 ./target/$(TARGET)/libnss_userdomain.so "$(PREFIX)/lib/libnss_userdomain.so.2"
