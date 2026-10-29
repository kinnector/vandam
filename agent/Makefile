# Makefile for vandam EDR daemon
# The operator CLI (vandam) now lives in its own repo; build/install it separately.

PREFIX ?= /usr/local
SBINDIR = $(PREFIX)/sbin
BINDIR = $(PREFIX)/bin
CONFDIR = /etc/kinnector
VARDIR = /var/quarantine/kinnector
RUNDIR = /var/run/kinnector

DAEMON_BIN = target/x86_64-unknown-linux-gnu/release/vandam

.PHONY: all build install uninstall clean

all: build

build:
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-static-pie" cargo build --target x86_64-unknown-linux-gnu --release

install: build
	# Create required system directories
	install -d $(DESTDIR)$(SBINDIR)
	install -d $(DESTDIR)$(CONFDIR)
	install -d $(DESTDIR)$(VARDIR)
	install -d $(DESTDIR)$(RUNDIR)

	# Install binary
	install -m 0755 $(DAEMON_BIN) $(DESTDIR)$(SBINDIR)/vandam

	# Install default configuration if not already present
	if [ ! -f $(DESTDIR)$(CONFDIR)/core.conf ]; then \
		install -m 0640 core.conf.template $(DESTDIR)$(CONFDIR)/core.conf; \
	fi

	# Set quarantine directory permissions
	chmod 0750 $(DESTDIR)$(VARDIR)

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/vandam
	@echo "Binary removed. Configuration in $(CONFDIR) and quarantine in $(VARDIR) have been preserved."

clean:
	cargo clean
