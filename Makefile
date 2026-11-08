# BountyTool build and install rules.
#
# `make`            release build
# `make install`    install into $(DESTDIR)$(PREFIX)  (PKGBUILD passes PREFIX=/usr)
# `make dist`       source tarball for the AUR
#
# Everything is driven by cargo; the Makefile only exists so packaging and
# `make install` work the same way on every machine.

CARGO      ?= cargo
INSTALL    ?= install
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
MANDIR     ?= $(PREFIX)/share/man/man1
DOCDIR     ?= $(PREFIX)/share/doc
LICENSEDIR ?= $(PREFIX)/share/licenses
DESTDIR    ?=

PKGNAME    := bountytool
VERSION    := $(shell sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n1)
BINARY     := target/release/$(PKGNAME)
DISTFILE   := $(PKGNAME)-$(VERSION).tar.gz

CARGO_FLAGS ?= --locked
export CARGO_TERM_COLOR ?= always

.PHONY: all build release debug run check test clippy fmt install uninstall \
        dist aur clean distclean help

all: build

## Build the optimised binary.
build: release

release:
	$(CARGO) build $(CARGO_FLAGS) --release

## Build without optimisations (faster compile, slower scans).
debug:
	$(CARGO) build $(CARGO_FLAGS)

## Build and run against the arguments in ARGS.
run:
	$(CARGO) run $(CARGO_FLAGS) --release -- $(ARGS)

## Type-check everything, including tests and benches.
check:
	$(CARGO) check $(CARGO_FLAGS) --all-targets

## Run the test suite.
test:
	$(CARGO) test $(CARGO_FLAGS)

## Lint with clippy, warnings are errors.
clippy:
	$(CARGO) clippy $(CARGO_FLAGS) --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

## Install the binary, man page and documentation.
install: release
	$(INSTALL) -Dm755 $(BINARY) $(DESTDIR)$(BINDIR)/$(PKGNAME)
	$(INSTALL) -Dm644 docs/$(PKGNAME).1 $(DESTDIR)$(MANDIR)/$(PKGNAME).1
	$(INSTALL) -Dm644 README.md $(DESTDIR)$(DOCDIR)/$(PKGNAME)/README.md
	$(INSTALL) -Dm644 config/default.toml $(DESTDIR)$(DOCDIR)/$(PKGNAME)/config.toml
	$(INSTALL) -Dm644 scope.example.toml $(DESTDIR)$(DOCDIR)/$(PKGNAME)/scope.example.toml
	$(INSTALL) -Dm644 LICENSE $(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(PKGNAME)
	rm -f $(DESTDIR)$(MANDIR)/$(PKGNAME).1
	rm -rf $(DESTDIR)$(DOCDIR)/$(PKGNAME)
	rm -rf $(DESTDIR)$(LICENSEDIR)/$(PKGNAME)

## Compressed source tarball, excluding build output and VCS metadata.
## The archive is written outside the tree first: creating it in place would
## change the directory mtime that tar has already read.
dist:
	rm -f $(DISTFILE)
	@tmp=$$(mktemp -d); \
	if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
		git archive --format=tar --prefix=$(PKGNAME)-$(VERSION)/ HEAD \
			| gzip -9 > "$$tmp/$(DISTFILE)"; \
	else \
		echo "not a git repository: packaging the working tree instead"; \
		tar --exclude=./target --exclude=./pkg --exclude=./.git \
		    --exclude=./sessions --exclude=./scratch \
		    --exclude=./scope.toml --exclude=./.env --exclude=./.env.* \
		    --exclude=./src/pkg --exclude=./src/bountytool-* \
		    --transform "s,^\.,$(PKGNAME)-$(VERSION)," \
		    -czf "$$tmp/$(DISTFILE)" .; \
	fi; \
	mv "$$tmp/$(DISTFILE)" $(DISTFILE); \
	rmdir "$$tmp"; \
	echo "wrote $(DISTFILE)"

## Regenerate .SRCINFO for the AUR.
aur:
	makepkg --printsrcinfo > .SRCINFO
	@echo "wrote .SRCINFO"

clean:
	$(CARGO) clean

distclean: clean
	rm -f $(DISTFILE) .SRCINFO

help:
	@echo "targets: build debug run check test clippy fmt install uninstall dist aur clean"
	@echo "  PREFIX=$(PREFIX)  DESTDIR=$(DESTDIR)  VERSION=$(VERSION)"
