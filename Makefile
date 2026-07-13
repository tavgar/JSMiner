BINARY := jsminer
DIST := dist

.PHONY: build test vet bundle clean

# Build the jsminer binary in the repo root.
build:
	go build -o $(BINARY) ./cmd/jsminer

test:
	go test ./...

vet:
	go vet ./...

# Produce a self-contained bundle in $(DIST): the jsminer binary plus a Chromium
# under $(DIST)/chromium, so the directory can be archived and shipped as one
# artifact that renders out of the box, with no separate browser install and no
# runtime download. The bundled Chromium is the current latest stable
# Chrome-for-Testing build. Requires network access at build time.
bundle:
	mkdir -p $(DIST)
	go build -o $(DIST)/$(BINARY) ./cmd/jsminer
	$(DIST)/$(BINARY) -download-browser -browser-dest $(DIST)
	@echo "Bundle ready in $(DIST)/ (binary + chromium/)."

clean:
	rm -rf $(BINARY) $(DIST)
