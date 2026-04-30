VENV := knowledge/.venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
TARGET := knowledge/target/mpe-knowledge-$(VERSION).jar

OLLAMA_HOST  ?= http://localhost:11434
OLLAMA_MODEL ?= nomic-embed-text:v1.5

.PHONY: knowledge-build knowledge-install knowledge-deploy knowledge-clean

$(VENV): knowledge/requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r knowledge/requirements.txt

knowledge-build: $(VENV)  ## Build the knowledge JAR
	mkdir -p knowledge/target
	@if ! curl -fsS $(OLLAMA_HOST)/api/version >/dev/null 2>&1; then \
	  echo ""; \
	  echo "ERROR: Ollama is not reachable at $(OLLAMA_HOST)"; \
	  echo "  Install: https://ollama.com/download"; \
	  echo "  Start:   ollama serve   (or run the desktop app)"; \
	  echo "  Override: OLLAMA_HOST=http://other:11434 make knowledge-build"; \
	  echo ""; \
	  exit 1; \
	fi
	@if ! curl -fsS $(OLLAMA_HOST)/api/show -d '{"name":"$(OLLAMA_MODEL)"}' >/dev/null 2>&1; then \
	  echo "Model $(OLLAMA_MODEL) not present locally, pulling..."; \
	  curl -fsS $(OLLAMA_HOST)/api/pull -d '{"name":"$(OLLAMA_MODEL)","stream":false}' | tail -1; \
	fi
	OLLAMA_HOST=$(OLLAMA_HOST) MPE_OLLAMA_MODEL=$(OLLAMA_MODEL) $(PYTHON) knowledge/build.py

knowledge-install: knowledge-build  ## Install JAR to ~/.m2 (for local iamlite dev)
	mvn install:install-file \
	  -Dfile=$(TARGET) \
	  -DgroupId=io.github.manetu \
	  -DartifactId=mpe-knowledge \
	  -Dversion=$(VERSION) \
	  -Dpackaging=jar

knowledge-deploy: knowledge-build  ## Deploy JAR to Clojars (CI only)
	mvn deploy:deploy-file \
	  -Dfile=$(TARGET) \
	  -DgroupId=io.github.manetu \
	  -DartifactId=mpe-knowledge \
	  -Dversion=$(VERSION) \
	  -Dpackaging=jar \
	  -DrepositoryId=clojars \
	  -Durl=https://repo.clojars.org/

knowledge-clean:
	rm -rf knowledge/target
