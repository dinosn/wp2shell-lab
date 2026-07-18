# wp2shell lab — one-command vulnerable/patched validation + RCE.
WP_PORT        ?= 8093
WP_VULN_TAG    ?= 6.9.4
WP_PATCHED_TAG ?= 7.0.2
BASE            = http://localhost:$(WP_PORT)
export WP_PORT

.PHONY: help up patched install check proof exploit down clean

help:
	@echo "make up        # start vulnerable WordPress 6.9.4 + install"
	@echo "make check     # run the non-destructive detector against the lab"
	@echo "make proof     # detector + read-only evidence (@@version, current_user)"
	@echo "make exploit   # full pre-auth RCE: create admin, deploy webshell, run id"
	@echo "make patched   # restart on WordPress 7.0.2 and re-check (expect: not vulnerable)"
	@echo "make down      # stop and remove the lab (with volumes)"

up:
	WP_TAG=$(WP_VULN_TAG) docker compose up -d
	./scripts/install-wp.sh
	@echo "lab up (vulnerable $(WP_VULN_TAG)): $(BASE)"

install:
	./scripts/install-wp.sh

check:
	python3 wp2shell_check.py $(BASE)

proof:
	python3 wp2shell_check.py $(BASE) --proof

exploit:
	python3 wp2shell_check.py $(BASE) -c "id; uname -a"

patched:
	@docker manifest inspect wordpress:$(WP_PATCHED_TAG) >/dev/null 2>&1 || { \
	  echo "wordpress:$(WP_PATCHED_TAG) is not on Docker Hub yet (official images lag core"; \
	  echo "security releases by a day or two). Retry later, or override with a published"; \
	  echo "fixed tag once available:  make patched WP_PATCHED_TAG=6.9.5"; exit 1; }
	docker compose down -v --remove-orphans
	WP_TAG=$(WP_PATCHED_TAG) docker compose up -d
	./scripts/install-wp.sh
	python3 wp2shell_check.py $(BASE)

down clean:
	docker compose down -v --remove-orphans
