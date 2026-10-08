VENV := .venv
ACTIONLINT := .tools/bin/actionlint
YAML_FILES := .yamllint.yml .ansible-lint collections.yml inventories/production.example.yml playbooks roles .github/workflows
INVENTORY ?= inventories/production.yml
AUTOMATION_KEY ?= $(HOME)/.ssh/portfolio-server-infrastructure/ansible_ed25519
export INVENTORY AUTOMATION_KEY
export ANSIBLE_HOME := $(CURDIR)/.ansible
# Subprocesses must find the same pinned Ansible tools as the invoking interpreter.
export PATH := $(abspath $(VENV))/bin:$(PATH)

.PHONY: deps setup bootstrap-user verify-access docker-host verify-docker harden verify-hardening inspect-hardening reboot-host check ci lint-yaml lint-ansible syntax-check lint-workflows test-access

# Dependency setup uses registries; checks below use installed dependencies offline.
deps:
	@sh scripts/setup.sh deps

# Local setup prepares toolchain/dependencies and creates only missing inventory.
setup:
	@sh scripts/setup.sh setup

# LIVE / MUTATING: invoking this target consents to root-equivalent NOPASSWD sudo.
bootstrap-user:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py bootstrap-user --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / read-only verification: never runs the bootstrap role or asks for a password.
verify-access:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py verify-access --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / MUTATING: managed key-only access; no initial password transport.
docker-host:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py docker-host --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE verification: disposable smoke container; may populate the image cache.
verify-docker:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py verify-docker --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / MUTATING: firewall and validated SSH ports; preserve human recovery access.
harden:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py harden --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / read-only: aggregate all Stage 3 safety findings before harden.
inspect-hardening:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py inspect-hardening --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / read-only: independent key-only connections and hardening/runtime probes.
verify-hardening:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py verify-hardening --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / MUTATING: interactive confirmation after managed access preflight.
reboot-host:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py reboot-host --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# Strictly offline, including wrapper tests with temporary fixtures and mocked processes.
check: lint-yaml lint-ansible syntax-check lint-workflows test-access

ci: check

lint-yaml:
	@$(VENV)/bin/yamllint $(YAML_FILES)

lint-ansible:
	@ANSIBLE_INVENTORY="$(CURDIR)/inventories/production.example.yml" $(VENV)/bin/ansible-lint --offline playbooks roles

syntax-check:
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/bootstrap.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/verify.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/docker-host.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/verify-docker.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/harden.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/verify-hardening.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/reboot-host.yml

lint-workflows:
	@$(ACTIONLINT) -shellcheck="" .github/workflows/ci.yml

test-access:
	@$(VENV)/bin/python -m unittest discover -s tests -q
