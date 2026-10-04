VENV := .venv
ACTIONLINT := .tools/bin/actionlint
YAML_FILES := .yamllint.yml .ansible-lint requirements.yml inventories/production.example.yml playbooks roles .github/workflows
INVENTORY ?= inventories/production.yml
AUTOMATION_KEY ?= $(HOME)/.ssh/portfolio-server-infrastructure/ansible_ed25519
export INVENTORY AUTOMATION_KEY
export ANSIBLE_HOME := $(CURDIR)/.ansible

.PHONY: deps setup bootstrap verify check ci lint-yaml lint-ansible syntax-check lint-workflows test-access

# Dependency setup uses registries; checks below use installed dependencies offline.
deps:
	@sh scripts/setup.sh deps

# Local setup prepares toolchain/dependencies and creates only missing inventory.
setup:
	@sh scripts/setup.sh setup

# LIVE / MUTATING: invoking this target consents to root-equivalent NOPASSWD sudo.
bootstrap:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py bootstrap --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / read-only verification: never runs the bootstrap role or asks for a password.
verify:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py verify --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# Strictly offline, including wrapper tests with temporary fixtures and mocked processes.
check: lint-yaml lint-ansible syntax-check lint-workflows test-access

ci: check

lint-yaml:
	@$(VENV)/bin/yamllint $(YAML_FILES)

lint-ansible:
	@ANSIBLE_INVENTORY="$(CURDIR)/inventories/production.example.yml" $(VENV)/bin/ansible-lint --offline playbooks roles/bootstrap_user

syntax-check:
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/bootstrap.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/verify.yml

lint-workflows:
	@$(ACTIONLINT) -shellcheck="" .github/workflows/ci.yml

test-access:
	@$(VENV)/bin/python -m unittest discover -s tests -q
