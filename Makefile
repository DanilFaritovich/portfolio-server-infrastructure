VENV := .venv
ACTIONLINT := .tools/bin/actionlint
YAML_FILES := .yamllint.yml .ansible-lint requirements.yml inventories/production.example.yml playbooks roles .github/workflows
export ANSIBLE_HOME := $(CURDIR)/.ansible

.PHONY: deps check ci lint-yaml lint-ansible syntax-check lint-workflows

# Dependency setup uses registries; checks below use installed dependencies offline.
deps:
	@python3.12 -m venv $(VENV)
	@$(VENV)/bin/python -m pip install -r requirements-dev.txt
	@$(VENV)/bin/ansible-galaxy collection install -r requirements.yml -p .ansible/collections
	@sh scripts/install-actionlint.sh

check: lint-yaml lint-ansible syntax-check lint-workflows

ci: check

lint-yaml:
	@$(VENV)/bin/yamllint $(YAML_FILES)

lint-ansible:
	@ANSIBLE_INVENTORY="$(CURDIR)/inventories/production.example.yml" $(VENV)/bin/ansible-lint --offline playbooks/bootstrap.yml roles/bootstrap_user

syntax-check:
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/bootstrap.yml

lint-workflows:
	@$(ACTIONLINT) -shellcheck="" .github/workflows/ci.yml
