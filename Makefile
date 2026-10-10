VENV := .venv
ACTIONLINT := .tools/bin/actionlint
YAML_FILES := .yamllint.yml .ansible-lint collections.yml inventories/production.example.yml playbooks roles .github/workflows
INVENTORY ?= inventories/production.yml
# Optional legacy override; explicit inventory supplies the managed key path.
AUTOMATION_KEY ?=
AGENT_LOAD ?= ask
export INVENTORY AUTOMATION_KEY
export ANSIBLE_HOME := $(CURDIR)/.ansible
# Subprocesses must find the same pinned Ansible tools as the invoking interpreter.
export PATH := $(abspath $(VENV))/bin:$(PATH)

.PHONY: list-users show-user list-user-keys add-user-key revoke-user-key remove-user generate-user-key load-user-key show-public-key copy-public-key show-controller connect-controller connect-user deps setup bootstrap-user verify-access docker-host verify-docker harden verify-hardening inspect-hardening reboot-host add-user verify-user secure-ssh verify-ssh-security inspect-operations setup-operations verify-operations check ci lint-yaml lint-ansible syntax-check lint-workflows test-access
.PHONY: show-server-trust copy-server-trust trust-server

# Human account inputs are supplied by the caller; USER is intentionally untouched.
export AGENT_LOAD KEY_FINGERPRINT RECOVERY_USER RECOVERY_KEY KEY_NAME HUMAN_USER HUMAN_GROUPS HUMAN_SUDO HUMAN_SUDO_COMMANDS HUMAN_KEY HUMAN_PUBLIC_KEY

# Dependency setup uses registries; checks below use installed dependencies offline.
deps:
	@sh scripts/setup.sh deps

# Local setup prepares toolchain/dependencies and creates only missing inventory.
setup:
	@sh scripts/setup.sh setup

# LOCAL only: generate/load the selected key or display its public member/fingerprint.
generate-user-key load-user-key show-public-key copy-public-key:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py $@

# LOCAL trust transfer; copying may offer clipboard package installation.
show-server-trust copy-server-trust trust-server:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py $@ --inventory "$$INVENTORY"

show-controller:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py $@ --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE interactive SSH; controller may offer verified cross-port local trust.
connect-controller connect-user:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py $@ --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

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

# LIVE user/key management: mutations require explicit interactive confirmation.
list-users show-user list-user-keys add-user-key revoke-user-key remove-user:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py $@ --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / MUTATING: add a human account using explicitly supplied HUMAN_* inputs.
add-user:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py add-user --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE verification: verify the human account using explicitly supplied HUMAN_* inputs.
verify-user:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py verify-user --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / MUTATING: secure SSH using explicitly supplied HUMAN_* inputs.
secure-ssh:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py secure-ssh --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE verification: verify SSH security using explicitly supplied HUMAN_* inputs.
verify-ssh-security:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py verify-ssh-security --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE: preview is check/diff only; apply changes only the guarded APT file.
.PHONY: preview-apt-policy apply-apt-policy
preview-apt-policy apply-apt-policy:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py $@ --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / read-only: inspect Stage 5 operations readiness.
inspect-operations:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py inspect-operations --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / MUTATING: configure bounded system operations policy.
setup-operations:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py setup-operations --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# LIVE / read-only: verify Stage 5 operations policy and services.
verify-operations:
	@test -x $(VENV)/bin/python || { echo "Run make setup first." >&2; exit 1; }
	@$(VENV)/bin/python scripts/access.py verify-operations --inventory "$$INVENTORY" --key "$$AUTOMATION_KEY"

# Strictly offline, including wrapper tests with temporary fixtures and mocked processes.
check: lint-yaml lint-ansible syntax-check lint-workflows test-access

ci: check

lint-yaml:
	@$(VENV)/bin/yamllint $(YAML_FILES)

lint-ansible:
	@ANSIBLE_INVENTORY="$(CURDIR)/inventories/production.example.yml" $(VENV)/bin/ansible-lint --offline playbooks roles

syntax-check:
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/apt-policy.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/bootstrap.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/verify.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/docker-host.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/verify-docker.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/harden.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/verify-hardening.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/reboot-host.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/add-user.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/verify-user.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/secure-ssh.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/verify-ssh-security.yml
	@$(VENV)/bin/ansible-playbook --syntax-check -i inventories/production.example.yml playbooks/setup-operations.yml

lint-workflows:
	@$(ACTIONLINT) -shellcheck="" .github/workflows/ci.yml

test-access:
	@$(VENV)/bin/python -m unittest discover -s tests -q
