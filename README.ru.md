# portfolio-server-infrastructure

[English](README.md)

Provisioning VPS на Ubuntu через Ansible. Pipeline:

```text
local setup -> bootstrap managed ansible user -> verify access
-> provision Docker host -> verify Docker
-> firewall + validated SSH host ports -> verify hardening -> STOP
```

Docker Engine, Compose и Buildx готовят хост к будущим workloads. Caddy,
application networks/Compose files, Vue, domains/TLS, GHCR authentication,
deployment/CD, human/admin access и окончательная root/password-login policy, fail2ban и
automatic upgrades остаются отдельными следующими этапами.

## Quick Start

Нужен Linux-контроллер x86_64 или arm64 (glibc, например Ubuntu) с Make,
POSIX shell, curl, tar/gzip, coreutils (включая sha256sum) и OpenSSH clients
(`ssh`, `ssh-keygen`, `ssh-keyscan`, `scp`, `sftp`). **Предварительно устанавливать Python 3.12
и uv не нужно.** Paramiko автоматически устанавливается в project-local
`.venv`; sshpass не требуется. Setup не требует sudo и не устанавливает системные пакеты.
На VPS уже должны работать root SSH password login и быть доступны
`/usr/bin/python3`, `/bin/bash`, sudo, `/usr/sbin/visudo` и включение `/etc/sudoers.d`.

```bash
git clone https://github.com/DanilFaritovich/portfolio-server-infrastructure.git
cd portfolio-server-infrastructure
make setup

# Измените inventories/production.yml: ansible_host и ansible_port.
# Подготовьте fingerprint провайдера и доступ к recovery console.
make bootstrap-user
# Для нового хоста сначала подтвердите fingerprint; затем Ansible запросит root password.
make verify-access
make docker-host
make verify-docker
# Проверьте hardening settings, recovery console и сетевые правила провайдера ниже.
make harden
make verify-hardening
```

`make setup` проверяет минимальные system tools, устанавливает pinned uv
**0.12.23** с проверкой checksum в `.tools/bin/uv`, скачивает managed Python
**3.12** в `.tools/python`, создаёт `.venv` из этого managed interpreter,
устанавливает pinned dependencies (включая **Paramiko 5.0.0**)/Ansible collections и actionlint, затем
копирует example inventory **только если production.yml ещё не существует**. Существующий inventory
setup не читает и не перезаписывает. `make deps` использует тот же toolchain/dependency mechanism без
создания inventory. Повторный setup переиспользует pinned uv, совместимые managed
Python и `.venv`; он не уничтожает их и не переустанавливает Python без причины.
Установка пакетов согласует pinned requirements, существующие collections и
совместимый actionlint переиспользуются. Setup требует сеть для dependency
sources, но никогда не подключается к VPS. В стандартном сценарии измените только hostname/address
и текущий SSH-порт; `ansible_user` по умолчанию — `root`. Сохраните структуру
`bootstrap` с одним хостом; не записывайте пароли или содержимое ключей в inventory.

Версии collections закреплены в `collections.yml`; setup/deps устанавливают их явно.
Это имя исключает автоматическое обнаружение requirements в ansible-lint;
`make check` сохраняет `--offline` и сообщает об отсутствующих collections. Make
ставит проектный `.venv/bin` первым в PATH, чтобы Ansible subprocesses использовали тот же toolchain.

**First-use trust выполняется внутри `make bootstrap-user`.** Сохраните доступ к
recovery console и рабочую административную сессию. Если запись уже есть в
`~/.ssh/known_hosts`, bootstrap использует её без повторного сканирования или
замены. Изменённый ключ по-прежнему приводит к отказу при строгой проверке.

Для нового хоста bootstrap получает public host keys через OpenSSH `ssh-keyscan`
и показывает hostname/IP, port, выбранный тип ключа и SHA256 fingerprint,
вычисленный `ssh-keygen`. Выбирается один ключ: сначала Ed25519, затем ECDSA,
затем RSA. Это **первый trust**: ответ из сети сам по себе не подтверждает
подлинность сервера. Сравните fingerprint с панелью или консолью VPS-провайдера
перед ответом на `Trust this host? [y/N]`. Только `y` или `yes` сохраняет показанный
ключ в ваш `~/.ssh/known_hosts`; другой ввод или EOF останавливает bootstrap
до генерации automation key, запроса пароля и изменения конфигурации VPS.
Заранее запускать отдельный `ssh` только ради `known_hosts` больше не нужно.

Для нестандартного порта используется запись `[host]:port`. Ошибки получения
ключа/fingerprint и отсутствие интерактивного TTY останавливают first trust.
`make verify-access` не предлагает first trust и не получает новые ключи; для нового
хоста сначала выполните bootstrap. Строгая проверка host key остаётся включённой
для Paramiko bootstrap и OpenSSH verification; silent trust отсутствует.
См. [OpenSSH ssh-keyscan](https://man.openbsd.org/ssh-keyscan)
и [ssh-keygen](https://man.openbsd.org/ssh-keygen).
Заранее подтвердите VPS prerequisites и включение sudoers.d. Не выбирайте чужую
существующую учётную запись как управляемого пользователя `ansible`.

## Доступ и безопасность

Стандартный путь: **root + интерактивный SSH password → ansible + dedicated
SSH key + NOPASSWD sudo**. Root используется только для initial bootstrap.
Дальнейшее provisioning должно использовать `ansible`; `make verify-access` явно
переопределяет начальный login из inventory на `ansible` и не использует root password.

`make bootstrap-user` локально создаёт Ed25519 key, если оба файла пары отсутствуют,
непосредственно перед bootstrap. `make setup` не генерирует SSH keys:

```text
~/.ssh/portfolio-server-infrastructure/ansible_ed25519
~/.ssh/portfolio-server-infrastructure/ansible_ed25519.pub
```

Директория защищена правами `0700`, private key — `0600` или строже.
Существующие ключи никогда не перезаписываются. Неполная пара, symlinks,
небезопасные права или путь ключа внутри репозитория приводят к ошибке.
Wrapper проверяет только metadata private key; private key остаётся на
контроллере и используется только его SSH-клиентом. Bootstrap role получает
только путь public key, читает публичный ключ локально и добавляет его в
`/home/ansible/.ssh/authorized_keys`, сохраняя посторонние authorized keys.
Не добавляйте SSH keys, реальные inventories, credentials и логи в Git.

Проверка и чтение public key выполняются в явно локальном controller block
через Python самого playbook, без sudo. Host/port берутся из local inventory.
Runtime connection overrides действуют только для VPS alias во временном
inventory overlay (0600, удаляется после завершения Ansible), а не в глобальных
connection extra-vars; delegated localhost сохраняет локальный context.
В `-e` остаются только role inputs. Overlay не содержит паролей или содержимого ключей.

Generated keys создаются **без passphrase** для unattended provisioning.
Обладание этим private automation key вместе с неограниченным `NOPASSWD: ALL`
фактически даёт **root-equivalent access к VPS**. Защитите контроллер и резервные
копии ключа. Запуск `make bootstrap-user` явно разрешает эту policy; default consent
роли остаётся `false`. Отдельный `/etc/sudoers.d/ansible` принадлежит root,
имеет `0440` и проверяется через `visudo -cf`. Login password для `ansible` не задаётся.

Initial root connection использует локальный адаптер `portfolio_password` поверх
`ansible.builtin.paramiko_ssh` из pinned
Ansible Core **2.18.6** с project-local Paramiko **5.0.0**. Штатный Ansible
`--ask-pass` интерактивно запрашивает пароль и держит его в памяти процесса;
wrapper не читает и не сохраняет пароль. Он не передаётся через command arguments,
environment variables или файлы и не сохраняется в inventory, `.env`,
конфигурации или shell history. Используйте обычный интерактивный терминал;
не записывайте секретный ввод и не передавайте пароль shell-командами.

Адаптер переиспользует встроенную SSH-реализацию и задаёт `look_for_keys=False`,
`host_key_auto_add=False` и `record_host_keys=False` через plugin API
`set_options(direct=...)`. В Core 2.18.6 первые две опции не имеют variable bindings;
их environment/INI bindings также задают deprecated globals. Эти environment
settings удаляются из дочерних процессов; deprecation warnings остаются включены.

Initial bootstrap отключает SSH agent authentication и поиск private keys,
проверяет подтверждённую запись `known_hosts`; автоматическое добавление host keys
отключено. Автоматическая handoff verification и `make verify-access` используют
**OpenSSH + dedicated private key + public-key-only authentication**, с отключёнными
password prompts и agent. Paramiko используется только для initial password bootstrap.
См. [документацию pinned Ansible Paramiko transport](https://docs.ansible.com/projects/ansible-core/2.18/collections/ansible/builtin/paramiko_ssh_connection.html).
В новых версиях Ansible plugin deprecated и запланирован к удалению в 2.21;
перед обновлением Ansible до этой версии нужно пересмотреть initial password transport.

## Команды и границы

| Target | Назначение | Доступ к хосту |
| --- | --- | --- |
| `make setup` | Установить local dependencies; создать отсутствующий inventory | Только dependency registries |
| `make deps` | Установить pinned local tooling/collections | Только dependency registries |
| `make bootstrap-user` | Создать/использовать dedicated key, bootstrap account, проверить доступ | **LIVE / MUTATING** |
| `make verify-access` | Проверить существующий key-only доступ ansible | **LIVE / verification**, без изменений managed configuration |
| `make docker-host` | Установить Docker, logging policy и настроить services | **LIVE / MUTATING**, managed key-only access |
| `make verify-docker` | Проверить Docker/services и disposable container | **LIVE / verification**, временные container/image-cache changes |
| `make harden` | Настроить UFW и validated SSH listening ports | **LIVE / MUTATING**, managed key-only access |
| `make verify-hardening` | Проверить все SSH-порты, UFW и active Docker/containerd | **LIVE / verification**, без изменения managed state |
| `make check` | YAML/Ansible lint, syntax, actionlint, wrapper tests | **OFFLINE** |
| `make ci` | Те же offline checks, что у `make check` | **OFFLINE** |

Bootstrap проверяет prerequisites, local inventory, host/port и запись known_hosts
с явным подтверждением first-use trust до генерации ключа и запроса начального пароля. Затем запускает существующую роль
с explicit sudo consent и открывает независимые key-only SSH connections как
`ansible`. Verification проверяет Ansible ping, `id -un == ansible` и
`sudo -n id -u == 0`; ошибка любой стадии завершает workflow с ошибкой.
Повторное использование начального SSH-соединения отключено. Docker provisioning запускается отдельным явным target; access verification его не выполняет.

`make verify-access` использует тот же verification playbook без bootstrap role и
генерации ключа. Password authentication и prompts отключены. Назначение —
read-only: Ansible может создавать и удалять временные module files, но
не меняет account или host configuration. При ошибке сохраните резервный доступ.
Успешного bootstrap recap недостаточно для подтверждения handoff.

Docker regression tests проверяют managed key-only orchestration, isolation
connection overlay, остановку при preflight failure, отклонение example inventory,
Make/CI offline boundaries, unchanged probes и smoke cleanup. Выбранные safety
assertions и convergence daemon policy выполняются реальным Ansible на временных
local fixtures с заблокированной сетью. Syntax-check покрывает все шесть
playbooks; lint проверяет все три роли.

Checks всегда используют `inventories/production.example.yml`, никогда —
production inventory, ключи, пароли или соединения с VPS. Wrapper tests используют
временные синтетические fixtures и mocked processes, включая генерацию ключей.
Access tests также проверяют bootstrap без sshpass, Paramiko password transport,
OpenSSH key-only verification, отсутствие credentials в arguments/environment,
генерацию ключа только при bootstrap и pinned plugin с mock SSH client
(включая отказ при изменённом host key). First-trust tests проверяют существующий/новый
trust, подтверждение, отказ/EOF, ошибки получения ключа/fingerprint, нестандартный
порт, отсутствие TTY и verification без first trust через mock retrieval
и offline OpenSSH с синтетическими public keys. Setup tests запускают shell scripts с изолированным PATH без system Python/uv
и fake downloads: проверяют fresh/repeated setup, сохранение inventory, reuse,
arm64, ошибки prerequisites и checksum/version.
GitHub Actions скачивает зависимости и запускает только `make ci`, без production
credentials. Offline success не доказывает live access или runtime idempotency.
Controller-key regression test запускает реальный локальный preflight роли
с синтетическим remote host/Paramiko context и заблокированными network connections;
проверяет локальный `.pub` и отклоняет отсутствующий файл и symlinks.
Безопасный автоматический formatter (`make fix`) не настроен. Для диагностики:
`make lint-yaml`, `make lint-ansible`, `make syntax-check`, `make lint-workflows`,
`make test-access`. Required branch-protection check `offline-validation`
настраивается отдельно.

## Docker host stage

`make docker-host` использует существующий access wrapper, dedicated key и
строгий trust из `known_hosts`. Он не генерирует ключи и не принимает новый host
trust. До любых Docker mutation выполняется `playbooks/verify.yml`: login должен
быть `ansible`, а `sudo -n` — возвращать UID 0. Если ключа нет, сообщение предлагает
`make bootstrap-user`; ошибка login/sudo останавливает stage. Docker tasks
используют privilege escalation только там, где требуется, с non-interactive
sudo. Пользователь `ansible` не добавляется в группу `docker`. Initial administrator
из inventory переопределяется только для managed host; controller-local context
сохраняется.

`playbooks/docker-host.yml` вызывает `roles/docker_host`. Для non-mutating package
inspection в remote Python из inventory должен быть доступен Ubuntu `python3-apt`;
если его нет, preflight завершится до изменений. Подготовьте его через существующий
административный доступ до этого stage. Поддерживаются Ubuntu
Jammy 22.04, Noble 24.04 и Resolute 26.04 с systemd; architecture mapping включает
amd64, arm64, armhf, ppc64el и s390x. Смотрите defaults роли и
[официальную инструкцию Docker для Ubuntu](https://docs.docker.com/engine/install/ubuntu/).
Роль настраивает официальный stable APT repository с отдельным ASCII signing
keyring, закреплённым SHA256 key checksum и release/architecture текущего хоста.
Ротация vendor signing key требует явного review checksum. Устанавливаются
`docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin` и
`docker-compose-plugin` с `state: present`; повторный запуск не обновляет уже
установленные пакеты. APT metadata обновляется только при отсутствии необходимых
пакетов или изменении managed repository/key, чтобы converged rerun давал `changed=0`.

Все safety inspections завершаются до изменений packages/repository/configuration.
Конфликтующие `docker.io`, `docker-compose`, `docker-compose-v2`, `docker-doc`,
`docker-buildx`, `podman-docker`, `containerd` или `runc` останавливают provisioning.
Автоматических uninstall, purge и удаления runtime data нет. Существующий Docker
APT source должен точно совпадать с managed source; конкурирующие sources,
custom Docker/containerd systemd units/drop-ins, неожиданное содержимое keyring
и orphan runtime data требуют manual review. Существующий `daemon.json` должен
содержать ровно managed policy; некорректные или другие настройки останавливают
роль с предложением выполнить migration вручную. Перед повтором осознанно
проверьте workloads/configuration и выполните migration. Роль не принимает
произвольную существующую runtime installation автоматически.

Роль включает и запускает `docker.service` и `containerd.service`. Минимальный
`/etc/docker/daemon.json` использует Docker-supported `local` logging driver с
`max-size: 20m` и `max-file: "5"` (пять rotated files на контейнер).
Перед заменой конфигурация проверяется через `dockerd --validate`; restart handler
вызывается только при изменении config. Policy ограничивает логи **новых
контейнеров**; существующие сохраняют logging settings времени создания.
Смотрите [Docker local logging](https://docs.docker.com/engine/logging/drivers/local/).
Application networks и deployment configuration не создаются.

`make verify-docker` сначала повторяет key-only access/sudo verification, затем
выполняет `docker version`, `docker info`, `docker compose version`,
`docker buildx version`, проверяет active/enabled для обоих services и активный
logging driver `local`. Эти probes дают `changed=0`. Smoke test создаёт контейнер
`hello-world:latest` с `--network none`, запускает/ожидает его с timeout 120 секунд,
затем удаляет точный container ID в `always` cleanup, включая ошибку запуска.
Runtime operations корректно сообщают changes. Smoke test может скачать image
из Docker Hub и оставить его в Docker image cache; verification **не является
строго read-only**. После cleanup запущенный test container не остаётся.
Cache pruning, удаляющего посторонние operator data, нет.

Ручная проверка после уже выполненного bootstrap managed access:

```bash
make setup
make check
make verify-access
make docker-host
make verify-docker
make docker-host
make verify-docker
```

Второй `make docker-host` должен дать `changed=0`, если внешнее состояние не
изменилось. Live access, installation, runtime behavior и полная host idempotency
проверяются вручную; агент эти команды против VPS не запускал.

## Host hardening (Stage 3)

Stage 3 начинается с проверенного Docker-ready host. Human/admin users и personal
keys не создаются; `PermitRootLogin`, `PasswordAuthentication` и
`KbdInteractiveAuthentication` сохраняются. Окончательная access policy — Stage 4.
Перед `make harden` сохраните рабочую human/recovery SSH-сессию и убедитесь в
доступности provider console. Внешние security groups должны разрешать каждый
нужный SSH-порт; Ansible не управляет сетевыми правилами провайдера.

Добавьте настройки под существующим host в локальном inventory. Setup сохраняет
имеющийся inventory, поэтому новые поля при необходимости добавьте вручную:

```yaml
ansible_port: 22
ssh_listen_ports: [22, 2222]
firewall_allowed_tcp_ports: [80, 443]
```

Фиксированного SSH-порта в роли нет: без `ssh_listen_ports` используется текущий
`ansible_port`. Web ports по умолчанию — 80 и 443; Caddy не устанавливается.
Списки поддерживают несколько уникальных целых чисел 1–65535; additional TCP
list может быть пустым. Первый переход обязан сохранить текущий проверенный
`ansible_port`: переход 22 → 2222 начинается с `[22, 2222]`. Если доступ уже работает
на 2222, допустимо `[2222]`. Не удаляйте последний human/recovery route до Stage 4.
Последующая смена inventory port требует отдельно проверенного доверия
`known_hosts` для этого порта: Stage 3 не сохраняет новое доверие и не редактирует
inventory. Исключение существующих UFW rules из desired lists вызывает safety
stop и требует осознанной ручной миграции.

`playbooks/harden.yml` вызывает `roles/host_hardening`. До изменений проверяются:
неоднозначные activation modes, custom SSH/UFW service/socket units и нестандартные
systemd drop-ins, unmanaged `Port`/`ListenAddress`, нестандартные SSH Include
hierarchies, занятые SSH-порты, неактивные Docker/containerd и неоднозначный UFW
state останавливают роль. Поддерживается обычный `/etc/ssh/sshd_config` со
стандартным include `/etc/ssh/sshd_config.d/*.conf` и управляемыми ролью listening
directives. Поддерживаются штатный Ubuntu active/enabled `ssh.socket` и обычный
listener mode `ssh.service`; переключения activation mode нет. Штатный socket
dependency drop-in принимается только с точными директивами `After=ssh.socket`
и `Requires=ssh.socket`; socket address drop-ins должны быть созданы runtime
generator Ubuntu. Custom overrides отклоняются. Все текущие socket listening
ports должны оставаться в `ssh_listen_ports`.
Generated `ListenStream` и systemd `Listen` сравниваются как множества TCP
listeners: address family, wildcard bind и port. Принимается штатная пара
Ubuntu `0.0.0.0:<port>` / `[::]:<port>`. Доступность IPv4 через IPv6 wildcard
определяется `BindIPv6Only`, а при `default` — `/proc/sys/net/ipv6/bindv6only`;
реальное несовпадение address families отклоняется. См.
[systemd socket binding semantics](https://www.freedesktop.org/software/systemd/man/systemd.socket.html#BindIPv6Only=).
Preflight допускает listener только на текущем inventory SSH port, даже если
desired list содержит будущие ports. Текущий порт должен оставаться live и
входить в desired list.

Отсутствующий UFW устанавливается с `state: present`. При первом adoption
существующий UFW должен быть inactive, без user rules, с package-original base
configuration. Fingerprints сохраняются в `/etc/ufw/portfolio-hardening.json`;
повторный запуск отклоняет посторонние изменения base/raw rules и unknown rules.
Reset, удаление правил и замена unmanaged configuration не выполняются.
После прерванного firewall mutation ownership snapshot может устареть: изучите
реальное состояние и осознанно согласуйте его через recovery access до retry.
Read-only модуль `library/portfolio_hardening_info.py` выполняет inspection.
UFW CLI используется без новой collection; операции с rules идемпотентны и
отмечают фактические additions/updates.

Все SSH allow rules создаются до incoming deny, outgoing allow и UFW enable.
IPv4 и IPv6 должны быть включены и проверены. В начало SSH config добавляется
managed port/public-key block; остальное содержимое сохраняется. Полный candidate
проходит `sshd -t -f` до atomic replacement. Только изменённый block вызывает
handler, который повторяет `sshd -t`. В service mode выполняется узкий reload
`ssh.service`. В socket mode выполняется `daemon-reload`, затем generated/effective
semantic listeners сравниваются между собой, а их ports — с `sshd -T` и desired
list, пока текущие listeners продолжают работать. Candidate inspection также
требует runtime UFW allow для всех desired SSH ports в IPv4/IPv6 до restart.
После успешной проверки `ssh.socket` и
`ssh.service` перезапускаются одной упорядоченной транзакцией. Preflight проверяет
фактические зависимости socket/service и `KillMode=process` для сохранения
установленных сессий. Несовпадение generated ports останавливает выполнение до
restart listeners; перед повторной попыткой согласуйте конфигурацию через recovery
access. Handlers запускаются только при изменении SSH block. См.
[Ubuntu socket activation](https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189),
[UFW remote management](https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html)
и [OpenSSH configuration](https://man.openbsd.org/sshd_config).

Оба public targets сначала проверяют независимый `ansible` key-only access и
`sudo -n`. После provisioning wrapper открывает новое соединение на **каждом**
configured SSH port и повторяет access/sudo и hardening checks. Уже доверенная
host identity закрепляется через
[OpenSSH HostKeyAlias](https://man.openbsd.org/ssh_config#HostKeyAlias), с strict
checking и отключённым connection sharing. Ошибка соединения немедленно
останавливает stage; используйте recovery access без слепого повторения изменений.
`make verify-hardening` выполняет те же независимые подключения и read-only
inspection: SSH config/effective ports/exact daemon listeners, UFW active/enabled,
incoming deny/outgoing allow, все configured TCP allow rules для IPv4/IPv6,
неизменённые ownership fingerprints и active Docker/containerd. Проверка ничего
не устанавливает, не вызывает handlers и не создаёт smoke container. Временные
Ansible module files очищаются как при access verification.
Это post-convergence verification: требуются все configured SSH ports.
До первого успешного `make harden` timeout на будущем порту возможен; сам по
себе он не означает lockout текущего inventory route. Wrapper сообщает failed
configured port и направляет к `make verify-access` и recovery access.
При ошибке остановитесь; выполняйте следующую manual-команду только после
успешного завершения предыдущей.

Docker forwarding rules сохраняются. UFW host-input policy сама по себе не
ограничивает будущие Docker-published container ports; application network
security относится к отдельному deployment stage. См.
[Docker and UFW](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw).

Offline-регрессии используют synthetic inventories, opaque keys, mocked commands
и real local Ansible с заблокированной сетью. Проверяются preflight failures,
isolation managed/controller connections, verification каждого порта, validation
перед заменой SSH config, сохранение fallback policy, SSH/UFW convergence,
порядок firewall enable и verification без записи managed state. Эти проверки
не доказывают работоспособность production host.

Ручная live validation на уже Docker-ready host:

```bash
make verify-access
make verify-docker
make harden
make verify-hardening
make harden
make verify-hardening
```

Второй `make harden` должен дать `changed=0`, если external state не изменился.
Агент выполняет только offline checks; live safety, listeners и идемпотентность
подтверждаются вручную. После Stage 3 — STOP.

## Переопределения и troubleshooting

Make поддерживает local inventory path и абсолютный private-key path вне
репозитория. Используйте одинаковые overrides для всех live targets:

```bash
make bootstrap-user INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make verify-access INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make docker-host INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make verify-docker INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
```

Для существующего ключа нужен соседний `.pub`. Используйте dedicated ключ без
шифрования: encrypted existing keys не смогут аутентифицироваться в
non-interactive verification этого wrapper. Права существующей key-directory
должны быть `0700` или строже; исправляйте небезопасные локальные права осознанно.
Отсутствующая пара генерируется, но неполная пара автоматически не исправляется
и не заменяется.

Можно заменить `ansible_user: root` в inventory на существующего администратора
без изменений роли. Нужны SSH password login и sudo; bootstrap тогда также
запросит sudo password через штатный `--ask-become-pass`. Managed user этих Make
targets остаётся `ansible`. Inventory поддерживает один хост и только поля host,
port, initial user, Python interpreter и hardening port lists из example; credentials и дополнительные
runtime variables отклоняются.

Все generated runtimes/tooling находятся в ignored `.tools`, `.venv`, `.ansible`
и `.cache`. uv release archives и SHA256 закреплены в `scripts/install-uv.sh`
([официальный release](https://github.com/astral-sh/uv/releases/tag/0.12.23));
Python/Ansible dependencies и `ansible.posix` — в requirements files.
Версия actionlint и checksums закреплены в его installer. Patch version Python
выбирает pinned uv в рамках серии 3.12; существующий совместимый managed runtime
3.12 переиспользуется. Setup задаёт `UV_PYTHON_INSTALL_DIR` и `UV_CACHE_DIR`
внутри проекта. Global PATH и system Python не меняются; предварительно
установленный uv и Go не требуются.

Ошибки checksum/version останавливают setup до создания inventory. Несовместимый
local uv/actionlint или неполная/несовместимая `.venv` сохраняются; setup сообщает
ошибку вместо скрытой замены. Проверьте и перенесите/удалите только проблемный
локальный tool/environment перед повтором `make setup`. Ручная установка runtime,
shell exports и активация environment больше не нужны.

Не используйте production `--check`
как offline test: он подключается к хосту и не проверяет новый login.
Осознанный повтор bootstrap для оценки `changed=0` — ещё одна live mutating
операция, требующая отдельного разрешения. Этот PR не выполнял доступ к VPS.

## Лицензия

См. [LICENSE](LICENSE). Существующая лицензия сохранена.
