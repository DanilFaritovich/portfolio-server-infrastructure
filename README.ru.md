# portfolio-server-infrastructure

[English](README.md)

Provisioning VPS на Ubuntu через Ansible. Pipeline:

```text
local setup -> bootstrap managed automation user -> verify access
-> provision Docker host -> verify Docker
-> firewall + validated SSH host ports -> verify hardening
-> human access -> verify users -> final SSH policy -> verify SSH security
-> separately confirmed server operations -> verify operations -> STOP
```

Docker Engine, Compose и Buildx готовят хост к будущим workloads. Caddy,
application networks/Compose files, Vue, domains/TLS, GHCR authentication,
deployment/CD, fail2ban и
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
make inspect-hardening
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
и текущий SSH-порт. `bootstrap_login_user` по умолчанию — `root`;
`ansible_user` выбирает рабочего пользователя, а `ansible_private_key_file` — путь к его ключу. Сохраните структуру
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
существующую учётную запись как управляемого пользователя `ansible_user`.

## Доступ и безопасность

Стандартный путь: **bootstrap_login_user + интерактивный SSH password →
ansible_user + dedicated SSH key + NOPASSWD sudo**. Начальный login используется
только для bootstrap. Все операции и проверки Stage 1–5 используют рабочего
пользователя и ключ из inventory через независимый key-only SSH и `sudo -n`.

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
`/home/<ansible_user>/.ssh/authorized_keys`, сохраняя посторонние authorized keys.
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
роли остаётся `false`. Отдельный `/etc/sudoers.d/<ansible_user>` принадлежит root,
имеет `0440` и проверяется через `visudo -cf`. Login password для `ansible_user` не задаётся.

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
| `make generate-user-key` | Создать локальную пару Ed25519 для пользователя | **LOCAL / только файлы ключа** |
| `make show-public-key` | Показать public key и SHA256 fingerprint | **LOCAL / read-only** |
| `make show-controller` | Показать доступ из inventory и SSH-команду | **LOCAL / read-only** |
| `make connect-controller` | Интерактивный SSH под рабочим пользователем inventory | **LIVE / интерактивная сессия** |
| `make connect-user` | Интерактивный SSH под указанным пользователем | **LIVE / интерактивная сессия** |
| `make bootstrap-user` | Создать/использовать dedicated key, bootstrap account, проверить доступ | **LIVE / MUTATING** |
| `make verify-access` | Проверить key-only доступ managed user из inventory | **LIVE / verification**, без изменений managed configuration |
| `make docker-host` | Установить Docker, logging policy и настроить services | **LIVE / MUTATING**, managed key-only access |
| `make verify-docker` | Проверить Docker/services и disposable container | **LIVE / verification**, временные container/image-cache changes |
| `make inspect-hardening` | Собрать все Stage 3 safety findings перед harden | **LIVE / read-only**, exit 0 для PASS/WARN, non-zero для FAIL |
| `make harden` | Настроить UFW и validated SSH listening ports | **LIVE / MUTATING**, managed key-only access |
| `make verify-hardening` | Проверить все SSH-порты, UFW и active Docker/containerd | **LIVE / verification**, без изменения managed state |
| `make reboot-host` | Проверить доступ, подтвердить reboot, дождаться восстановления и проверить access/Docker/hardening | **LIVE / MUTATING**, интерактивное подтверждение, возможны изменения image cache |
| `make check` | YAML/Ansible lint, syntax, actionlint, wrapper tests | **OFFLINE** |
| `make ci` | Те же offline checks, что у `make check` | **OFFLINE** |

Bootstrap проверяет prerequisites, local inventory, host/port и запись known_hosts
с явным подтверждением first-use trust до генерации ключа и запроса начального пароля. Затем запускает существующую роль
с explicit sudo consent и открывает независимые key-only SSH connections как
`ansible_user`. Verification проверяет Ansible ping, `id -un == ansible_user` и
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
local fixtures с заблокированной сетью. Syntax-check покрывает все семь
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
быть `ansible_user`, а `sudo -n` — возвращать UID 0. Если ключа нет, сообщение предлагает
`make bootstrap-user`; ошибка login/sudo останавливает stage. Docker tasks
используют privilege escalation только там, где требуется, с non-interactive
sudo. Рабочий пользователь не добавляется в группу `docker`. Bootstrap login
используется только для bootstrap; managed access действует для VPS, а controller-local context
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
# Необязательно: внешние проверки доступа (по умолчанию все ssh_listen_ports).
ssh_verify_ports: [22, 2222]
firewall_allowed_tcp_ports: [80, 443]
```

`ssh_verify_ports` — непустой список уникальных integer ports из
`ssh_listen_ports` и обязательно включает текущий `ansible_port`. Если сеть компьютера блокирует порт 22, сохраните
`ssh_listen_ports: [22, 2222]`, используйте доступный `ansible_port: 2222` и задайте
`ssh_verify_ports: [2222]`. Оба server listeners и IPv4/IPv6 UFW rules остаются
обязательными; выбранные ports ограничивают только внешние SSH/sudo probes.
Внешняя доступность порта 22 при этом не подтверждается. Без этой настройки
проверяются подключения на всех listening ports.

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
systemd drop-ins, unsupported legacy `Port`/unmanaged `ListenAddress`, нестандартные SSH Include
hierarchies, занятые SSH-порты, неактивные Docker/containerd и неоднозначный UFW
state останавливают роль. Поддерживается обычный `/etc/ssh/sshd_config` со
стандартным include `/etc/ssh/sshd_config.d/*.conf` и управляемыми ролью listening
directives. Поддерживаются штатный Ubuntu active/enabled `ssh.socket` и обычный
listener mode `ssh.service`; переключения activation mode нет. Для Ubuntu 24.04
socket support рассчитан на штатный layout systemd SSH generator; service mode тоже
обязан пройти preflight. Это поддержка проверяемых конфигураций, а не любых Ubuntu
images, старых migration overrides или custom systemd layouts. Проверки выполняются
offline с synthetic fixtures и local Ansible; успешный acceptance run на Ubuntu 24.04
VM/VPS не заявляется. Штатный socket
dependency drop-in принимается только с точными директивами `After=ssh.socket`
и `Requires=ssh.socket`; socket address drop-ins должны быть созданы runtime
generator Ubuntu. Custom overrides отклоняются. Все текущие live SSH listening
ports должны оставаться в `ssh_listen_ports`.

Допускается adoption проверенного набора обычных global legacy-директив `Port <integer>`
из основного файла и обычных файлов стандартного include directory. Поддерживаются
несколько разных desired ports и повторные директивы с одинаковым портом. Каждое
значение должно входить в desired list; текущий inventory port должен входить туда
и быть live; effective и live SSH ports не должны содержать ports вне desired set.
`ListenAddress`, Port внутри Match или с unsupported syntax, legacy Port рядом с
managed block, нестандартные/вложенные/условные или повторные Includes, symlinked
configuration files и custom systemd/socket ownership по-прежнему останавливают
роль до mutation. Диагностика указывает тип директивы без вывода SSH config.

Read-only preflight сохраняет точные source path, line number, port и fingerprints
файлов. После создания UFW rules для всех desired SSH ports `portfolio_ssh_adopt`
собирает полный main/include candidate с managed block из unique sorted desired ports,
удаляет только подтверждённые exact records, сохраняя inline comments и все unrelated
bytes/settings. Повторные records с одинаковыми source/line отклоняются. До записи выполняются
`sshd -t` и проверка effective ports/public-key authentication через `sshd -T`;
Effective candidate ports должны точно совпадать с desired set, public-key authentication
должна быть включена; invalid candidate оставляет оригинальные SSH-файлы целыми.
Source fingerprints повторно проверяются непосредственно перед записью; изменения
source после preflight останавливают adoption. Snippet и main заменяются атомарно по отдельности,
с откатом при обнаруженной ошибке записи; единой filesystem transaction нет, поэтому
прерванная запись требует проверки через recovery access.
До замены adoption сохраняет `/etc/ssh/portfolio-adoption.pending` с mode 0600.
Uncatchable termination, failed rollback или ошибка удаления marker оставляют этот
сигнал; preflight и прямой adoption блокируют retry. Live listeners могут использовать
старую конфигурацию, пока main/includes на диске заменены частично. Через recovery
access восстановите или завершите согласованный tree, сохраните текущий route и
human authentication policy, проверьте `sshd -t` и effective desired ports, и только
после этого удаляйте marker. Нельзя вслепую выполнять reload SSH или удалять marker. Существующие service/socket
handlers валидируют и активируют установленную конфигурацию, затем wrapper проверяет
независимые подключения на каждом порту из `ssh_verify_ports`. После convergence legacy-директивы
нет, следующий запуск даёт `changed=0`.

Preflight проверяет штатную структуру generator/drop-ins без требования совпадения
generated file на диске с уже загруженными listeners или `sshd -T`: эти состояния
могут относиться к разным reload cycles. После `daemon-reload` generated
`ListenStream` должен точно совпасть с desired TCP routes и effective ports
`sshd -T`. Loaded systemd `Listen` и live listeners могут сохранять старый
безопасный subset до restart. После restart все три множества routes должны
точно совпасть с desired: address family, wildcard bind и port. Inspector
объединяет все строки `Listen=` из `systemctl show`. Принимается штатная пара
Ubuntu `0.0.0.0:<port>` / `[::]:<port>`. Доступность IPv4 через IPv6 wildcard
определяется `BindIPv6Only`, а при `default` — `/proc/sys/net/ipv6/bindv6only`;
реальное несовпадение address families отклоняется. См.
[systemd socket binding semantics](https://www.freedesktop.org/software/systemd/man/systemd.socket.html#BindIPv6Only=).
Preflight допускает listener только на текущем inventory SSH port, даже если
desired list содержит будущие ports. Текущий порт должен оставаться live и
входить в desired list.

Отсутствующий UFW устанавливается с `state: present`. При первом adoption
существующий UFW должен быть inactive, без unknown или unmanaged raw user rules,
с regular non-symlink base files, parseable IPv4/IPv6/default-policy и boot
configuration и stock systemd ownership. Безопасные изменения provider/image
сохраняются; отличие package hashes даёт один provenance WARN и не блокирует adoption.
Текущие normalized fingerprints сохраняются в `/etc/ufw/portfolio-hardening.json`;
повторный запуск отклоняет посторонние изменения base/raw rules и unknown rules.
Reset, удаление правил и произвольная замена unmanaged configuration не выполняются.
Managed `ENABLED`, input/output policies и fingerprints изменённых ролью rules
сходятся без ложного external drift. Effective ports из `sshd -T` сравниваются
как множество, включая одинаковые повторяющиеся entries; desired inventory port
lists по-прежнему должны содержать unique ports.
Перед UFW mutation роль сохраняет exact raw fingerprints, разрешённые порты,
normalized recovery fingerprints и правила, уже присутствующие в каждой address
family. После прерывания процесса `harden` продолжает только точные разрешённые
TCP allow additions с комментарием роли и её input/output/boot policy changes.
Распознаётся штатный UFW 0.36 empty-template rewrite при `LOGLEVEL=low/off` и стандартном
forward policy, включая IPv6 rate-limit capability variants. Остальные bytes,
неизвестные tuples/raw rules, дубликаты, удаление правил и protected base drift
блокируют продолжение. Отсутствующие raw files и неподдерживаемые initial template/logging
layouts дают fail-closed; предполагаемых rewrites и reset нет. Старый ownership marker
обновляется лишь при совпадении исходных fingerprints и не разрешает уже устаревший
ruleset. Standalone verification отклоняет stale raw fingerprints, пока `harden` не
сохранит завершённое состояние. После ошибки сначала изучите read-only report и
recovery access; не удаляйте ownership markers для обхода проверки.
SSH/UFW configuration, systemd units/drop-ins и их parent directories должны принадлежать
root с root group без group/other write permission. Symlink/type guards сохранены;
штатный Ubuntu alias `/lib` → `/usr/lib` принимается строго для package units.
UFW ownership marker дополнительно запрещает group/other access (0600 или строже).
Небезопасные ownership/modes останавливают inspection до configuration mutation.
Read-only модуль `library/portfolio_hardening_info.py` выполняет inspection.
UFW CLI используется без новой collection; операции с rules идемпотентны и
отмечают фактические additions/updates.

Все SSH allow rules создаются до incoming deny, outgoing allow и UFW enable.
IPv4 и IPv6 должны быть включены и проверены. В начало SSH config добавляется
managed port/public-key block; остальное содержимое сохраняется. Полный candidate
проходит `sshd -t -f` до atomic replacement. Изменённый block или несошедшееся
socket state вызывает handler, который повторяет `sshd -t`. В service mode выполняется узкий reload
`ssh.service`. В socket mode выполняется `daemon-reload`, затем generated
candidate routes и `sshd -T` сравниваются с desired list, пока loaded/live
listeners продолжают работать как безопасный subset. Candidate validation требует
наличия generated file со штатной поддерживаемой структурой. Candidate inspection также
требует runtime UFW allow для всех desired SSH ports в IPv4/IPv6 до restart.
После успешной проверки `ssh.socket` и
`ssh.service` перезапускаются одной упорядоченной транзакцией. Затем role строго
проверяет generated, loaded и live routes, effective SSH ports, Docker/containerd
и active UFW с точными desired IPv4/IPv6 TCP rules. Wrapper проверяет свежий
key-only SSH и `sudo -n` на каждом порту из `ssh_verify_ports`. Runtime mismatch завершает
запуск ошибкой. Preflight проверяет
фактические зависимости socket/service и `KillMode=process` для сохранения
установленных сессий. Несовпадение generated ports останавливает выполнение до
restart listeners; перед повторной попыткой согласуйте конфигурацию через recovery
access. При socket drift handlers запускаются и с неизменённым установленным SSH
block, чтобы завершить прерванный transition за один `make harden`. Безопасный
pre-transition drift generated/loaded/live даёт WARN в `make inspect-hardening`,
который остаётся READY; после convergence эти проверки дают PASS. Повторный запуск после convergence
не выполняет reload/restart SSH. См.
[Ubuntu socket activation](https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189),
[UFW remote management](https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html)
и [OpenSSH configuration](https://man.openbsd.org/sshd_config).

Оба public targets сначала проверяют независимый `ansible_user` key-only access и
`sudo -n`. После provisioning wrapper открывает новое соединение на **каждом**
порту из `ssh_verify_ports` и повторяет access/sudo и hardening checks. Уже доверенная
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
Это post-convergence verification: на сервере обязательны все routes из
`ssh_listen_ports`; внешний доступ обязателен на каждом порту из `ssh_verify_ports`.
До первого успешного `make harden` timeout на будущем порту возможен; сам по
себе он не означает lockout текущего inventory route. Wrapper сообщает failed
configured port и направляет к `make verify-access` и recovery access.
При ошибке остановитесь; выполняйте следующую manual-команду только после
успешного завершения предыдущей.

Docker forwarding rules сохраняются. UFW host-input policy сама по себе не
ограничивает будущие Docker-published container ports; application network
security относится к отдельному deployment stage. Stage 3 не меняет управление
Docker iptables, не создаёт application networks и не публикует контейнеры.
До application deployment отдельно проверяются provider-side rules и политика
Docker-published ports; открытия host-input ports здесь недостаточно. См.
[Docker and UFW](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-and-ufw).

Offline-регрессии используют synthetic inventories, opaque keys, mocked commands
и real local Ansible с заблокированной сетью. Проверяются preflight failures,
isolation managed/controller connections, verification каждого порта, validation
перед заменой SSH config, сохранение fallback policy, SSH/UFW convergence,
порядок firewall enable и verification без записи managed state. Эти проверки
не доказывают работоспособность production host.

`make inspect-hardening` — read-only preflight всего Stage 3. Он проверяет managed
key-only access и `sudo -n` по текущему inventory route, затем собирает независимые
SSH, systemd, Docker/containerd и UFW safety findings одним компактным отчётом.
Проверяются desired/effective/live ports, supported SSH files и legacy Port adoption,
activation mode, disk/generated/loaded socket state, unit overrides, UFW package
baseline, ownership, raw rules и unsafe file types. Содержимое конфигов, credentials,
command stderr и ownership fingerprints не выводятся.

`PASS` означает подходящее состояние. `WARN` означает, что harden умеет безопасно
adopt/converge его: например, supported legacy Ports, отсутствующий или inactive
pristine UFW, stale stock socket state. `FAIL` блокирует harden. Exit code равен 0
при отсутствии FAIL, включая WARN-only отчёты, и non-zero при blocking findings.
Перед harden исправьте все FAIL; повторные запуски harden не заменяют диагностику.
Проверки, которым нужны недоступные или небезопасные данные, отмечаются как
unavailable; остальные безопасные проверки продолжаются. Без managed access/sudo
remote inspection продолжить нельзя. Будущие SSH-порты проверяются без требования
их сетевой доступности до convergence.

Inspection передаёт общую с harden и verify-hardening implementation
`portfolio_hardening_info.py` через SSH stdin с `sudo -n` и Python `-B`, без remote
payload/temp files. Он не устанавливает пакеты, не пишет файлы, не меняет firewall
или systemd, не делает daemon-reload и SSH reload/restart, не запускает handlers.
Существующее strict host trust сохраняется. READY — snapshot текущего состояния;
harden повторяет safety checks перед mutation, а verification требует runtime
convergence.

Ручная live validation на уже Docker-ready host:

```bash
make verify-access &&
make inspect-hardening &&
make harden &&
make verify-hardening &&
make harden &&
make verify-hardening
```

Второй `make harden` должен дать `changed=0`, если external state не изменился.
Агент выполняет только offline checks; live safety, listeners и идемпотентность
подтверждаются вручную. После Stage 3 — STOP до отдельного запуска Stage 4.

## Подтверждённая перезагрузка хоста

После успешной проверки Stage 3 можно отдельно выполнить `make reboot-host`.
Это явная операция обслуживания, а не автоматический шаг provisioning. Перед
запуском проверьте provider-console/recovery access и provider-side SSH rules:
reboot прервёт текущие SSH sessions. Используйте те же overrides, что при остальных
проверках:

```bash
make reboot-host INVENTORY=/path/to/local-inventory.yml AUTOMATION_KEY=/path/to/automation-key
```

Wrapper сначала проверяет key-only SSH как `ansible_user` и `sudo -n` на текущем inventory
порту. Затем в интерактивном терминале спрашивает `Reboot this host now? [y/N]`.
Только `y`/`yes` разрешают reboot; пустой ответ, отказ, EOF или Ctrl-C останавливают
команду. Без TTY запуск отклоняется до обращения к хосту; unattended/force режима нет.
Существующие inventory, ключ и host trust сохраняются; новые ключи не создаются,
password authentication и sudo prompts запрещены.

`playbooks/reboot-host.yml` использует `ansible.builtin.reboot` с `reboot_timeout: 300`,
`connect_timeout: 10` и `post_reboot_delay: 5`. Ansible отдельно ограничивает ожидание
нового boot ID и readiness test: возможны примерно 600 секунд ожидания плюс задержка
и SSH/Ansible overhead. После восстановления последовательно выполняются проверки
`verify-access`, `verify-docker`, `verify-hardening` с теми же inventory и ключом,
включая независимый доступ на каждом `ssh_verify_ports` и все server listeners.
Docker smoke test может изменить image cache; firewall/SSH provisioning не запускается.
При ошибке возвращается non-zero status с указанием failed phase, последующие проверки
не выполняются. Reboot уже мог произойти: используйте recovery console и не повторяйте
его вслепую. Human-access policy реализуется отдельно в Stage 4 ниже; application deployment остаётся отдельным.

Offline-тесты подменяют все remote/reboot вызовы; `make check`/CI выполняют только
syntax-check этого playbook и локальные проверки. Агент не выполнял реальный reboot.

## Настройка рабочего пользователя и миграция

Три поля доступа задаются вместе у хоста в существующей структуре inventory:

```yaml
bootstrap_login_user: root
ansible_user: automation
ansible_private_key_file: ~/.ssh/portfolio-server-infrastructure/automation_ed25519
```

Путь к ключу должен быть абсолютным или начинаться с `~/`, вне репозитория.
Bootstrap создаёт выбранного пользователя, добавляет публичный ключ без удаления
других ключей и устанавливает проверенный через `visudo` фрагмент `NOPASSWD: ALL`.
Затем независимо проверяет новый key-only login, ping и `sudo -n`. Ошибка проверки
останавливает выполнение; inventory, старые аккаунты и SSH policy автоматически
не переключаются и не удаляются.

Старый inventory без обоих новых полей сохраняет прежний смысл: `ansible_user`
обозначает начальный login (обычно root), а следующие стадии используют старый
аккаунт `ansible` и прежний ключ либо `AUTOMATION_KEY`. Setup сохраняет существующий
inventory. Для явной записи прежнего доступа задайте `bootstrap_login_user` равным
старому initial login, `ansible_user: ansible` и путь к существующему ключу;
проверьте доступ перед дальнейшей работой. Для нового формата `AUTOMATION_KEY`
допустим только при совпадении с ключом из inventory; конфликт блокирует команду.

Если первоначальный password bootstrap login ещё работает, можно выбрать новый
аккаунт/ключ в candidate inventory и выполнить
`make bootstrap-user INVENTORY=inventories/migration.yml`. Независимая проверка
должна успешно завершиться до замены старого inventory; старый аккаунт и SSH policy
сохраняются.

На VPS с завершёнными Stage 4/5 сохраните старый inventory, открытую admin-сессию
и доступ к консоли провайдера. Не открывайте root/password SSH и не повторяйте
password bootstrap. Через старый рабочий inventory создайте отдельный ранее
неиспользованный аккаунт существующим путём `add-user`:

```bash
make add-user HUMAN_USER=automation HUMAN_SUDO=admin HUMAN_KEY="$HOME/.ssh/portfolio-infra/automation_ed25519"
make verify-user HUMAN_USER=automation HUMAN_SUDO=admin HUMAN_KEY="$HOME/.ssh/portfolio-infra/automation_ed25519"
```

Нужна завершённая Stage 3; новый admin проверяется по SSH и sudo. Public-only import
недостаточен. Используйте отдельный незашифрованный automation key вне репозитория
и сохраните независимый human recovery access. Создайте отдельный ignored candidate
inventory с `ansible_user: automation`, точным путём к новому ключу и прежними портами.
До замены рабочего inventory выполните:

```bash
make verify-access INVENTORY=inventories/migration.yml
make verify-docker INVENTORY=inventories/migration.yml
make verify-hardening INVENTORY=inventories/migration.yml
make verify-ssh-security INVENTORY=inventories/migration.yml HUMAN_USER=operator HUMAN_SUDO=admin HUMAN_KEY="$HOME/.ssh/portfolio-infra/operator_ed25519"
make verify-operations INVENTORY=inventories/migration.yml
```

Для SSH security укажите существующего отдельно проверенного human admin.
Это ручные LIVE-проверки; Docker verification может заполнить image cache.
При любой ошибке продолжайте использовать старый inventory и recovery access.
Только после успешных проверок осознанно замените рабочий inventory. Автоматического
переключения, удаления старого `ansible` или изменения SSH policy при миграции нет.
Повторное provisioning и проверка идемпотентности остаются отдельно разрешаемыми
операторскими действиями.

## Локальные ключи и интерактивный SSH

После `make setup` или `make deps` локальным командам ключей нужны OpenSSH client tools,
но не нужны inventory, Ansible playbook, аккаунт на VPS или подключение к серверу:

```bash
make generate-user-key HUMAN_USER=operator
make show-public-key HUMAN_USER=operator
```

Путь по умолчанию: `~/.ssh/portfolio-infra/operator_ed25519` и соседний `.pub`.
`KEY_NAME` выбирает другое имя private-key файла в том же каталоге, например
`KEY_NAME=operator_laptop_ed25519`; каталоги и суффикс `.pub` запрещены.
`HUMAN_KEY=/absolute/path/to/key` имеет приоритет над `KEY_NAME`. Используйте одинаковые
параметры для генерации, показа public key и `connect-user`. Существующие пары сохраняются;
неполные пары, symlinks, небезопасные права/владелец и некорректные public keys блокируют
операцию. Новые каталоги имеют `0700`, private files — `0600` или строже. Существующие
права проверяются без автоматического исправления. В репозитории допустим только
ignored каталог `secrets/portfolio-infra/`; предпочтительны ключи вне репозитория.

Для новой пары нужен терминал: `ssh-keygen` напрямую запрашивает passphrase, не передавая
её в аргументах и не сохраняя в проекте. Нажатие Enter осознанно создаёт незашифрованный
ключ. Повторная проверка существующей пары не требует терминала. `show-public-key`
выводит только публичные algorithm/key без комментария и SHA256 fingerprint;
нужна полная локальная пара, private file проверяется только по metadata.
Передавайте администратору только public key. Генерация и показ не создают аккаунт
и не устанавливают ключ на VPS; это отдельная операция `add-user`. Для нестандартного
имени передавайте точный путь через `HUMAN_KEY` существующим Stage 4 командам,
которые сохраняют прежние defaults.

Перед подключением загрузите зашифрованный ключ в существующий локальный `ssh-agent`:

```bash
ssh-add "$HOME/.ssh/portfolio-infra/operator_ed25519"
make show-controller
make connect-controller
make connect-user HUMAN_USER=operator
```

Если agent не запущен, сначала запустите локальный `ssh-agent`. `show-controller`
работает только локально: показывает рабочего пользователя, сервер, текущий порт
inventory, полный путь к ключу и готовую SSH-команду с shell quoting. Проверяются
локальная пара и существующее доверие к серверу; отсутствие ключа или trust блокирует
команду. `connect-controller` использует ту же команду; `connect-user` — сервер/порт
того же inventory и выбранные human key/login. Обе команды подключения требуют
терминал и уже установленный соответствующий public key. Они открывают обычный
интерактивный shell без provisioning или verification playbooks. Действия внутри
этой сессии могут изменять VPS.

Все три команды требуют существующую доверенную запись в `~/.ssh/known_hosts` для
`host` либо `[host]:port`. Отсутствие trust блокирует локальную проверку; изменившийся
host key вызывает отказ при подключении. Автоматического scan, принятия или замены trust нет. До осознанной настройки отсутствующей
записи проверьте identity через provider console или уже доверенный административный
маршрут. Trust file и каталог должны принадлежать вам, не быть writable для group/others
и не быть symlinks. SSH использует strict host checking, выбранный identity и key-only
authentication; password/keyboard-interactive fallback, agent forwarding, другие
forwarding и connection sharing отключены. SSH client config не используется, чтобы
user, host, port и trust source определялись входными параметрами. Пути с control
characters и OpenSSH expansion tokens запрещены. Разблокированный agent может
аутентифицировать выбранный зашифрованный ключ; без него будет отказ, а не запрос
пароля. Поддержка agent действует и для `connect-controller`; unattended Stage 1–5
сохраняют прежнюю agent-independent policy. `INVENTORY` и legacy `AUTOMATION_KEY`
следуют правилам задачи 1; конфликт managed-key override блокирует команду.

## Переопределения и troubleshooting

Make поддерживает local inventory path. Задайте `ansible_private_key_file` в нём.
`AUTOMATION_KEY` сохранён для legacy inventory; для явного формата он должен
совпадать с ключом inventory. Override ниже необязателен. Используйте одинаковый
inventory для всех live targets:

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

Можно заменить `bootstrap_login_user: root` в inventory на существующего администратора
без изменений роли. Нужны SSH password login и sudo; bootstrap тогда также
запросит sudo password через штатный `--ask-become-pass`. Managed user этих Make
targets выбирается через `ansible_user`. Inventory поддерживает один хост и только поля host,
port, bootstrap/managed users, local key path, Python interpreter и hardening port lists из example; credentials и дополнительные
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

## Пользователи и финальная защита SSH (Stage 4)

Запускайте отдельно после успешной проверки Stage 3. Все четыре команды —
**LIVE**. `add-user` и `secure-ssh` изменяют сервер; verification создаёт свежие
SSH-сессии и выполняет read-only проверки аккаунтов/policy. Root-пароли не
используются, host trust не изменяется. Сохраняйте прежние локальные inventory и
`AUTOMATION_KEY`: каждая команда сначала проверяет ключевой доступ `ansible_user`,
`sudo -n` и завершение Stage 3 на каждом маршруте `ssh_verify_ports`.

```bash
# Отдельный локальный Ed25519-ключ; администратор с root-equivalent NOPASSWD.
make add-user HUMAN_USER=portfolio_admin HUMAN_SUDO=admin
make verify-user HUMAN_USER=portfolio_admin HUMAN_SUDO=admin
# Оставьте сессию operator открытой; интерактивно подтвердите доступность console recovery.
make secure-ssh HUMAN_USER=portfolio_admin HUMAN_SUDO=admin
make verify-ssh-security HUMAN_USER=portfolio_admin HUMAN_SUDO=admin
```

Ключ человека по умолчанию: `~/.ssh/portfolio-infra/<HUMAN_USER>_ed25519`, отдельно
от automation key. `HUMAN_KEY` меняет путь. В репозитории разрешён только
`./secrets/portfolio-infra/`, например:

```bash
make add-user HUMAN_USER=reader HUMAN_GROUPS=readers HUMAN_SUDO=none \
  HUMAN_KEY="$PWD/secrets/portfolio-infra/reader_ed25519"
# Импорт одного public key без генерации/копирования private key.
make add-user HUMAN_USER=operator2 HUMAN_SUDO=admin \
  HUMAN_PUBLIC_KEY="$HOME/.ssh/operator2.pub"
# Владелец проверяет доступ с соответствующей локальной private/public парой.
make verify-user HUMAN_USER=operator2 HUMAN_SUDO=admin \
  HUMAN_KEY="$HOME/.ssh/operator2" HUMAN_PUBLIC_KEY="$HOME/.ssh/operator2.pub"
# Ограниченный sudo: путь разрешает любые аргументы поддерживаемой программы.
make add-user HUMAN_USER=auditor HUMAN_SUDO=restricted \
  HUMAN_SUDO_COMMANDS=/usr/bin/id
```

`HUMAN_USER` обязателен; `HUMAN_SUDO` по умолчанию `none`. `admin` устанавливает
`NOPASSWD: ALL`; `restricted` требует абсолютные пути программ через запятую в
`HUMAN_SUDO_COMMANDS`, без аргументов, wildcard и синтаксиса sudoers. Shell,
интерпретатор или service manager даже с таким grant могут дать полный root.
Restricted executables должны иметь canonical path, root ownership и execute bit,
с защищёнными root-owned parents; mutable files и symlinks запрещены.
`HUMAN_GROUPS` — добавляемые группы через запятую; отсутствующие создаются.
Root/system и распространённые runtime privilege groups запрещены; `sudo`/`admin`
требуют admin policy. Права custom groups проверяйте отдельно. `none` не добавляет
sudo fragment; verification требует отсутствия non-interactive sudo grant.

Ключи, автоматически создаваемые `add-user`, остаются без passphrase; отдельная
команда `generate-user-key` запрашивает её. Каталоги имеют `0700`, private keys — `0600`
или строже. Существующие пары сохраняются; неполные пары, symlinks, небезопасные
permissions и совпадение пути с automation key блокируют операцию. Wrapper не
читает private-key bytes и не отправляет их на сервер. Существующие зашифрованные
human keys могут использовать уже разблокированный SSH agent с
`IdentitiesOnly=yes` и выбранным identity; automation не зависит от agent.
Public-only импорт без доступного локального private key отмечается **UNVERIFIED**
и не разрешает финальную защиту. Используйте отдельный ключ для каждого человека;
защищайте резервные копии как пароли. `secrets/` и распространённые имена ключей
исключены из Git/Docker context; ignore rules не заменяют review staged files.
Секреты и public keys не должны попадать в inventory или committed config.
Только явная команда `show-public-key` выводит публичный ключ для передачи;
содержимое private key никогда не выводится.

### Типичная ошибка preflight

В стандартной системе у пользователя `operator` может уже существовать системная
группа с GID 37, конфликтующая с созданием нового human account с таким именем.
Раньше общее сообщение preflight скрывало причину. Выберите свободное имя
`HUMAN_USER`; не удаляйте и не принимайте существующих пользователей, группы,
домашние каталоги, sudo fragments, записи состояния и ключи вслепую. Уже созданный
ключ `operator` сохраняется. Из оставленной recovery-сессии оператор может
проверить аккаунт и sudo validator:

```bash
getent passwd operator
getent group operator
sudo -n /usr/sbin/visudo -c
sudo -n namei -l /usr/sbin/visudo
```

Symlinks по-прежнему запрещены. Не заменяйте системные бинарные файлы ради обхода
preflight; передайте диагноз на отдельную проверку совместимости.

Роль использует общие bootstrap-задачи аккаунта/controller key, сохраняет другие
`authorized_keys`, защищает home/SSH files и валидирует sudo candidate через
`visudo -cf`. Существующие unmanaged аккаунты/primary groups, unsafe homes,
конфликтующие sudo fragments, orphan records и смена privilege policy блокируют
мутации. Завершённые аккаунты записываются root-owned в
`/var/lib/portfolio-human-access/`. Добавление групп/ключей поддерживается;
удаление, adoption, миграция sudo и удаление старых ключей/групп — отдельная работа.
Прерванное создание без completion record требует recovery inspection вместо
автоматического adoption. Повторный успешный запуск сохраняет ключи и приводит
аккаунт к прежнему состоянию без замены доступа.

`secure-ssh` заново проверяет выбранного **admin** и `ansible_user`: свежий key-only
SSH и non-interactive root sudo, затем запрашивает подтверждение recovery с
default deny. Роль также перепроверяет обе учётные записи непосредственно перед
работой с policy. Устанавливаются `PermitRootLogin no`, `PasswordAuthentication no`
и `KbdInteractiveAuthentication no` отдельным блоком после Stage 3 port block,
перед standard includes. Порты, firewall и activation mode сохраняются. Любой
`Match` и неподдерживаемый Include tree блокируют операцию. Полный snapshot,
syntax validation, сравнение effective policy и fingerprints предшествуют atomic
installation; изменяться могут только три authentication settings. Валидированный
reload `ssh.service` применяет authentication в service/socket modes без restart
listeners. При неизменённой конфигурации сервис не перезагружается.

После применения независимые SSH/sudo проверки администратора и automation
повторяются на каждом выбранном маршруте. Read-only verification проверяет
effective policy и предлагаемые сервером authentication methods с existing host
trust, запрещая password/keyboard-interactive. Запрет root подтверждается effective
global policy без условных исключений; root credential для отрицательного login
не используется. Runtime probes покрывают выбранные verification routes; server
listener checks по-прежнему требуют все `ssh_listen_ports`.

При любой ошибке остановитесь: policy могла уже примениться. Не закрывайте
сохранённую сессию и не повторяйте запуск вслепую.
`/etc/ssh/portfolio-security.pending` блокирует применение/verification при
прерванной установке/reload. Через сохранённую sudo-сессию или проверенную provider
console изучите managed block, source files и pending receipt, выполните `sshd -t`
и проверьте `sshd -T`, затем явно перезагрузите проверенную конфигурацию и
подтвердите свежий доступ. Удаляйте receipt только после recovery/convergence.
Возврат нужного fallback policy — отдельное решение через console, без automatic
rollback. После hardening добавляйте людей теми же `add-user`/`verify-user` через
`ansible_user`: root/password fallback не включается. Stage 3 и maintenance сохраняют
финальный блок. Application deployment остаётся отдельным этапом.

Порядок ручной проверки: offline `make check` (включая новые synthetic/mocked
Stage 4 regressions), review кода и локальных inputs, затем отдельное разрешение
live Stage 3 verification, `add-user`, `verify-user`, `secure-ssh`,
`verify-ssh-security` именно в таком порядке. Повторите создание и secure operation
для проверки идемпотентности, затем добавьте/проверьте обычного пользователя после
hardening. Отказы (denied confirmation, bad key, unmanaged account, sudo conflict,
Match/include, interrupted activation) проверяйте только в disposable fixtures
или на тестовом VPS с рабочим recovery.

## Эксплуатация и обслуживание сервера (Stage 5)

Stage 5 запускается отдельно после Stage 4. Развёртывание приложений остаётся
отдельным этапом. `inspect-operations` и `verify-operations` используют строгий
key-only OpenSSH, существующее доверие к host key и `sudo -n`. Python-код
передаётся через stdin с `-I -B`: без удалённых payload-файлов, обновления кеша,
smoke-контейнеров и изменений журналов. Обычные записи аудита SSH/sudo возможны.
Все команды сначала проверяют hardening Stage 3; Stage 5 также требует финальную
политику Stage 4 для root/password/keyboard-interactive. Используется текущий
SSH-маршрут inventory; все маршруты и доступ человеческого администратора
перепроверяйте отдельно командами Stage 3/4.

| Команда | Поведение |
| --- | --- |
| `make inspect-operations` | LIVE/read-only preflight: PASS/WARN допускаются, FAIL блокирует |
| `make setup-operations` | LIVE/изменения: preflight, затем TTY-подтверждение `[y/N]`, по умолчанию отказ |
| `make verify-operations` | LIVE/read-only: требует применённые настройки, пакеты, таймеры и лимиты |
| `make preview-apt-policy` | LIVE/check-diff: preview только одной отсутствующей строки APT policy |
| `make apply-apt-policy` | LIVE/изменения: guarded APT-only replacement после TTY-подтверждения `[y/N]` |

Для выявленной отсутствующей директивы
`Unattended-Upgrade::Remove-New-Unused-Dependencies "false";` предусмотрен отдельный
APT-only entry point. Он использует существующие strict SSH/sudo, host trust и
инспекторы Stage 3/5. Preview и применение требуют отдельных LIVE-разрешений:

```bash
make preview-apt-policy INVENTORY=inventories/production.yml
# Только после проверки preview и отдельного разрешения на применение:
make apply-apt-policy INVENTORY=inventories/production.yml
make verify-operations INVENTORY=inventories/production.yml
```

Назначение должно уже быть regular file root:root с mode 0644 и доверенными
родительскими каталогами. Байты должны точно совпадать с текущим `apt-security.j2`
либо отличаться только отсутствием одной указанной строки. Более широкий diff,
небезопасные metadata, конкурентная замена и занятый lock останавливают команду
без попытки исправления. Preview использует Ansible `--check --diff` и не записывает
managed APT-файл; Ansible может создавать временные файлы выполнения. Применение
атомарно заменяет только `/etc/apt/apt.conf.d/99zz-portfolio-security`, затем запускает
существующую verification Stage 5. Совпадающий файл остаётся unchanged. Этот путь
не устанавливает пакеты и не настраивает Docker, journald, timers, SSH, sudoers или
аккаунты. При ошибке применения или последующей verification APT-файл уже мог
измениться: STOP, read-only диагностика, без слепого повтора. `setup-operations`
сохраняет широкий объём действий и не подходит для APT-only исправления.

Роль устанавливает `unattended-upgrades` и `logrotate` с `state: present`, без
немедленного обновления индексов или пакетов. Один маркированный APT-файл очищает
унаследованные списки origins и разрешает только Ubuntu `-security` для текущего
релиза. Сторонний origin Docker, обычный `-updates`, ESM и прочие origins исключены.
Автоматические перезагрузки и удаление пакетов/ядер отключены. Таймеры `apt-daily`,
`apt-daily-upgrade` и `logrotate` выполняют обслуживание по расписанию;
пропущенный запуск может состояться вскоре после setup. Обновления безопасности
могут перезапускать затронутые сервисы через package maintainer scripts.
Сохраните recovery-доступ и выберите окно обслуживания. Установка требует рабочих
кешированных индексов APT и сети; ошибка останавливает этап без автоматического
восстановления. Уже выполняющиеся APT maintenance services блокируют переход
политики: дождитесь завершения и повторите инспекцию, не удаляйте lock-файлы.

Лимиты journald по умолчанию: 256 MiB постоянных журналов, 64 MiB runtime,
512 MiB резерв свободного места, 14 дней хранения, сжатие. Параметры задаются
в `roles/server_operations/defaults/main.yml`, а не в ограниченном inventory.
Только изменение конфигурации вызывает handler перезапуска journald. Повторный
setup без drift должен дать `changed=0`; это нужно подтвердить на вашем VPS.
Существующие журналы освобождаются при обычной ротации; setup не выполняет vacuum
или удаление. Лимиты относятся к отдельному journal namespace и не ограничивают
произвольные файлы приложений; нестандартные namespaces вне этого этапа.

Системный logrotate должен иметь конечный глобальный rotate (1–52); отдельные
файлы допускают 0–52. Поддерживается только стандартный include `/etc/logrotate.d`.
Preflight показывает конкретные экранированные пути и ожидаемое/фактическое состояние.
Отсутствие управляемых файлов и каталога drop-in journald — WARN перед setup и FAIL
при verify. Небезопасные существующие файлы, предки или symlink всегда дают FAIL.
Штатный `apt-config` проверяет синтаксис установленной конфигурации и эффективные
значения. Будущая конфигурация передаётся через stdin в порядке загрузки APT:
управляемый файл вставляется на своё место, основной `apt.conf` — последним.
Hooks, shell-команды и операции с пакетами при этом не запускаются. Комментарии
с `#`, вложенные блоки, списки, regex и независимые vendor hooks разбирает сам APT.
Исключений по именам файлов нет: штатные periodic-настройки, включая `10periodic`,
совместимы, если кандидат безопасно приводит политику к целевому состоянию.
Поздние/main overrides, неизвестные управляющие ключи, небезопасные настройки
reboot/removal/authentication, непроверенные includes и перенаправление источников
конфигурации блокируют setup. Штатный `Unattended-Upgrade::DevRelease` определяет
запуск unattended updates на development-выпуске; он не разрешает дополнительные
origins и не обновляет дистрибутив до другого выпуска. На подтверждённой стабильной
Ubuntu, включая Noble 24.04 LTS, допустимы `auto`, `false` и `true`. Неизвестные
значения, вложенные управляющие ключи и отсутствующие или противоречивые данные
выпуска блокируют операцию. Development-выпуски не поддерживаются: `auto` может
разрешать обновления ближе к дате выпуска, `true` разрешает их, а `false` отключает
и потому не обеспечивает гарантии Stage 5. Текущая и будущая APT-политики используют
одинаковую классификацию из `/etc/os-release` и, при наличии, `/etc/lsb-release`.
Независимые настройки journald, например
`ForwardToSyslog`, допускаются; сторонние настройки хранения и неизвестные или
некорректные настройки остаются блокером. Диагностика выводит пути, ключи и строки
без значений конфигурации или текста команд. Также блокируются небезопасные пути
или symlink, masked/custom maintenance units и drop-ins, сбои критичных сервисов,
незавершённое состояние dpkg, нехватка места или inode. Конфликты устраняются
вручную: автоматического reset или adoption нет. Системный logrotate проверяется
только с `--debug`, без ротации и изменения state-файла. В daemon Docker и каждом
существующем контейнере требуются лимиты Stage 2: `local`, `20m`, `5`. Контейнеры
сохраняют настройки момента создания; несовместимые нужно отдельно рассмотреть
и пересоздать. Stage 5 не перезапускает Docker, не делает prune и не добавляет
сети, публичные порты или внешние monitoring-сервисы.

Диагностика показывает нагрузку на CPU, доступную RAM, swap, место/inode для `/`,
`/var`, `/var/log`, `/var/lib/docker`, SSH/socket, Docker/containerd, journald,
таймеры, failed units, эффективную политику обновлений и лимиты журналов.
Свободное место ниже 10% или 512 MiB, inode ниже 5% блокируют setup. RAM ниже 15%,
load/core выше 1, swap выше 50% или его отсутствие дают WARN. Pending reboot и
APT/update-run stamps старше трёх дней тоже дают WARN: stamp подтверждает активность
расписания, но не успешную установку всех security updates. Инспекция использует
текущие кешированные данные; она не обновляет индексы, не симулирует upgrade,
не считает ожидающие security-пакеты, не устанавливает обновления и не запускает
постоянный мониторинг. Состояние systemd не доказывает доступность приложения.
Timeout или некорректный ответ блокируют операцию; сырой stderr, конфиги и журналы
не выводятся.

Последовательность самостоятельной проверки (при реализации не выполнялась):

```bash
make deps               # если pinned tools ещё не установлены; доступ к registry
make check              # offline regression tests, lint, syntax с примером inventory
# После review кода, локального inventory, ключей и provider recovery-доступа:
make inspect-operations
make setup-operations   # явное подтверждение в терминале
make verify-operations
make setup-operations   # повторное подтверждение; ожидается changed=0 без drift
make verify-operations
```

Поддерживаются прежние overrides `INVENTORY` и `AUTOMATION_KEY`. Live `--check`
не является offline-проверкой. Автоматического reboot нет: при необходимости
отдельно подтвердите `make reboot-host`, затем повторите `make verify-operations`.
Существующая проверка reboot-host включает Docker smoke-контейнер и может
пополнить image cache.

Восстановление выполняется вручную. Если SSH недоступен, остановите повторные
попытки и используйте provider console. Посмотрите `systemctl status ssh.service
ssh.socket --no-pager`, `sshd -t`, `sshd -T`, `ss -lnt`, `ufw status verbose`;
сопоставьте порты Stage 3 и политику Stage 4 до редактирования или reload.
Сохраните открытую recovery-сессию и независимо подтвердите managed и human
key-only доступ перед выходом. Автоматически включать root/password login
или сбрасывать UFW нельзя.

Для Docker через console или проверенный admin-доступ прочитайте
`systemctl is-active docker containerd`, `docker info --format '{{.LoggingDriver}}'`.
Перед отдельно разрешённым ремонтом проверьте место и известную корректную
конфигурацию daemon Stage 2. Не удаляйте `/var/lib/docker`, runtime-пакеты,
ресурсы через prune и не перезапускайте Docker вслепую. Для администратора через
console/managed-доступ проверьте `id <admin>`, `getent passwd <admin>`, `visudo -c`;
восстанавливайте только рассмотренные public key/account/sudo настройки. Не
копируйте private keys и не принимайте unmanaged account автоматически. Повторно
подтвердите `make verify-user` и `make verify-ssh-security` с прежними `HUMAN_*`.
Отсутствующий managed account требует отдельно разрешённого bootstrap/recovery.

Для диагностики обновлений/журналов read-only команды: `systemctl is-active
apt-daily.timer apt-daily-upgrade.timer logrotate.timer`, `systemctl --failed
--no-pager`, `dpkg --audit`, `journalctl --disk-usage`, `logrotate --debug
/etc/logrotate.conf`. Выполняйте их только в явно разрешённой live-сессии;
подробный/debug-вывод просматривайте локально, он может раскрывать пути или другую
чувствительную информацию. Logrotate без `--debug`, принудительное удаление
APT/dpkg locks, autoremove, vacuum журналов и запуск upgrade не являются безопасной
диагностикой.

## Управление пользователями и SSH-ключами (Stage 6, задача 3)

Команды обращаются к VPS через managed user и путь ключа из inventory. Начальный
password login не используется, имя automation-пользователя не фиксировано.
Списки читают фактические аккаунты, группы, effective sudo/SSH policy и authorized keys;
локального кэша пользователей/ключей нет. Root и текущий контроллер защищены.

| Команда | Назначение | Граница |
| --- | --- | --- |
| `make list-users` | Управляемые human-пользователи, права, ключи и защищённый inventory controller | LIVE / read-only |
| `make show-user HUMAN_USER=operator` | Identity, группы, sudo и SSH-ключи | LIVE / read-only |
| `make list-user-keys HUMAN_USER=operator` | Разрешённые public keys, SHA256 fingerprints и принадлежность | LIVE / read-only |
| `make add-user-key HUMAN_USER=operator HUMAN_PUBLIC_KEY=/path/other-pc.pub` | Добавить один public key, сохранив остальные записи | LIVE / MUTATING, интерактивное подтверждение |
| `make revoke-user-key HUMAN_USER=operator KEY_FINGERPRINT=SHA256:...` | Отозвать конкретный управляемый ключ | LIVE / MUTATING, проверка другого admin и подтверждение |
| `make remove-user HUMAN_USER=operator` | Отозвать ключи/sudo и удалить аккаунт, сохранив файлы | LIVE / MUTATING, проверка другого admin и подтверждение |

Импорт использует существующую проверку `.pub`; private keys не читаются и не загружаются.
Для public key с другого ПК не нужен его private key на контроллере. После добавления
владелец независимо проверяет вход этой identity, например
`make verify-user HUMAN_USER=operator HUMAN_SUDO=admin HUMAN_KEY=/path/operator-key`
из настроенного checkout на том ПК. Успешный импорт сам по себе не доказывает доступ.
Для существующего аккаунта `add-user` использует тот же механизм добавления ключа;
изменения существующих прав/групп требуют отдельно рассмотренной миграции.

Принадлежность аккаунта определяется защищённой записью
`/var/lib/portfolio-human-access/<user>.json`, сверяемой с identity и privilege policy.
Точные authorized-key строки, явно установленные этими wrappers, учитываются в соседней
записи `<user>.keys.json`. Ключи предыдущих этапов отображаются как unmanaged.
Чтобы явно принять ответственность за такой ключ, добавьте идентичную public строку
(включая comment) через `add-user-key`. Совпадающий fingerprint при иных options/comments
или нескольких записях блокирует операцию. Неуправляемые аккаунты не принимаются в
управление; неуправляемые ключи нельзя отозвать, и они блокируют удаление аккаунта.
Записи на сервере определяют принадлежность; источником фактов о доступе остаётся VPS.

Для отзыва/удаления укажите другого managed human-admin и его локальный ключ:

```sh
make revoke-user-key HUMAN_USER=operator KEY_FINGERPRINT=SHA256:... \
  RECOVERY_USER=backupadmin RECOVERY_KEY=~/.ssh/portfolio-infra/backupadmin_ed25519
make remove-user HUMAN_USER=operator \
  RECOVERY_USER=backupadmin RECOVERY_KEY=~/.ssh/portfolio-infra/backupadmin_ed25519
```

Сохраняемый admin должен отличаться от цели и текущего контроллера. Свежий key-only SSH
доказывается отдельной ключевой identity: копия ключа контроллера по другому пути
не подходит. Проверки OpenSSH игнорируют client config, дополнительные identity,
proxy и forwarding; human ssh-agent может использовать только выбранную identity.
Пути ключей не допускают подстановок OpenSSH. Automation остаётся независимой от
agent, поэтому выделенный ключ должен работать без запроса passphrase. Recovery-keypair
должна быть локальной, полной и защищённой теми же правами, что остальные human keys;
заранее разблокируйте зашифрованный recovery-ключ через `ssh-add`.
Key-only SSH
и `sudo -n` проверяются на каждом маршруте `ssh_verify_ports`. Без этого доказательства
последний подтверждённый human-admin доступ нельзя удалить. Сохраняйте provider-console
recovery. Мутации проверяют Stage 3 и managed access, показывают состояние/запрос,
требуют default-deny TTY confirmation и отклоняют изменения состояния после preflight.
Серверные операции сериализуются и сверяют содержимое ключей перед atomic replacement.
SSH daemon, порты, authentication policy и сервисы не меняются. Успешная мутация
проверяет точный результат на сервере и повторно доказывает managed access.

Удаление блокируется активными процессами пользователя, custom userdel hooks, неизвестным
состоянием прав/групп, SSH Match, неподдерживаемыми key sources/includes и pending SSH
activation. Сначала очищаются authorized keys и удаляется managed sudo fragment,
затем вызывается `userdel` без `--remove` и `--force`. Home, mail и остальные файлы
сохраняются с числовыми владельцами; защищённая запись об удалении блокирует автоматическое
пересоздание аккаунта. Не назначайте этот UID другому аккаунту без ревизии сохранённых файлов.
Повторное добавление/отзыв/удаление не меняет уже подтверждённый результат.
Отзыв ключа влияет на будущую аутентификацию, но не закрывает существующую SSH-сессию.
При ошибке мутации credentials уже могли быть отозваны: остановитесь и проверьте состояние
через сохраняемого admin/provider recovery; не повторяйте вслепую и не ослабляйте SSH policy.

Offline checks покрывают границы принадлежности, сохранение ключей, точный отзыв,
устаревшие proofs, подтверждение, сохранение файлов, strict transport и Make wrappers.
Ручные LIVE-проверки остаются необходимыми: импортировать ключи двух ПК, независимо
проверить обе identity, отозвать один и подтвердить отказ нового входа при успешном входе
вторым, удалить тестовый managed account и проверить сохранность файлов, затем проверить
повторные операции и доступ Stage 1–5.

## Stage 6: checklist ручной интеграционной LIVE-проверки

Offline-проверки не доказывают доступ к VPS или LIVE-идемпотентность. Каждый шаг
выполняется оператором по отдельному разрешению, с проверенной provider console и
сохранённой admin-сессией. Для отзыва и удаления используйте тестовые аккаунты/ключи.

1. **Исходный доступ и миграция.** Сохраните старый ignored inventory и проверьте доступ.
   На защищённом VPS следуйте [миграции через candidate inventory](#настройка-рабочего-пользователя-и-миграция):
   создайте нового admin через `add-user`, проверьте его, затем выполните `verify-access`
   с candidate inventory. Сохраните порты и SSH policy. Password bootstrap применим
   только к новому VPS с ещё доступным initial login.
2. **Локальные ключи и trust.** На каждом ПК выполните `make setup`, создайте отдельный
   ключ через `generate-user-key`, покажите публичную часть через `show-public-key`.
   Независимо сверьте host fingerprints перед записью локального trust. Для human/recovery
   используйте passphrase и `ssh-add`, для automation — выделенный незашифрованный ключ.
   Передавайте только `.pub`. `show-controller` должен показывать выбранные на этом ПК
   inventory user/key. Отсутствующий trust и конфликтующий override должны блокировать доступ.
3. **Второй контроллер и sudo.** С первого контроллера добавьте public key второго ПК
   отдельному managed admin через `add-user`/`add-user-key`. На ПК 2 проверьте candidate
   inventory через `verify-access`, а human admin независимо через
   `verify-user HUMAN_USER=… HUMAN_SUDO=admin HUMAN_KEY=…`. В `connect-controller` и
   `connect-user` проверьте `id -un` и `sudo -n id -u` (для admin: `0`). Оба ПК должны
   работать без копирования private keys и зависимости от agent другого ПК.
4. **Точечный отзыв и отказ recovery.** Добавьте два ключа разных ПК тестовому human account,
   просмотрите `list-user-keys` и проверьте каждый с ПК владельца. Повторное добавление:
   `changed: false`. С отдельными доказанными `RECOVERY_USER`/`RECOVERY_KEY` отзовите один
   fingerprint. Новый вход им должен отказать, второй ключ, controller и recovery admin
   должны работать. Повторный отзыв — unchanged. Неверный/неразблокированный recovery-ключ,
   отсутствие sudo, копия controller key, recovery username цели/контроллера и отказ
   подтверждения должны сохранять состояние цели. Старые сессии переживают отзыв ключа;
   проверяйте новые подключения.
5. **Удаление и файлы.** Создайте marker file в home тестового пользователя и закройте
   его сессии/процессы. Legacy keys предварительно зарегистрируйте идентичной public line.
   Удалите пользователя с отдельным recovery proof; проверьте отсутствие account/sudo,
   пустые authorized keys, сохранность marker/home с числовыми владельцами, рабочий
   recovery/controller доступ и unchanged при повторном удалении. Пересоздание должно
   блокироваться. Активные процессы и unmanaged keys должны блокировать удаление до отзыва.
6. **Регрессии Stage 1–5 и STOP.** С обоих candidate inventories последовательно выполните
   `verify-access`, `verify-docker`, `verify-hardening`, `verify-ssh-security` с сохраняемым
   human admin и `verify-operations`. Docker verification может пополнить image cache.
   Только после успеха явно выберите candidate inventory. Повторный provisioning и
   проверки `changed=0` требуют отдельного разрешения; не перезагружайте VPS и не
   повторяйте password bootstrap на защищённом сервере ради регрессии.

Оба контроллера используют общие защищённые серверные записи; локального ledger для
синхронизации нет. Защищены root и текущий inventory controller; сервер не может узнать
candidate inventories других ПК. Исключите все действующие контроллеры из тестов удаления
и сохраняйте отдельного проверенного human admin. Unmanaged legacy automation accounts
этими командами не удаляются. Если ключ установлен, но запись ledger завершилась ошибкой,
новая запись остаётся unmanaged: проверьте состояние через recovery, затем явно
зарегистрируйте идентичную public line. Ошибка после отзыва credentials или sudo требует
ручной проверки через recovery без слепого повторения.
