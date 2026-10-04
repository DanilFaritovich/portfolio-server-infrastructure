# portfolio-server-infrastructure

[English](README.md)

Host provisioning VPS на Ubuntu через Ansible. Этот этап только создаёт
пользователя `ansible`, устанавливает его публичный ключ и sudo policy,
проверяет новый доступ и делает **STOP**. Docker, Compose, сети, firewall,
SSH hardening, Caddy и application deployment находятся вне scope этого PR.

## Quick Start

Нужен Linux-контроллер с Make, Python 3.12 (`python3.12`, venv и pip),
OpenSSH clients (`ssh`, `ssh-keygen`, `scp`, `sftp`), **sshpass**, curl, tar/gzip
и coreutils. Отсутствующие prerequisites устанавливайте самостоятельно;
например, на Ubuntu `sudo apt install sshpass`. Targets не устанавливают системные
пакеты скрыто. На VPS уже должны работать root SSH password login и быть доступны
`/usr/bin/python3`, `/bin/bash`, sudo, `/usr/sbin/visudo` и включение `/etc/sudoers.d`.

```bash
git clone https://github.com/DanilFaritovich/portfolio-server-infrastructure.git
cd portfolio-server-infrastructure
make setup

# Измените inventories/production.yml: ansible_host и ansible_port.
# До live-запуска выполните подготовку fingerprint/recovery, описанную ниже.
make check
make bootstrap
# Ansible интерактивно запросит root SSH password.
make verify
```

`make setup` скачивает pinned project-local dependencies и копирует example
inventory **только если production.yml ещё не существует**. Существующий inventory
setup не читает и не перезаписывает. `make deps` устанавливает зависимости без
создания inventory. В стандартном сценарии измените только hostname/address
и текущий SSH-порт; `ansible_user` по умолчанию — `root`. Сохраните структуру
`bootstrap` с одним хостом; не записывайте пароли или содержимое ключей в inventory.

**Перед первым live bootstrap:** независимо проверьте host, port и fingerprint
через консоль провайдера; сохраните доступ к recovery console и рабочую
административную сессию. Один раз откройте SSH, чтобы принять проверенный
fingerprint в `~/.ssh/known_hosts` контроллера (это **LIVE**):

```bash
ssh -p <verified-port> root@<verified-host>
```

Сравните показанный fingerprint перед подтверждением. Bootstrap требует запись
known_hosts; он не использует непроверенный вывод `ssh-keyscan` и не отключает
host-key checking. Неизвестный или изменённый ключ останавливает workflow.
Заранее подтвердите VPS prerequisites и включение sudoers.d. Не выбирайте чужую
существующую учётную запись как управляемого пользователя `ansible`.

## Доступ и безопасность

Стандартный путь: **root + интерактивный SSH password → ansible + dedicated
SSH key + NOPASSWD sudo**. Root используется только для initial bootstrap.
Дальнейшее provisioning должно использовать `ansible`; `make verify` явно
переопределяет начальный login из inventory на `ansible` и не использует root password.

`make bootstrap` локально создаёт Ed25519 key, если оба файла пары отсутствуют:

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

Generated keys создаются **без passphrase** для unattended provisioning.
Обладание этим private automation key вместе с неограниченным `NOPASSWD: ALL`
фактически даёт **root-equivalent access к VPS**. Защитите контроллер и резервные
копии ключа. Запуск `make bootstrap` явно разрешает эту policy; default consent
роли остаётся `false`. Отдельный `/etc/sudoers.d/ansible` принадлежит root,
имеет `0440` и проверяется через `visudo -cf`. Login password для `ansible` не задаётся.

Пароль запрашивает штатный Ansible `--ask-pass`, используя OpenSSH и sshpass
с закреплённой версией Ansible. Пароль находится в памяти процессов и передаётся
внутренне через pipe; wrapper его не обрабатывает. Пароль не передаётся через
command arguments, environment variables или файлы и не сохраняется в inventory,
`.env`, конфигурации или shell history. Используйте обычный интерактивный терминал;
не записывайте секретный ввод и не передавайте пароль shell-командами.
См. [документацию Ansible SSH transport](https://docs.ansible.com/projects/ansible-core/2.18/collections/ansible/builtin/ssh_connection.html).

## Команды и границы

| Target | Назначение | Доступ к хосту |
| --- | --- | --- |
| `make setup` | Установить local dependencies; создать отсутствующий inventory | Только dependency registries |
| `make deps` | Установить pinned local tooling/collections | Только dependency registries |
| `make bootstrap` | Создать/использовать dedicated key, bootstrap account, проверить доступ | **LIVE / MUTATING** |
| `make verify` | Проверить существующий key-only доступ ansible | **LIVE / verification**, без изменений managed configuration |
| `make check` | YAML/Ansible lint, syntax, actionlint, wrapper tests | **OFFLINE** |
| `make ci` | Те же offline checks, что у `make check` | **OFFLINE** |

Bootstrap проверяет prerequisites, local inventory, host/port и запись known_hosts
до генерации ключа и запроса начального пароля. Затем запускает существующую роль
с explicit sudo consent и открывает независимые key-only SSH connections как
`ansible`. Verification проверяет Ansible ping, `id -un == ansible` и
`sudo -n id -u == 0`; ошибка любой стадии завершает workflow с ошибкой.
Повторное использование начального SSH-соединения отключено. После verification
дальнейший host provisioning не выполняется.

`make verify` использует тот же verification playbook без bootstrap role и
генерации ключа. Password authentication и prompts отключены. Назначение —
read-only: Ansible может создавать и удалять временные module files, но
не меняет account или host configuration. При ошибке сохраните резервный доступ.
Успешного bootstrap recap недостаточно для подтверждения handoff.

Checks всегда используют `inventories/production.example.yml`, никогда —
production inventory, ключи, пароли или соединения с VPS. Wrapper tests используют
временные синтетические fixtures и mocked processes, включая генерацию ключей.
GitHub Actions скачивает зависимости и запускает только `make ci`, без production
credentials. Offline success не доказывает live access или runtime idempotency.
Безопасный автоматический formatter (`make fix`) не настроен. Для диагностики:
`make lint-yaml`, `make lint-ansible`, `make syntax-check`, `make lint-workflows`,
`make test-access`. Required branch-protection check `offline-validation`
настраивается отдельно.

## Переопределения и troubleshooting

Make поддерживает local inventory path и абсолютный private-key path вне
репозитория. Используйте одинаковые overrides для обоих live targets:

```bash
make bootstrap INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
make verify INVENTORY=/absolute/path/production.yml AUTOMATION_KEY=/absolute/path/dedicated/key
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
port, initial user и Python interpreter из example; credentials и дополнительные
runtime variables отклоняются.

Dependency tooling остаётся в игнорируемых `.venv`, `.ansible` и `.tools`:
версии Python/Ansible tooling и `ansible.posix` закреплены в requirements files;
версия actionlint и checksums архивов — в installer. Поддерживаются Linux x86_64
и arm64; Go не нужен. Если Python 3.12 отсутствует, можно подготовить local runtime
через uv (необязательно):

```bash
export UV_PYTHON_INSTALL_DIR="$PWD/.tools/python"
export UV_CACHE_DIR="$PWD/.cache/uv"
uv python install 3.12 --no-bin
mkdir -p .tools/runtime-bin
ln -sf "$(uv python find --managed-python 3.12)" .tools/runtime-bin/python3.12
export PATH="$PWD/.tools/runtime-bin:$PATH"
export PIP_CACHE_DIR="$PWD/.cache/pip"
make setup
```

В новых терминалах снова добавьте этот PATH. Не используйте production `--check`
как offline test: он подключается к хосту и не проверяет новый login.
Осознанный повтор bootstrap для оценки `changed=0` — ещё одна live mutating
операция, требующая отдельного разрешения. Этот PR не выполнял доступ к VPS.

## Лицензия

См. [LICENSE](LICENSE). Существующая лицензия сохранена.
