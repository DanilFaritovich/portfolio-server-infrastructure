# portfolio-server-infrastructure

[English](README.md)

Host provisioning VPS на Ubuntu через Ansible. Этот этап только создаёт
пользователя `ansible`, устанавливает его публичный ключ и sudo policy,
проверяет новый доступ и делает **STOP**. Docker, Compose, сети, firewall,
SSH hardening, Caddy и application deployment находятся вне scope этого PR.

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
make bootstrap
# Для нового хоста сначала подтвердите fingerprint; затем Ansible запросит root password.
make verify
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

**First-use trust выполняется внутри `make bootstrap`.** Сохраните доступ к
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
`make verify` не предлагает first trust и не получает новые ключи; для нового
хоста сначала выполните bootstrap. Строгая проверка host key остаётся включённой
для Paramiko bootstrap и OpenSSH verification; silent trust отсутствует.
См. [OpenSSH ssh-keyscan](https://man.openbsd.org/ssh-keyscan)
и [ssh-keygen](https://man.openbsd.org/ssh-keygen).
Заранее подтвердите VPS prerequisites и включение sudoers.d. Не выбирайте чужую
существующую учётную запись как управляемого пользователя `ansible`.

## Доступ и безопасность

Стандартный путь: **root + интерактивный SSH password → ansible + dedicated
SSH key + NOPASSWD sudo**. Root используется только для initial bootstrap.
Дальнейшее provisioning должно использовать `ansible`; `make verify` явно
переопределяет начальный login из inventory на `ansible` и не использует root password.

`make bootstrap` локально создаёт Ed25519 key, если оба файла пары отсутствуют,
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
копии ключа. Запуск `make bootstrap` явно разрешает эту policy; default consent
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
отключено. Автоматическая handoff verification и `make verify` используют
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
| `make bootstrap` | Создать/использовать dedicated key, bootstrap account, проверить доступ | **LIVE / MUTATING** |
| `make verify` | Проверить существующий key-only доступ ansible | **LIVE / verification**, без изменений managed configuration |
| `make check` | YAML/Ansible lint, syntax, actionlint, wrapper tests | **OFFLINE** |
| `make ci` | Те же offline checks, что у `make check` | **OFFLINE** |

Bootstrap проверяет prerequisites, local inventory, host/port и запись known_hosts
с явным подтверждением first-use trust до генерации ключа и запроса начального пароля. Затем запускает существующую роль
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
