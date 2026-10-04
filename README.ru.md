# portfolio-server-infrastructure

[English](README.md)

Ansible-инфраструктура для личного VPS на Ubuntu. Первый этап через существующую
административную SSH-учётную запись создаёт управляемого пользователя `ansible`,
добавляет предоставленный контроллером публичный ключ и настраивает явно
одобренную политику sudo без пароля. На этом этап заканчивается. Offline-проверки
пройдены; live-запуск и независимая проверка новой учётной записи не выполнялись.

## Область задачи и prerequisites

Для контроллера разработчика нужны Linux x86_64 или arm64, Make, POSIX shell,
curl, tar с поддержкой gzip и coreutils, включая sha256sum. Python 3.12 должен
быть доступен как `python3.12` с поддержкой venv и pip. Для описанной ниже
подготовки локального Python также нужен uv в PATH. Go для проекта не требуется.
Версии Python tooling и `ansible.posix` закреплены в `requirements-dev.txt` и
`requirements.yml`; версия actionlint v1.7.7 и SHA256-суммы архивов закреплены в
`scripts/install-actionlint.sh`. Подготовка скачивает пакеты и готовый release
из GitHub. После подготовки проверки работают offline.

До bootstrap независимо проверьте хост, SSH-порт, административную учётную
запись, fingerprint хоста и доступ к консоли восстановления. На VPS уже должны
быть `/usr/bin/python3`, `/bin/bash`, sudo, `/usr/sbin/visudo` и активное включение
`/etc/sudoers.d` в sudoers. Текущий администратор должен иметь возможность стать
root. Этот этап не устанавливает prerequisites и не меняет SSH-настройки.

По умолчанию создаётся `ansible` с домашней директорией `/home/ansible` и shell
`/bin/bash`. Имя можно переопределить; домашняя директория должна быть
`/home/<username>`. Не выбирайте чужую существующую учётную запись или текущего
bootstrap-пользователя. Пароль не задаётся. Существующие дополнительные группы
и посторонние authorized keys сохраняются. Владельцы и права домашней директории
и SSH-файлов управляются явно. Новая учётная запись предназначена для входа по ключу.

`bootstrap_user_allow_passwordless_sudo` по умолчанию равен `false`. До изменения
учётной записи bootstrap требует явно установить boolean `true`. Это включает
неограниченный `NOPASSWD: ALL`, эквивалентный root-доступу. Отдельный sudoers-файл
с владельцем root и правами `0440` проверяется через `visudo -cf` до активации.
Изучите эту политику перед включением.

Допускается только абсолютный путь к читаемому обычному `.pub`-файлу; symlink
отклоняется. Файл читается на контроллере и должен содержать один OpenSSH-ключ
RSA, Ed25519 или NIST ECDSA. Задачи с ключом скрывают его содержимое в выводе.
Playbook не читает и не копирует private keys. Реальные inventories, публичные
и приватные ключи, credentials и логи не должны попадать в Git.

## Локальная подготовка и offline validation

Выполняйте команды из корня репозитория. Сохраняется текущий подход с локальным
Python 3.12 и `.venv`. Если Python 3.12 ещё недоступен, подготовьте его через uv:

```bash
export UV_PYTHON_INSTALL_DIR="$PWD/.tools/python"
export UV_CACHE_DIR="$PWD/.cache/uv"
uv python install 3.12 --no-bin
mkdir -p .tools/runtime-bin
ln -sf "$(uv python find --managed-python 3.12)" .tools/runtime-bin/python3.12
```

В каждом новом терминале для этого локального runtime настройте PATH и cache pip
внутри проекта:

```bash
export PATH="$PWD/.tools/runtime-bin:$PATH"
export PIP_CACHE_DIR="$PWD/.cache/pip"
```

Python runtime находится в `.tools/python`; symlink `python3.12` — в
`.tools/runtime-bin`. `make deps` создаёт `.venv` через `python3.12 -m venv`,
устанавливает туда pinned Python/Ansible tooling, а collections — в
`.ansible/collections`. Готовый pinned binary actionlint скачивается для
архитектуры контроллера, проверяется по SHA256 и устанавливается в
`.tools/bin/actionlint`. Go runtime и компиляция не используются.

`.tools`, `.venv`, `.cache` и `.ansible` — локальные игнорируемые директории
проекта, а не системная установка. Подготовка и проверки не устанавливают tools
системно. Подготовке нужен доступ к источникам зависимостей, но VPS не используется:

```bash
make deps
```

Запустите одну общую offline-проверку:

```bash
make check
```

`make check` и `make lint-workflows` используют `.tools/bin/actionlint` напрямую;
добавлять actionlint в PATH не нужно. `make ci` запускает ту же общую проверку.
Для диагностики отдельно запускайте только нужный target:

```bash
make lint-yaml
make lint-ansible
make syntax-check
make lint-workflows
```

Syntax check и Ansible lint используют безопасный example inventory. Они не
исполняют задачи, не читают реальный публичный ключ и не подключаются к хосту.
`make fix` и `make verify` отсутствуют: безопасный автоформаттер и disposable
integration test не настроены. Успешные lint/syntax checks не подтверждают
runtime-идемпотентность или доступ.

GitHub Actions устанавливает зависимости и запускает `make ci` для PR в
`develop` и `main`, а также push в эти ветки. CI не использует production inventory
или secrets. Настройте `offline-validation` как обязательную проверку в branch
protection; настройки репозитория — отдельный ручной шаг.

## Первый bootstrap вручную

Сохраните рабочую административную SSH-сессию и доступ к консоли восстановления.
Сначала завершите offline-проверки. Следующая подготовка не подключается к VPS:

```bash
cp inventories/production.example.yml inventories/production.yml
```

Отредактируйте игнорируемый `inventories/production.yml`: замените пример хоста,
начальный `ansible_user`, текущий SSH-порт и при необходимости путь Python.
Сохраните alias `portfolio` для команд ниже. Не переключайте inventory на
`ansible` до создания этой учётной записи. Не записывайте пароли или содержимое
ключей в inventory.

Задайте на контроллере реальные независимо проверенные значения. Строки ниже —
placeholders, а не конфигурация сервера:

```bash
export VPS_HOST='your-verified-host'
export VPS_PORT='your-existing-port'
export VPS_ADMIN='your-existing-admin'
export BOOTSTRAP_PUBLIC_KEY='/absolute/path/to/automation_key.pub'
export BOOTSTRAP_PRIVATE_KEY='/absolute/path/to/automation_key'
```

Переменная private key используется только SSH-клиентом при независимой проверке
входа. Playbook получает только `BOOTSTRAP_PUBLIC_KEY`. Административная
аутентификация может использовать текущие SSH config/agent; при необходимости
добавьте `--private-key` с ключом администратора. Зашифрованный ключ при
необходимости самостоятельно разблокируйте в локальном agent.

**LIVE: следующая команда подключается к VPS.** Проверьте fingerprint через
доверенный канал; не отключайте host-key checking. Проверьте текущую sudo-политику
и Python, затем сохраните эту сессию для восстановления доступа:

```bash
ssh -p "$VPS_PORT" "$VPS_ADMIN@$VPS_HOST"
# В удалённой административной сессии:
command -v python3
sudo -l
sudo /usr/sbin/visudo -c
```

До продолжения подтвердите включение `/etc/sudoers.d` административной проверкой.
Реализация проверяет пути prerequisites, но не переписывает главный sudoers-файл
и не включает эту директорию.

**LIVE, ИЗМЕНЯЕТ ХОСТ: из отдельного терминала контроллера создайте учётную запись.**
Команда явно разрешает неограниченный sudo без пароля:

```bash
.venv/bin/ansible-playbook -i inventories/production.yml playbooks/bootstrap.yml \
  --limit portfolio --ask-become-pass \
  -e "$(.venv/bin/python -c 'import json, os; print(json.dumps({"bootstrap_user_public_key_path": os.environ["BOOTSTRAP_PUBLIC_KEY"]}))')" \
  -e '{"bootstrap_user_allow_passwordless_sudo": true}'
```

Уберите `--ask-become-pass`, если текущий администратор — root или уже имеет sudo
без пароля. Локальный Python-фрагмент сериализует только путь публичного ключа
в JSON, включая пути с пробелами; файл ключа не читается. При любой ошибке
остановитесь; не отключайте проверки и не расширяйте задачу до hardening.

В Make и CI нет автоматического live-target. Production-запуск с `--check` тоже
подключается к хосту и может упасть на зависимых задачах ключей/файлов, если
пользователь ещё не существует; последующий вход он не проверяет. Это не
offline validation; recap не заменяет независимую проверку доступа.

## Независимая проверка доступа и STOP

**LIVE: из другого терминала контроллера проверьте вход по новому ключу и sudo.**
Команда принудительно использует public-key authentication с выбранным private key:

```bash
ssh -p "$VPS_PORT" -i "$BOOTSTRAP_PRIVATE_KEY" \
  -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  "ansible@$VPS_HOST" 'id -un && sudo -n -l && sudo -n id -u'
```

Ожидаются имя `ansible`, согласованная sudo-политика и итоговый UID `0`; проверьте
весь вывод и exit status. Одного успешного recap недостаточно. При ошибке входа
или sudo сохраните старую административную сессию и разберите причину.

Необязательная **LIVE** Ansible-проверка после SSH/sudo handoff использует тот же
alias с явным переопределением подключения. Role изменения учётной записи не запускается:

```bash
.venv/bin/ansible portfolio -i inventories/production.yml \
  -u ansible --private-key "$BOOTSTRAP_PRIVATE_KEY" -e ansible_user=ansible \
  -m ansible.builtin.ping
.venv/bin/ansible portfolio -i inventories/production.yml \
  -u ansible --private-key "$BOOTSTRAP_PRIVATE_KEY" -e ansible_user=ansible \
  --become -m ansible.builtin.command -a 'id -u'
```

Для оценки идемпотентности осознанно повторите ту же **LIVE-команду, изменяющую
хост**, через исходного администратора; для уже корректного хоста ожидается
`changed=0`. Это отдельный реальный запуск, а не offline-проверка.

STOP после независимой проверки доступа и привилегий. Этот этап не реализует
и не разрешает Docker, proxy, firewall, SSH hardening, смену порта, отключение
root-login, изменение password authentication или deployment. Сохраните резервный доступ.

## Лицензия

См. [LICENSE](LICENSE). Существующая лицензия сохранена.
