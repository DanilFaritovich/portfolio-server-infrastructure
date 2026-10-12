"""Local human key commands and selected identity loading into an existing agent."""

import os
import re
import shutil
import subprocess
import sys

from .clipboard import copy_public_key
from .plans import plan_confirm, planned_action
from .common import require, validate_cli_path
from .keys import check_key, human_key_path, prepare_human_key, public_key_file


def cli_human_key(public_only=False):
    """Local key selection does not imply account creation or a sudo policy."""
    name = os.environ.get('HUMAN_USER', '')
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name) and name != 'root',
            'Set HUMAN_USER to a non-root Ubuntu username.')
    key = human_key_path(os.environ.get('HUMAN_KEY'), name, os.environ.get('KEY_NAME'), public_only=public_only)
    validate_cli_path(key)
    return name, key


def load_agent_key(key, public, *, planned=False):
    """OpenSSH owns passphrase input; never launch an agent in a child shell."""
    require(shutil.which('ssh-add'), 'Missing ssh-add. Install OpenSSH client tools.')
    fingerprint = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(public)],
                                 capture_output=True, text=True, check=True)
    fields = fingerprint.stdout.split()
    require(len(fields) >= 2 and re.fullmatch(r'SHA256:[A-Za-z0-9+/]+', fields[1]),
            'Cannot determine the public-key SHA256 fingerprint.')
    selected = fields[1]

    def identities():
        try:
            result = subprocess.run(['ssh-add', '-l', '-E', 'sha256'],
                                    capture_output=True, text=True, check=False, timeout=10)
        except subprocess.TimeoutExpired:
            raise ValueError('SSH agent did not respond within 10 seconds; check SSH_AUTH_SOCK and retry make load-user-key.') from None
        require(result.returncode in (0, 1),
                'SSH agent unavailable. Start it in your shell with eval "$(ssh-agent -s)", '
                'then run make load-user-key with the same HUMAN_USER/HUMAN_KEY/KEY_NAME.')
        return {line.split()[1] for line in result.stdout.splitlines()
                if len(line.split()) >= 2} if result.returncode == 0 else set()

    if selected in identities():
        print('SSH key already loaded in ssh-agent.\nFingerprint: ' + selected)
        return
    require(sys.stdin.isatty(),
            'Key is not loaded. Run make load-user-key in a terminal for the OpenSSH passphrase prompt. '
            'Use AGENT_LOAD=no to skip loading during generation.')
    before = public.read_bytes()
    agent_endpoint = os.environ.get('SSH_AUTH_SOCK')
    if not planned:
        plan_confirm([f'Load the selected key {key} ({selected}) into the invoking shell SSH agent; OpenSSH may ask for its passphrase. Rights: controller user; no agent is started.'],
                     validate=lambda: (check_key(key), require(public.read_bytes() == before and os.environ.get('SSH_AUTH_SOCK') == agent_endpoint, 'Selected public identity or agent endpoint changed; STOP.')))
    environment = os.environ.copy()
    environment['SSH_ASKPASS_REQUIRE'] = 'never'
    try:
        result = subprocess.run(['ssh-add', '-q', str(key)], check=False, env=environment)
    except KeyboardInterrupt:
        raise ValueError('ssh-add cancelled; key preserved. Retry make load-user-key.') from None
    require(result.returncode == 0, 'ssh-add failed or was cancelled; key preserved. Retry make load-user-key.')
    require(selected in identities(), 'ssh-add did not load the selected public identity; key preserved.')
    print('SSH key added to ssh-agent successfully.\nFingerprint: ' + selected)


def local_key(mode):
    require(shutil.which('ssh-keygen'), 'Missing ssh-keygen. Install OpenSSH client tools.')
    name, key = cli_human_key(public_only=mode == 'copy-public-key')
    policy = os.environ.get('AGENT_LOAD', 'ask')
    require(policy in ('ask', 'yes', 'no'), 'AGENT_LOAD must be ask, yes or no.')
    created = False
    agent_planned = False
    selected_agent = os.environ.get('SSH_AUTH_SOCK')
    if mode == 'generate-user-key':
        if not key.exists() and not key.with_name(key.name + '.pub').exists():
            agent_planned = policy == 'yes' or (policy == 'ask' and bool(os.environ.get('SSH_AUTH_SOCK')))
            if not planned_action(mode):
                plan_confirm([f'Create a non-overwriting Ed25519 key pair at {key} (private 0600, directory 0700); native OpenSSH passphrase input; rights: controller user.' +
                              (' Load only this newly generated identity into the existing SSH agent; native passphrase input.' if agent_planned else '')],
                             validate=lambda: require(not key.exists() and not key.with_name(key.name + '.pub').exists(),
                                                      'Key plan changed; STOP before generation.'))
        created = prepare_human_key(key, name, interactive_passphrase=True)
    # Inspect only private metadata; validate and read public material separately.
    if mode != 'copy-public-key':
        check_key(key)
    public = public_key_file(str(key) + '.pub')
    if mode == 'copy-public-key':
        copy_public_key(public)
    elif mode == 'load-user-key':
        load_agent_key(key, public)
    elif mode == 'generate-user-key':
        if created:
            print('SSH key generated successfully.')
        if created and agent_planned:
            require(os.environ.get('SSH_AUTH_SOCK') == selected_agent, 'Agent endpoint changed; STOP before loading.')
            try:
                load_agent_key(key, public, planned=True)
            except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                print('Key preserved; agent loading failed. ' + str(error), file=sys.stderr)
        elif policy == 'yes':
            try:
                load_agent_key(key, public)
            except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                print('Key preserved; agent loading failed. ' + str(error), file=sys.stderr)
        else:
            print('Agent loading skipped. Use make load-user-key when ready.')
    elif mode == 'show-public-key':
        fingerprint = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(public)],
                                     capture_output=True, text=True, check=True)
        fields = fingerprint.stdout.split()
        require(len(fields) >= 2 and re.fullmatch(r'SHA256:[A-Za-z0-9+/]+', fields[1]),
                'Cannot determine the public-key SHA256 fingerprint.')
        # Comments are not needed for transfer and may contain terminal control codes.
        print(' '.join(public.read_text().split()[:2]))
        print('SHA256 fingerprint: ' + fields[1])
