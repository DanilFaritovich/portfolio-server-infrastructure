"""Reviewed image profiles, strict registry validation and HTTPS transport."""

from pathlib import Path
import re
import urllib.request

import yaml


class E2EError(ValueError):
    """Only static, safe operator diagnostics may use this exception."""


def require(condition, message):
    if not condition:
        raise E2EError(message)


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate fields instead of silently selecting the last value."""

    def construct_mapping(self, node, deep=False):
        pairs = self.construct_pairs(node, deep=deep)
        require(all(isinstance(key, str) for key, _ in pairs), 'Invalid E2E registry field.')
        require(len({key for key, _ in pairs}) == len(pairs), 'Duplicate E2E registry field.')
        return dict(pairs)


def registry(path=None, *, legacy=False):
    try:
        data = yaml.load((path or Path(__file__).with_name('e2e_distros.yml')).read_text(), Loader=UniqueLoader)
    except yaml.YAMLError:
        raise E2EError('Invalid E2E image registry YAML.') from None
    require(isinstance(data, dict) and set(data) == {'schema', 'default', 'legacy_schema1', 'distros'}
            and type(data['schema']) is int and data['schema'] == 1
            and isinstance(data['distros'], list) and data['distros'], 'Invalid E2E registry schema.')
    profiles = {}
    fields = {'id', 'distribution', 'version', 'name', 'architecture', 'image_url', 'checksum_url',
              'osinfo', 'boot', 'disk_format', 'cloud_init', 'ssh'}
    for item in data['distros']:
        require(isinstance(item, dict) and set(item) == fields
                and all(isinstance(value, str) for value in item.values()), 'Invalid E2E image profile.')
        # These are compatibility boundaries, not arbitrary URL/virt-install inputs.
        require(item['distribution'] == 'ubuntu' and item['version'] in ('22.04', '24.04')
                and item['architecture'] == 'amd64' and item['boot'] == 'bios'
                and item['disk_format'] == 'qcow2' and item['cloud_init'] == 'ubuntu-root-password'
                and item['ssh'] == 'stock-service-or-socket', 'Unsupported E2E compatibility profile.')
        require(item['id'] == 'ubuntu-' + item['version'] and item['id'] not in profiles
                and item['osinfo'] == 'ubuntu22.04'
                and re.fullmatch(r'[A-Za-z0-9 .()-]{1,80}', item['name']), 'Invalid/duplicate E2E distro identity.')
        base = re.fullmatch(r'https://cloud-images\.ubuntu\.com/releases/([a-z]+)/release/ubuntu-'
                            + re.escape(item['version']) + r'-server-cloudimg-amd64\.img', item['image_url'])
        require(base and base[1] == ('jammy' if item['version'] == '22.04' else 'noble')
                and item['checksum_url'] == item['image_url'].rsplit('/', 1)[0] + '/SHA256SUMS',
                'Untrusted E2E image/checksum URL.')
        profiles[item['id']] = item
    require(isinstance(data['default'], str) and data['default'] in profiles, 'Invalid E2E default distro.')
    require(isinstance(data['legacy_schema1'], str) and data['legacy_schema1'] in profiles
            and profiles[data['legacy_schema1']]['version'] == '24.04', 'Invalid E2E schema-1 compatibility distro.')
    return data['legacy_schema1'] if legacy else data['default'], profiles


def select(identity=None):
    default, profiles = registry()
    require(not identity or identity in profiles, 'Unsupported E2E_DISTRO; run make e2e-list-distros.')
    return profiles[identity or default]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise E2EError('Cloud image/checksum redirect refused before following it.')


def open_official(url):
    # Registry validation must precede this call. Disable environment proxy routing.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(url, timeout=60)


def list_distros():
    default, profiles = registry()
    for identity, profile in profiles.items():
        print(f'{identity}: {profile["name"]} ({profile["architecture"]})'
              + (' [default]' if identity == default else ''))
