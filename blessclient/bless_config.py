from __future__ import absolute_import
from six.moves.configparser import SafeConfigParser


class BlessConfig(object):

    DEFAULT_CONFIG = {
        'user_session_length': '64800',
        'usebless_role_session_length': '3600',
        'update_sshagent': 'true',
        'remote_user': '',
        'ca_backend': 'bless',
        'use_env_creds': 'false',
    }

    def __init__(self):
        self.blessconfig = None

    def _get_region_kms_config(self, region, config):
        section = 'REGION_{}'.format(region)
        return {
            'kmskey': config.get(section, 'kmsauthkey'),
            'context': {
                'to': config.get('MAIN', 'kms_service_name'),
                'user_type': 'user'
            },
            'awsregion': config.get(section, 'awsregion')
        }

    def _get_region_housekeeper_config(self, region, config):
        regionsection = 'REGION_{}'.format(region)
        return {
            'userrole': config.get('HOUSEKEEPER', 'user_role'),
            'accountid': config.get('HOUSEKEEPER', 'account_id'),
            'url': config.get(regionsection, 'housekeeper_url'),
            'awsregion': config.get(regionsection, 'awsregion')
        }

    def parse_config_file(self, config_file):
        config = SafeConfigParser(self.DEFAULT_CONFIG)
        config.readfp(config_file)

        blessconfig = {
            'CLIENT_CONFIG': {
                'domain_regex': config.get('CLIENT', 'domain_regex'),
                'cache_dir': config.get('CLIENT', 'cache_dir'),
                'cache_file': config.get('CLIENT', 'cache_file'),
                'mfa_cache_dir': config.get('CLIENT', 'mfa_cache_dir'),
                'mfa_cache_file': config.get('CLIENT', 'mfa_cache_file'),
                'ip_urls': [s.strip() for s in config.get('CLIENT', 'ip_urls').split(",")],
                'update_script': config.get('CLIENT', 'update_script'),
                'user_session_length': int(config.get('CLIENT', 'user_session_length')),
                'usebless_role_session_length': int(config.get('CLIENT', 'usebless_role_session_length')),
                'update_sshagent': config.getboolean('CLIENT', 'update_sshagent'),
                'use_env_creds': config.getboolean('CLIENT', 'use_env_creds'),
            },
            'BLESS_CONFIG': {
                'ca_backend': config.get('MAIN', 'ca_backend'),
                'userrole': config.get('LAMBDA', 'user_role'),
                'accountid': config.get('LAMBDA', 'account_id'),
                'functionname': config.get('LAMBDA', 'functionname'),
                'functionversion': config.get('LAMBDA', 'functionversion'),
                'certlifetime': config.getint('LAMBDA', 'certlifetime'),
                'ipcachelifetime': config.getint('LAMBDA', 'ipcachelifetime'),
                'timeoutconfig': {
                    'connect': config.getint('LAMBDA', 'timeout_connect'),
                    'read': config.getint('LAMBDA', 'timeout_read')
                }
            },
            'AWS_CONFIG': {
                'remote_user': config.get('MAIN', 'remote_user')
            },
            'REGION_ALIAS': {}
        }

        if config.has_option('MAIN', 'bastion_ips'):
            blessconfig['AWS_CONFIG']['bastion_ips'] = config.get('MAIN', 'bastion_ips')
        if blessconfig['BLESS_CONFIG']['ca_backend'].lower() == 'hashicorp-vault':
            blessconfig['VAULT_CONFIG'] = {
                'vault_addr': config.get('VAULT', 'vault_addr'),
                'auth_mount': config.get('VAULT', 'auth_mount'),
                'ssh_backend_mount': config.get('VAULT', 'ssh_backend_mount'),
                'ssh_backend_role': config.get('VAULT', 'ssh_backend_role'),
            }

        regions = config.get('MAIN', 'region_aliases').split(",")
        regions = [region.strip() for region in regions]
        for region in regions:
            region = region.upper()
            kms_region_key = 'KMSAUTH_CONFIG_{}'.format(region)
            blessconfig.update({kms_region_key: self._get_region_kms_config(region, config)})
            blessconfig['REGION_ALIAS'].update({region: blessconfig[kms_region_key]['awsregion']})

            if config.has_section('HOUSEKEEPER'):
                hk_region_key = 'HOUSEKEEPER_CONFIG_{}'.format(region)
                blessconfig.update({hk_region_key: self._get_region_housekeeper_config(region, config)})
                blessconfig['REGION_ALIAS'].update({region: blessconfig[hk_region_key]['awsregion']})

        return blessconfig

    def get(self, section):
        if section in self.blessconfig:
            return self.blessconfig[section]
        else:
            raise ValueError('{} was not a valid section in blessconfig'.format(section))

    def set_config(self, config):
        self.blessconfig = config

    def get_config(self):
        return self.blessconfig

    def get_region_alias_from_aws_region(self, aws_region):
        for alias, region in self.blessconfig['REGION_ALIAS'].items():
            if region == aws_region:
                return alias
        raise ValueError('Unexpected region: {}'.format(aws_region))

    def get_client_config(self):
        return self.blessconfig['CLIENT_CONFIG']

    def set_client_config(self, key, value):
        if key in self.blessconfig['CLIENT_CONFIG']:
            self.blessconfig['CLIENT_CONFIG'][key] = value
            return True
        else:
            return False

    def get_lambda_config(self):
        return self.blessconfig['BLESS_CONFIG']

    def set_lambda_config(self, key, value):
        if key in self.blessconfig['BLESS_CONFIG']:
            self.blessconfig['BLESS_CONFIG'][key] = value
            return True
        else:
            return False

    def get_aws_config(self):
        return self.blessconfig['AWS_CONFIG']
