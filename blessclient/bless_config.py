import ConfigParser


class BlessConfig(object):

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

    def parse_config_file(self, config_file):
        config = ConfigParser.SafeConfigParser()
        loaded = config.readfp(config_file)

        blessconfig = {
            'CLIENT_CONFIG': {
                'domain_regex': config.get('CLIENT', 'domain_regex'),
                'cache_dir': config.get('CLIENT', 'cache_dir'),
                'cache_file': config.get('CLIENT', 'cache_file'),
                'mfa_cache_dir': config.get('CLIENT', 'mfa_cache_dir'),
                'mfa_cache_file': config.get('CLIENT', 'mfa_cache_file'),
                'ip_urls': map(str.strip, config.get('CLIENT', 'ip_urls').split(",")),
                'update_script': config.get('CLIENT', 'update_script')
            },
            'BLESS_CONFIG': {
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
                'bastion_ips': config.get('MAIN', 'bastion_ips')
            },
            'REGION_ALIAS': {}
        }

        regions = config.get('MAIN', 'region_aliases').split(",")
        regions = map(str.strip, regions)
        for region in regions:
            region = region.upper()
            kms_region_key = 'KMSAUTH_CONFIG_{}'.format(region)
            blessconfig.update({kms_region_key: self._get_region_kms_config(region, config)})
            blessconfig['REGION_ALIAS'].update({region: blessconfig[kms_region_key]['awsregion']})
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
        for alias, region in self.blessconfig['REGION_ALIAS'].iteritems():
            if region == aws_region:
                return alias
        raise ValueError('Unexpected region: {}'.format(aws_region))

    def get_client_config(self):
        return self.blessconfig['CLIENT_CONFIG']

    def get_lambda_config(self):
        return self.blessconfig['BLESS_CONFIG']

    def get_aws_config(self):
        return self.blessconfig['AWS_CONFIG']
