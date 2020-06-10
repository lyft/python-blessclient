#!/usr/local/bin/python
from __future__ import absolute_import
import boto3
from botocore.exceptions import (ClientError,
                                 ParamValidationError,
                                 ConnectionError,
                                 EndpointConnectionError)

import kmsauth
import os
import sys
import psutil
import datetime
import time
import re
import argparse
import copy
import subprocess
import json
import hvac
import getpass

import six

from . import awsmfautils
from .bless_aws import BlessAWS
from .bless_cache import BlessCache
from .user_ip import UserIP
from .bless_lambda import BlessLambda
from .bless_config import BlessConfig
from .vault_ca import VaultCA
from .lambda_invocation_exception import LambdaInvocationException

import logging

try:
    from . import tokengui
except ImportError:
    tokengui = None


DATETIME_STRING_FORMAT = '%Y%m%dT%H%M%SZ'


def update_client(bless_cache, bless_config):
    last_updated_cache = bless_cache.get('last_updated')
    if last_updated_cache:
        last_updated = datetime.datetime.strptime(last_updated_cache, DATETIME_STRING_FORMAT)
    else:
        last_updated = datetime.datetime.utcnow()
        bless_cache.set('last_updated', last_updated.strftime(DATETIME_STRING_FORMAT))
        bless_cache.save()
    if last_updated + datetime.timedelta(days=7) > datetime.datetime.utcnow():
        logging.debug('Client does not need to upgrade yet.')
        return
    # Update
    logging.info('Client is autoupdating.')
    autoupdate_script = bless_config.get_client_config()['update_script']
    if autoupdate_script:
        command = os.path.normpath(os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.pardir,
            autoupdate_script))
        if os.path.isfile(command):
            error_file = open('{}/.blessclient_err.log'.format(os.path.expanduser('~')), 'w')
            subprocess.Popen(command, stdout=error_file, stderr=error_file)
            # Note: Updating will remove the bless cache so the following cache update.
            # We are just setting it in case the update fails or the repo is already up to date
            # in which case the bless cache will not be deleted.
            last_updated = datetime.datetime.utcnow()
            bless_cache.set('last_updated', last_updated.strftime(DATETIME_STRING_FORMAT))
            bless_cache.save()
        else:
            logging.warn('Missing autoupdate script {}'.format(command))
    else:
        logging.info('No update script is configured, client will not autoupdate.')


def get_region_from_code(region_code, bless_config):
    alias_code = region_code.upper()
    aliases = bless_config.get('REGION_ALIAS')
    if alias_code in aliases:
        return aliases[alias_code]
    else:
        raise ValueError('Unrecognized region code: {}'.format(region_code))


def get_regions(region, bless_config):
    """ Get an ordered list of regions in which to run bless_config
    Args:
        region (str): the current AWS region code (e.g., 'us-east-1') where blessclient
            has attempted to run and failed.
        bless_config (dict): config from BlessConfig
    Returns:
        List of regions
    """
    regions = []
    aws_regions = tuple(sorted(bless_config.get('REGION_ALIAS').values()))
    try:
        ndx = aws_regions.index(region)
    except ValueError:
        ndx = 0
    while len(regions) < len(aws_regions):
        regions.append(aws_regions[ndx])
        ndx = (ndx + 1) % len(aws_regions)
    return regions


def get_kmsauth_config(region, bless_config):
    """ Return the kmsauth config values for a given AWS region
    Args:
        region (str): the AWS region code (e.g., 'us-east-1')
        bless_config (BlessConfig): config from BlessConfig
    Retruns:
        A dict of configuation values
    """
    alias_code = bless_config.get_region_alias_from_aws_region(region)
    return bless_config.get('KMSAUTH_CONFIG_{}'.format(alias_code))


def get_blessrole_credentials(iam_client, creds, blessconfig, bless_cache):
    """
    Args:
        iam_client: boto3 iam client
        creds: User credentials with rights to assume the use-bless role, or None for boto to
            use its default search
        blessconfig: BlessConfig object
        bless_cache: BlessCache object
    """
    role_creds = uncache_creds(bless_cache.get('blessrole_creds'))
    if role_creds and role_creds['Expiration'] > time.gmtime():
        return role_creds

    lambda_config = blessconfig.get_lambda_config()
    if creds is not None:
        mfa_sts_client = boto3.client(
            'sts',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
    else:
        mfa_sts_client = boto3.client('sts')

    user_arn = bless_cache.get('userarn')
    if not user_arn:
        user = iam_client.get_user()['User']
        user_arn = user['Arn']
        bless_cache.set('username', user['UserName'])
        bless_cache.set('userarn', user_arn)
        bless_cache.save()

    role_arn = awsmfautils.get_role_arn(
        user_arn,
        lambda_config['userrole'],
        lambda_config['accountid']
    )

    logging.debug("Role Arn: {}".format(role_arn))

    role_creds = mfa_sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='mfaassume',
        DurationSeconds=blessconfig.get_client_config()['usebless_role_session_length'],
    )['Credentials']

    logging.debug("Role Credentials: {}".format(role_creds))
    bless_cache.set('blessrole_creds', make_cachable_creds(role_creds))
    bless_cache.save()

    return role_creds


def get_idfile_from_cmdline(cmdline, default):
    identity_file = default

    if ('BLESS_IDENTITYFILE' in os.environ) and (
            os.environ['BLESS_IDENTITYFILE'] != ''):
        return os.environ['BLESS_IDENTITYFILE']

    try:
        iflag = cmdline.index('-i')
        identity_file = cmdline[iflag + 1]
    except ValueError:
        pass

    if (identity_file[-4:] == '.pub'):
        # someone set their public key as their identity
        identity_file = identity_file[0:-4]

    return identity_file


def get_mfa_token_cli():
    sys.stderr.write('Enter your AWS MFA code: ')
    mfa_pin = six.moves.input()
    return mfa_pin


def get_mfa_token_gui(message):
    sys.stderr.write(
        "Enter your AWS MFA token in the gui dialog.\n")
    tig = tokengui.TokenInputGUI()
    if message == 'BLESS':
        message = None
    tig.doGUI(message)
    mfa_pin = tig.code
    return mfa_pin


def get_mfa_token(showgui, message):
    mfa_token = None
    if not showgui:
        mfa_token = get_mfa_token_cli()
    elif tokengui:
        mfa_token = get_mfa_token_gui(message)
    else:
        raise RuntimeError(
            '--gui requested but no tkinter support '
            '(often the `python-tk` package).'
        )
    return mfa_token


def clear_kmsauth_token_cache(config, cache):
    cache_key = 'kmsauth-{}'.format(config['awsregion'])
    kmsauth_cache = {
        'token': None,
        'Expiration': '20160101T000000Z'
    }
    cache.set(cache_key, kmsauth_cache)
    cache.save()


def get_kmsauth_token(creds, config, username, cache):
    cache_key = 'kmsauth-{}'.format(config['awsregion'])
    kmsauth_cache = cache.get(cache_key)
    if kmsauth_cache:
        expiration = time.strptime(
            kmsauth_cache['Expiration'], '%Y%m%dT%H%M%SZ')
        if expiration > time.gmtime() and kmsauth_cache['token'] is not None:
            logging.debug(
                'Using cached kmsauth token, good until {}'.format(kmsauth_cache['Expiration']))
            return kmsauth_cache['token']

    config['context'].update({'from': username})
    try:
        token = kmsauth.KMSTokenGenerator(
            config['kmskey'],
            config['context'],
            config['awsregion'],
            aws_creds=creds,
            token_lifetime=60
        ).get_token().decode('US-ASCII')
    except kmsauth.ServiceConnectionError:
        logging.debug("Network failure for kmsauth")
        raise LambdaInvocationException('Connection error getting kmsauth token.')
    # We have to manually calculate expiration the same way kmsauth does
    lifetime = 60 - (kmsauth.TOKEN_SKEW * 2)
    if lifetime > 0:
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=lifetime)
        kmsauth_cache = {
            'token': token,
            'Expiration': expiration.strftime('%Y%m%dT%H%M%SZ')
        }
        cache.set(cache_key, kmsauth_cache)
        cache.save()
    return token


def setup_logging():
    setting = os.getenv('BLESSDEBUG', '')
    if setting == '1':
        logging.basicConfig(level=logging.DEBUG)
    elif setting != '':
        logging.basicConfig(filename=setting, level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.CRITICAL)


def get_bless_cache(nocache, bless_config):
    client_config = bless_config.get_client_config()
    cachedir = os.path.join(
        os.path.expanduser('~'),
        client_config['cache_dir'])
    cachemode = BlessCache.CACHEMODE_RECACHE if nocache else BlessCache.CACHEMODE_ENABLED
    return BlessCache(cachedir, client_config['cache_file'], cachemode)


def make_cachable_creds(token_data):
    _token_data = copy.deepcopy(token_data)
    expiration = token_data['Expiration'].strftime('%Y%m%dT%H%M%SZ')
    _token_data['Expiration'] = expiration
    return _token_data


def uncache_creds(cached_data):
    if cached_data and 'Expiration' in cached_data.keys():
        _cached_data = copy.deepcopy(cached_data)
        _cached_data['Expiration'] = time.strptime(
            cached_data['Expiration'], '%Y%m%dT%H%M%SZ')
        return _cached_data
    return cached_data


def load_cached_creds(bless_config):
    """ Load cached AWS credentials for the user that has recently MFA'ed
    Args:
        bless_config (BlessConfig): Loaded BlessConfig
    Return:
        dict of AWS credentials, or {} if no current credentials are found
    """
    client_config = bless_config.get_client_config()
    cachedir = os.path.join(
        os.getenv(
            'HOME',
            os.getcwd()),
        client_config['mfa_cache_dir'])
    cache_file_path = os.path.join(cachedir, client_config['mfa_cache_file'])
    if not os.path.isfile(cache_file_path):
        return {}

    cached_data = {}
    with open(cache_file_path, 'r') as cache:
        cached_data = uncache_creds(json.load(cache))
        if cached_data['Expiration'] < time.gmtime():
            cached_data = {}
    return cached_data


def save_cached_creds(token_data, bless_config):
    """ Save the session credentials for this user, after the user has MFA'ed
    Args:
        token_data (dict): credentials returned from sts call
        bless_config (BlessConfig): Loaded BlessConfig
    """
    client_config = bless_config.get_client_config()
    cachedir = os.path.join(
        os.getenv(
            'HOME',
            os.getcwd()),
        client_config['mfa_cache_dir'])
    if not os.path.exists(cachedir):
        os.makedirs(cachedir)

    cache_file_path = os.path.join(cachedir, client_config['mfa_cache_file'])
    _token_data = make_cachable_creds(token_data)
    with open(cache_file_path, 'w') as cache:
        json.dump(_token_data, cache)


def ssh_agent_remove_bless(identity_file):
    DEVNULL = open(os.devnull, 'w')
    try:
        subprocess.check_call(
            ['ssh-add', '-d', identity_file], stderr=DEVNULL)
    except subprocess.CalledProcessError:
        logging.debug(
            "Non-zero exit from ssh-add, are there no identities in the current agent?")


def ssh_agent_add_bless(identity_file):
    DEVNULL = open(os.devnull, 'w')
    try:
        subprocess.check_call(['ssh-add', identity_file], stderr=DEVNULL)
    except:
        logging.debug("Could not add '{}' to ssh-agent".format(identity_file))
        sys.stderr.write(
            "Couldn't add identity to ssh-agent")


def get_stderr_feedback():
    feedback = True
    if os.getenv('BLESSQUIET', '') != '':
        feedback = False
    return feedback


def get_username(aws, bless_cache):
    username = bless_cache.get('username')
    if not username:
        try:
            user = aws.iam_client().get_user()['User']
        except ClientError:
            try:
                awsmfautils.unset_token()
                user = aws.iam_client().get_user()['User']
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'SignatureDoesNotMatch':
                    sys.stderr.write(
                        "Your authentication signature was rejected by AWS; try checking your system " +
                        "date & timezone settings are correct\n")
                    raise

                sys.stderr.write(
                    "Can't get your user information from AWS! Either you don't have your user"
                    " aws credentials set as [default] in ~/.aws/credentials, or you have another"
                    " process setting AWS credentials for a service account in your environment.\n")
                raise
        username = user['UserName']
        bless_cache.set('username', username)
        bless_cache.set('userarn', user['Arn'])
        bless_cache.save()
    return username


def check_fresh_cert(cert_file, blessconfig, bless_cache, userIP):
    if os.path.isfile(cert_file):
        certlife = time.time() - os.path.getmtime(cert_file)
        if certlife < float(blessconfig['certlifetime'] - 15):
            if (certlife < float(blessconfig['ipcachelifetime'])
                or bless_cache.get('certip') == userIP.getIP()
            ):
                return True
    return False


def get_default_config_filename():
    """ Get the full path to the default config file
    Returns (str): Full path to file blessclient.cfg in repo root
    """
    file_dir = os.path.dirname(os.path.realpath(__file__))
    return os.path.normpath(os.path.join(file_dir, os.pardir, 'blessclient.cfg'))


def update_config_from_env(bless_config):
    """ Override config values from environment variables
    Args:
        bless_config (BlessConfig): Loaded BlessConfig
    """
    lifetime = os.getenv('BLESSIPCACHELIFETIME')
    if lifetime is not None:
        lifetime = int(lifetime)
        logging.debug('Overriding ipcachelifetime from env: {}'.format(lifetime))
        bless_config.set_lambda_config('ipcachelifetime', lifetime)


def get_linux_username(username):
    """
    Returns a linux safe username.
    :param username: Name of the user (could include @domain.com)
    :return: Username string that complies with IEEE Std 1003.1-2001
    """
    match = re.search('[.a-zA-Z]+', username)
    return match.group(0)


def get_cached_auth_token(bless_cache):
    """
    Returns cached Vault auth token if available, otherwise None
    :param bless_cache: Bless cache object
    :return: Vault auth token or None if no valid token cached
    """
    vault_creds = bless_cache.get('vault_creds')
    if vault_creds is None or vault_creds['expiration'] is None:
        return None
    else:
        expiration = vault_creds['expiration']
        if datetime.datetime.utcnow() < datetime.datetime.strptime(expiration, '%Y%m%dT%H%M%SZ'):
            logging.debug(
                'Using cached vault token, good until {}'.format(expiration))
            return vault_creds['token']
        else:
            return None


def get_credentials():
    print("Enter Vault username:")
    username = six.moves.input()
    password = getpass.getpass(prompt="Password (will be hidden):")
    return username, password


def auth_okta(client, auth_mount, bless_cache):
    """
    Authenticates a user in HashiCorp Vault using Okta
    :param bless_cache: Bless Cache to cache auth token
    :param auth_mount: Authentication mount point on Vault
    :param client: HashiCorp Vault client
    :return: Updated HashiCorp Vault client, and linux username
    """

    vault_auth_token = get_cached_auth_token(bless_cache)
    if vault_auth_token is not None:
        client.token = vault_auth_token
        username = get_linux_username(bless_cache.get('vault_creds')['username'])
        return client, get_linux_username(username)
    else:
        username, password = get_credentials()
        auth_params = {
            'password': password
        }
        current_time = datetime.datetime.utcnow()
        auth_url = '/v1/auth/{0}/login/{1}'.format(auth_mount, username)
        response = client.auth(auth_url, json=auth_params)

        token = response['auth']['client_token']
        expiration = current_time + datetime.timedelta(seconds=response['auth']['lease_duration'])
        username = get_linux_username(response['auth']['metadata']['username'])
        vault_credentials_cache = {
            "token": token,
            "expiration": expiration.strftime('%Y%m%dT%H%M%SZ'),
            "username": username
        }
        bless_cache.set('vault_creds', vault_credentials_cache)
        bless_cache.save()
        return client, get_linux_username(username)


def vault_bless(nocache, bless_config):

    vault_addr = bless_config.get('VAULT_CONFIG')['vault_addr']
    auth_mount = bless_config.get('VAULT_CONFIG')['auth_mount']
    bless_cache = get_bless_cache(nocache, bless_config)
    bless_lambda_config = bless_config.get_lambda_config()

    user_ip = UserIP(
        bless_cache=bless_cache,
        maxcachetime=bless_lambda_config['ipcachelifetime'],
        ip_urls=bless_config.get_client_config()['ip_urls'],
        fixed_ip=os.getenv('BLESSFIXEDIP', False))

    # Print feedback?
    show_feedback = get_stderr_feedback()

    # Create client to connect to HashiCorp Vault
    client = hvac.Client(url=vault_addr)

    # Identify the SSH key to be used
    clistring = psutil.Process(os.getppid()).cmdline()
    identity_file = get_idfile_from_cmdline(
        clistring,
        os.getenv('HOME', os.getcwd()) + '/.ssh/blessid'
    )
    # Define the certificate to be created
    cert_file = identity_file + '-cert.pub'

    logging.debug("Using identity file: {}".format(identity_file))

    # Check if we can skip asking for MFA code
    if nocache is not True:
        if check_fresh_cert(cert_file, bless_lambda_config, bless_cache, user_ip):
            logging.debug("Already have fresh cert")
            sys.exit(0)

    # Print feedback information
    if show_feedback:
        sys.stderr.write(
            "Requesting certificate for your public key"
            + " (set BLESSQUIET=1 to suppress these messages)\n"
        )

    # Identify and load the public key to be signed
    public_key_file = identity_file + '.pub'
    with open(public_key_file, 'r') as f:
        public_key = f.read()

    # Only sign public keys in correct format.
    if public_key[:8] != 'ssh-rsa ':
        raise Exception(
            'Refusing to bless {}. Probably not an identity file.'.format(identity_file))

    # Authenticate user with HashiCorp Vault
    client, linux_username = auth_okta(client, auth_mount, bless_cache)

    payload = {
        'valid_principals': linux_username,
        'public_key': public_key,
        'ttl': bless_config.get('BLESS_CONFIG')['certlifetime'],
        'ssh_backend_mount': bless_config.get('VAULT_CONFIG')['ssh_backend_mount'],
        'ssh_backend_role': bless_config.get('VAULT_CONFIG')['ssh_backend_role']
    }

    vault_ca = VaultCA(client)
    try:
        cert = vault_ca.getCert(payload)
    except hvac.exceptions.Forbidden:
        bless_cache = get_bless_cache(True, bless_config)
        client, linux_username = auth_okta(client, auth_mount, bless_cache)

        payload = {
            'valid_principals': linux_username,
            'public_key': public_key,
            'ttl': bless_config.get('BLESS_CONFIG')['certlifetime'],
            'ssh_backend_mount': bless_config.get('VAULT_CONFIG')['ssh_backend_mount'],
            'ssh_backend_role': bless_config.get('VAULT_CONFIG')['ssh_backend_role']
        }

        vault_ca = VaultCA(client)
        cert = vault_ca.getCert(payload)

    logging.debug("Got back cert: {}".format(cert))

    # Error handling
    if cert[:29] != 'ssh-rsa-cert-v01@openssh.com ':
        error_msg = json.loads(cert)
        if ('errorType' in error_msg
            and error_msg['errorType'] == 'KMSAuthValidationError'
            and nocache is False
        ):
            logging.debug("KMSAuth error with cached token, purging cache.")
            # clear_kmsauth_token_cache(kmsauth_config, bless_cache)
            raise LambdaInvocationException('KMSAuth validation error')

        if ('errorType' in error_msg and
                error_msg['errorType'] == 'ClientError'):
            raise LambdaInvocationException(
                'The BLESS lambda experienced a client error. Consider trying in a different region.'
            )

        if ('errorType' in error_msg and
                error_msg['errorType'] == 'InputValidationError'):
            raise Exception(
                'The input to the BLESS lambda is invalid. '
                'Please update your blessclient by running `make update` '
                'in the bless folder.')

        raise LambdaInvocationException(
            'BLESS client did not recieve a valid cert. Instead got: {}'.format(cert))

    # Remove old certificate, replacing with new certificate
    ssh_agent_remove_bless(identity_file)
    with open(cert_file, 'w') as cert_file:
        cert_file.write(cert)
    ssh_agent_add_bless(identity_file)

    # bless_cache.set('certip', my_ip)
    # bless_cache.save()

    logging.debug("Successfully issued cert!")
    if show_feedback:
        sys.stderr.write("Finished getting certificate.\n")


def bless(region, nocache, showgui, hostname, bless_config):
    # Setup loggging
    setup_logging()
    show_feedback = get_stderr_feedback()
    logging.debug("Starting...")

    if os.getenv('MFA_ROLE', '') != '':
        awsmfautils.unset_token()

    aws = BlessAWS()
    bless_cache = get_bless_cache(nocache, bless_config)
    update_client(bless_cache, bless_config)

    username = get_username(aws, bless_cache)

    clistring = psutil.Process(os.getppid()).cmdline()
    identity_file = get_idfile_from_cmdline(
        clistring,
        os.path.expanduser('~/.ssh/blessid'),
    )
    cert_file = identity_file + '-cert.pub'

    logging.debug("Using identity file: {}".format(identity_file))

    bless_lambda_config = bless_config.get_lambda_config()
    role_creds = None
    kmsauth_config = get_kmsauth_config(region, bless_config)
    userIP = UserIP(
        bless_cache=bless_cache,
        maxcachetime=bless_lambda_config['ipcachelifetime'],
        ip_urls=bless_config.get_client_config()['ip_urls'],
        fixed_ip=os.getenv('BLESSFIXEDIP', False))

    # Check if we can skip asking for MFA code
    if nocache is not True:
        if check_fresh_cert(cert_file, bless_lambda_config, bless_cache, userIP):
            logging.debug("Already have fresh cert")
            sys.exit(0)

        if ('AWS_SECURITY_TOKEN' in os.environ):
            try:
                # Try doing this with our env's creds
                kmsauth_token = get_kmsauth_token(
                    None,
                    kmsauth_config,
                    username,
                    cache=bless_cache
                )
                logging.debug(
                    "Got kmsauth token by default creds: {}".format(kmsauth_token))
                role_creds = get_blessrole_credentials(
                    aws.iam_client(), None, bless_config, bless_cache)
                logging.debug("Default creds used to assume role use-bless")
            except Exception:
                pass  # TODO

        if role_creds is None:
            try:
                # Try using creds stored by mfa.sh
                creds = load_cached_creds(bless_config)
                if creds:
                    kmsauth_token = get_kmsauth_token(
                        creds,
                        kmsauth_config,
                        username,
                        cache=bless_cache
                    )
                    logging.debug(
                        "Got kmsauth token by cached creds: {}".format(kmsauth_token))
                    role_creds = get_blessrole_credentials(
                        aws.iam_client(), creds, bless_config, bless_cache)
                    logging.debug("Assumed role use-bless using cached creds")
            except Exception:
                pass

    if role_creds is None:
        mfa_pin = get_mfa_token(showgui, hostname)
        if mfa_pin is None:
            sys.stderr.write("Certificate creation canceled\n")
            sys.exit(1)
        mfa_arn = awsmfautils.get_serial(aws.iam_client(), username)
        try:
            creds = aws.sts_client().get_session_token(
                DurationSeconds=bless_config.get_client_config()['user_session_length'],
                SerialNumber=mfa_arn,
                TokenCode=mfa_pin
            )['Credentials']
        except (ClientError, ParamValidationError):
            sys.stderr.write("Incorrect MFA, no certificate issued\n")
            sys.exit(1)

        if creds:
            save_cached_creds(creds, bless_config)
        kmsauth_token = get_kmsauth_token(
            creds,
            kmsauth_config,
            username,
            cache=bless_cache
        )
        logging.debug("Got kmsauth token: {}".format(kmsauth_token))
        role_creds = get_blessrole_credentials(
            aws.iam_client(), creds, bless_config, bless_cache)

    bless_lambda = BlessLambda(bless_lambda_config, role_creds, kmsauth_token, region)

    # Do bless
    if show_feedback:
        sys.stderr.write(
            "Requesting certificate for your public key"
            + " (set BLESSQUIET=1 to suppress these messages)\n"
        )
    public_key_file = identity_file + '.pub'
    with open(public_key_file, 'r') as f:
        public_key = f.read()

    if public_key[:8] != 'ssh-rsa ':
        raise Exception(
            'Refusing to bless {}. Probably not an identity file.'.format(identity_file))

    my_ip = userIP.getIP()
    ip_list = "{},{}".format(my_ip, bless_config.get_aws_config()['bastion_ips'])
    remote_user = bless_config.get_aws_config()['remote_user'] or username
    payload = {
        'bastion_user': username,
        'bastion_user_ip': my_ip,
        'remote_usernames': remote_user,
        'bastion_ips': ip_list,
        'command': '*',
        'public_key_to_sign': public_key,
    }
    cert = bless_lambda.getCert(payload)

    logging.debug("Got back cert: {}".format(cert))

    if cert[:29] != 'ssh-rsa-cert-v01@openssh.com ':
        error_msg = json.loads(cert)
        if ('errorType' in error_msg
            and error_msg['errorType'] == 'KMSAuthValidationError'
            and nocache is False
        ):
            logging.debug("KMSAuth error with cached token, purging cache.")
            clear_kmsauth_token_cache(kmsauth_config, bless_cache)
            raise LambdaInvocationException('KMSAuth validation error')

        if ('errorType' in error_msg and
                error_msg['errorType'] == 'ClientError'):
            raise LambdaInvocationException(
                'The BLESS lambda experienced a client error. Consider trying in a different region.'
            )

        if ('errorType' in error_msg and
                error_msg['errorType'] == 'InputValidationError'):
            raise Exception(
                'The input to the BLESS lambda is invalid. '
                'Please update your blessclient by running `make update` '
                'in the bless folder.')

        raise LambdaInvocationException(
            'BLESS client did not recieve a valid cert. Instead got: {}'.format(cert))

    # Remove RSA identity from ssh-agent (if it exists)
    ssh_agent_remove_bless(identity_file)
    with open(cert_file, 'w') as cert_file:
        cert_file.write(cert)

    # Check if we can skip adding identity into the running ssh-agent
    if bless_config.get_client_config()['update_sshagent'] is True:
        ssh_agent_add_bless(identity_file)
    else:
        logging.info(
            "Skipping loading identity into the running ssh-agent "
            'because this was disabled in the blessclient config.')

    bless_cache.set('certip', my_ip)
    bless_cache.save()

    logging.debug("Successfully issued cert!")
    if show_feedback:
        sys.stderr.write("Finished getting certificate.\n")


def main():
    parser = argparse.ArgumentParser(
        description=('A client for getting BLESS\'ed ssh certificates.')
    )
    parser.add_argument(
        '--host',
        help=('Host name to which we are connecting, abort if this is not a recognized host'),
        default='BLESS'
    )
    parser.add_argument(
        '--region',
        help=('Region to which you want the lambda to connect to. Options are iad or sfo. Defaults to iad'),
        default='iad'
    )
    parser.add_argument(
        '--nocache',
        help=('Don\'t use cached credentials'),
        action='store_true'
    )
    parser.add_argument(
        '--gui',
        help=(
            'If you need to input your AWS MFA token, use a gui (useful for interupting ssh)'),
        action='store_true'
    )
    parser.add_argument(
        '--config',
        help=(
            'Config file for blessclient, defaults to blessclient.cfg')
    )
    args = parser.parse_args()
    bless_config = BlessConfig()
    config_filename = args.config if args.config else get_default_config_filename()
    with open(config_filename, 'r') as f:
        bless_config.set_config(bless_config.parse_config_file(f))
    ca_backend = bless_config.get('BLESS_CONFIG')['ca_backend']
    if re.match(bless_config.get_client_config()['domain_regex'], args.host) or args.host == 'BLESS':
        start_region = get_region_from_code(args.region, bless_config)
        success = False
        for region in get_regions(start_region, bless_config):
            try:
                if ca_backend.lower() == 'hashicorp-vault':
                    vault_bless(args.nocache, bless_config)
                    success = True
                elif ca_backend.lower() == 'bless':
                    bless(region, args.nocache, args.gui, args.host, bless_config)
                    success = True
                else:
                    sys.stderr.write('{0} is an invalid CA backend'.format(ca_backend))
                    sys.exit(1)
                break
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'InvalidSignatureException':
                    sys.stderr.write(
                        'Your authentication signature was rejected by AWS; try checking your system ' +
                        'date & timezone settings are correct\n')
                logging.info(
                    'Lambda execution error: {}. Trying again in the alternate region.'.format(str(e)))
            except (LambdaInvocationException, ConnectionError, EndpointConnectionError) as e:
                logging.info(
                    'Lambda execution error: {}. Trying again in the alternate region.'.format(str(e)))
        if success:
            sys.exit(0)
        else:
            sys.stderr.write('Could not sign SSH public key.\n')
            sys.exit(1)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
