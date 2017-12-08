# Utility functions for working with AWS
#
#
from __future__ import absolute_import
import os


def get_serial(iam_client, username):
    devices = iam_client.list_mfa_devices(UserName=username)
    if len(devices['MFADevices']) == 1:
        return devices['MFADevices'][0]['SerialNumber']
    else:
        # User doesn't have an MFA device assigned.
        return None


def unset_token():
    unset_var('AWS_ACCESS_KEY_ID')
    unset_var('AWS_SECRET_ACCESS_KEY')
    unset_var('AWS_SESSION_TOKEN')
    unset_var('AWS_SECURITY_TOKEN')
    unset_var('AWS_SHARED_CREDENTIALS_FILE')


def unset_var(var):
    try:
        del os.environ[var]
    except KeyError:
        pass


def get_role_arn(user_arn, role, account_id=None):
    """
    Creates a role ARN string based on a role name and, optionally, an
    account ID.

    If role is None or empty, '' will be returned. This value will indicate to
    the mfa method that no role should be assumed.

    Arguments:
        user_arn: Arn returned from a call to iam_client.get_user()
        role: the role name
        account_id: AWS account ID

    Returns:
        The ARN as a string.
    """
    if not role:
        return ''

    if account_id:
        base_arn = user_arn.rsplit(':', 2)[0]
        return '{0}:{1}:role/{2}'.format(
            base_arn,
            account_id,
            role
        )
    else:
        base_arn = user_arn.rsplit(':', 1)[0]
        return '{0}:role/{1}'.format(base_arn, role)
