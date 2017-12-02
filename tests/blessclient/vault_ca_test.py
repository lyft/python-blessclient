import pytest
from blessclient.vault_ca import VaultCA
import hvac


TESTVAULTCONFIG = {
    'vault_addr': 'https://vault.example.com:1234'
}


def test_getCert(mocker):
    clientmock = mocker.MagicMock()
    clientmock.write.return_value = {
        'StatusCode': 200,
        'data': {
            'signed_key': "The Cert"
        }
    }
    hvacmock = mocker.patch('hvac.Client')
    hvacmock.return_value = clientmock
    client = hvac.Client(TESTVAULTCONFIG['vault_addr'])
    vault_ca = VaultCA(client)
    returned = vault_ca.getCert(
        {
            'ssh_backend_mount': 'foo',
            'ssh_backend_role': 'bar',
            'valid_principals': 'test',
            'public_key': 'ssh-rsa stuff',
            'ttl': '500'
        }
    )
    assert returned == 'The Cert'


def test_getCert_NoCert(mocker):
    clientmock = mocker.MagicMock()
    clientmock.write.return_value = {
        'StatusCode': 403,
        'data': {
            'error': "Forbidden"
        }
    }
    hvacmock = mocker.patch('hvac.Client')
    hvacmock.return_value = clientmock
    client = hvac.Client(TESTVAULTCONFIG['vault_addr'])
    vault_ca = VaultCA(client)
    with pytest.raises(Exception) as excinfo:
        vault_ca.getCert(
            {
                'ssh_backend_mount': 'foo',
                'ssh_backend_role': 'bar',
                'valid_principals': 'test',
                'public_key': 'ssh-rsa stuff',
                'ttl': '500'
            }
        )
    assert 'No certificate in response.' in str(excinfo.value)