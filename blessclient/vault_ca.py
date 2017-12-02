class VaultCA(object):

    def __init__(self, client):
        self.client = client

    def getCert(self, payload):
        client = self.client
        ssh_url = '{0}/sign/{1}'.format(payload['ssh_backend_mount'], payload['ssh_backend_role'])
        response = client.write(
            ssh_url,
            valid_principals=payload['valid_principals'],
            public_key=payload['public_key'],
            ttl=payload['ttl']
        )

        # EXTRACT PAYLOAD FROM RESPONSE
        payload = response['data']
        if 'signed_key' not in payload:
            raise Exception('No certificate in response.')

        # RETURN CERTIFICATE IF ALL GOES WELL
        return payload['signed_key']
