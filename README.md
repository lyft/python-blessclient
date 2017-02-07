# Blessclient
A client for interacting with [BLESS](https://github.com/lyft/bless) services from users' laptops.

## Introduction

## Requirements

## Installation
To get to the point where you can login to a server using your bless'ed SSH certificate, you will need:
  * A BLESS Lambda that signs your users' public keys, and is trusted by your SSH hosts. See [BLESS](https://github.com/lyft/bless/tree/lyft_base).
  * Your SSH server configured to trust the Lambda
  * The blessclient (this project) which talks to the Lambda to get a new SSH certificate
  * Some configuration work to have the blessclient invoked when the user runs SSH

### Run a BLESS lambda in AWS
Run Lyft's fork of Netflix's BLESS in your repo. There are two major additions that our fork includes which have not been upstreamed yet:
  * The client authenticates to the Lambda using a [kmsauth](https://github.com/lyft/python-kmsauth) token. This allows the Lambda to authenticate the user, even if the AWS user is in a different AWS account.
  * We allow a list of IP address or cidr blocks for the user's IP and bastion IP addresses.

The lambda execution role will need permissions to decrypt the CA private key in your configuration, as well as permission to decrypt kmsauth tokens (see below).

Blessclient assumes that the user will assume a role, and the role has permissions to execute the Lambda. You should create this role, give it permissions to execute the Lambda, and give your users permissions to assume the role. The kmsauth policy can be used to require MFA, however you may want to also require MFA to assume this role, in case the kmsauth control fails.

### Setup a kmsauth key + policy in your AWS account
Kmsauth is a system where we use an AWS KMS key and AWS IAM policy to get proof that a particular user proved their identity to AWS at a specific time. For more context around kmsauth, see [the announcement for Confidant](https://eng.lyft.com/announcing-confidant-an-open-source-secret-management-service-from-lyft-1e256fe628a3#.e813nrx6k), Lyft's secret management system.

To use kmsauth with blessclient,
 1) Add a kms key in each region where you want to be able to use kmsauth.
 2) Add a policy to the kmsauth key that looks something like,
  ```
         {
            "Action": "kms:Encrypt",
            "Effect": "Allow",
            "Resource": [
                "arn:aws:kms:us-east-1:123456789011:key/12345678-abab-cdcd-efef-123456789011",
            ],
            "Condition": {
                "StringEquals": {
                    "kms:EncryptionContext:to": [
                        "bless-production",
                    ],
                    "kms:EncryptionContext:user_type": "user",
                    "kms:EncryptionContext:from": "${aws:username}"
                },
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
  ```
This allows your users to encrypt data with the kms auth key only if the "from" context matches their username. Your lambda's execution role will need a corresponding permission to decrypt data using this same kms key when the "to" context matches the the service name (in this example, "bless-production").

### Trust your BLESS Lambda
Your sshd_config should have a TrustedUserCAKeys option setup to trust your BLESS Lambda. See the [Netflix BLESS](https://github.com/netflix/bless#enabling-bless-certificates-on-servers) documentation for how to do this.

### Quickly build a client
At minimum, you can run `make client` to setup a virtualenv, install python-blessclient, and symlink to the resulting script. This requires users to have virtualenv and pip installed (and have reasonably recent versions of both).

### Configure your client
By default, blessclient is configured by adding a blessclient.cfg file in the repo where you downloaded blessclient. You can also specify a config file location by passing `--config` when invoking blessclient.

If you fork this project, you can include a configuration file in the fork for your users to download when they clone the repo, or you can add this repo as a git submodule to a deployment repo, and have the installation process copy your configuration file to the correct location.

You can copy the sample config (blessclient.cfg.sample) and fill in the information about your BLESS Lambda, kmsauth key, and blessclient options.

### Integrate your client with SSH
Blessclient will need to be called before your users can ssh into BLESS-configured servers. There are a couple of ways you can accomplish this.

1. Wrap your `ssh` command with an alias that calls blessclient first.

2. Add a `Match exec` line to your ssh_config file

## Automatically updating the client
If you are using a real endpoint management system to deploy software onto your users laptops, you can ignore this!

If your users' laptops are relatively unmanaged, you will probably want to have them automatically update their copy of blessclient. After 7 days of use, blessclient will run an autoupdate script, which is configurable in blessclient.cfg ('update_script' in the CLIENT section). The update script does not block the client's execution (we don't want to make users wait for a client update if they are responding to an emergency). The script could be as simple as `git pull && make client`, although you may want to include logic to pull/build the client in a temporary location and update a symlink that the user calls. At Lyft, the update process also verifies that the update target (in our deployment repo) is signed by a trusted GPG key.


## Contributing
This project is governed by [Lyft's code of conduct](https://github.com/lyft/code-of-conduct). For your PR's to be accepted, you'll need to sign our [CLA](https://oss.lyft.com/cla).

To setup your development environment, run `make develop` to install the development python dependencies from pip. Test your work with `make test`. All new contributions should have 100% (or very close) test coverage.
