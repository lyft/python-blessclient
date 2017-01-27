# Blessclient
A client for interacting with [BLESS](https://github.com/lyft/bless) services from users' laptops.

## Introduction

## Requirements

## Installation

### Quickly build a client

### Integrate your client with SSH
Blessclient will need to be called before your users can ssh into BLESS-configured servers. There are a couple of ways you can accomplish this.

1. Wrap your `ssh` command with an alias that calls blessclient first.

2. Add a `Match exec` line to your ssh_config file

## Updating the client
