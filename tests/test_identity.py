# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import string
from urllib.parse import urlencode

import pytest

from rucio.common.config import config_get_bool
from rucio.common.exception import IdentityError, IdentityNotFound, Duplicate, DatabaseException
from rucio.common.types import InternalAccount
from rucio.common.utils import generate_uuid as uuid, ssh_sign
from rucio.core.account import add_account, del_account
from rucio.core.identity import add_account_identity, add_identity, del_account_identity, del_identity, list_identities, verify_identity
from rucio.db.sqla.constants import AccountType, IdentityType
from rucio.gateway.authentication import get_ssh_challenge_token
from rucio.tests.common import account_name_generator, auth, hdrdict, headers, rfc2253_dn_generator
from rucio.tests.common_server import get_vo

PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDrZmDV3wJnXpm1dTa851KKfyY"\
             "aovD7GMU7KbDXo6NyFotFt4Sar223zJrCK+x3Qu9zEByMBbQ90eC/BTb5aNRmKL"\
             "Mkw4D7vshzQmaaoG+rTai1XU9qAMbi0dRr7z6WtOvjd0jBS9PFD913pfzM3NOKU"\
             "6DIUiMTiYBPbmhos+8D0w== test_key"

PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA62Zg1d8CZ16ZtXU2vOdSin8mGqLw+xjFOymw16OjchaLRbeEmq9t
t8yawivsd0LvcxAcjAW0PdHgvwU2+WjUZiizJMOA+77Ic0JmmqBvq02otV1PagDG4tHUa+
8+lrTr43dIwUvTxQ/dd6X8zNzTilOgyFIjE4mAT25oaLPvA9MAAAIAzIGi5cyBouUAAAAH
c3NoLXJzYQAAAIEA62Zg1d8CZ16ZtXU2vOdSin8mGqLw+xjFOymw16OjchaLRbeEmq9tt8
yawivsd0LvcxAcjAW0PdHgvwU2+WjUZiizJMOA+77Ic0JmmqBvq02otV1PagDG4tHUa+8+
lrTr43dIwUvTxQ/dd6X8zNzTilOgyFIjE4mAT25oaLPvA9MAAAADAQABAAAAgQCejydK6B
xGZIJEp99m/qmqgFq6Nmb7u4OehkaH+cFuZ6EIJMU9LE1LMJZNlCiDbKK9bmzMJEt0GJq6
EFknRmVJ3/hv32E+jaeL1Gx1DdMdejOmdLb1+kd8bMZq0Ig7SJd0WGLAoGfC17Iv3QHQQX
nAlqX+x7jYfkv3cPm5wLJdAQAAAEEA9KlaQsLcrV7c3OmpLph4NcKhgKX07gLJwbdTWc5U
ZuAYZBu0YWZUDBnDwEqMl2qgxCwZXIojDAI9Xfy/ZQTi3wAAAEEA+q4f8C3OW7bNLqbPoh
cHdVAZOY4RPfPPA+RuuSmGuqcsxWLYm0u/ea5fJty4hJGF8xz5VC6Ka5dvf1tJLuxqeQAA
AEEA8GU9eSEVjAunxUvBAXQh3aDjKoswk7QMK9JYkP8A2ThkBbyQ/MD5b0bl7qVWe6UCVV
ecQCk8zea1FXVakInNqwAAAAh0ZXN0X2tleQE=
-----END OPENSSH PRIVATE KEY-----
"""


@pytest.mark.noparallel(reason='adds/removes entities with non-unique names')
class TestIdentity:
    """
    Test the Identity abstraction layer
    """

    def test_userpass(self, random_account):
        """ IDENTITY (CORE): Test adding and removing username/password authentication """

        add_identity(random_account.external, IdentityType.USERPASS, email='ph-adp-ddm-lab@cern.ch', password='secret')
        add_account_identity('ddmlab_%s' % random_account, IdentityType.USERPASS, random_account, email='ph-adp-ddm-lab@cern.ch', password='secret')

        add_identity('/ch/cern/rucio/ddmlab_%s' % random_account, IdentityType.X509, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('/ch/cern/rucio/ddmlab_%s' % random_account, IdentityType.X509, random_account, email='ph-adp-ddm-lab@cern.ch')

        add_identity('ddmlab_%s' % random_account, IdentityType.GSS, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('ddmlab_%s' % random_account, IdentityType.GSS, random_account, email='ph-adp-ddm-lab@cern.ch')

        list_identities()

        del_account_identity('ddmlab_%s' % random_account, IdentityType.USERPASS, random_account)
        del_account_identity('/ch/cern/rucio/ddmlab_%s' % random_account, IdentityType.X509, random_account)
        del_account_identity('ddmlab_%s' % random_account, IdentityType.GSS, random_account)

        del_identity('ddmlab_%s' % random_account, IdentityType.USERPASS)

    def test_ssh(self, random_account):
        """ IDENTITY (CORE): Test adding and removing SSH public key authentication """

        add_identity(random_account.external, IdentityType.SSH, email='ph-adp-ddm-lab@cern.ch')
        add_account_identity('my_public_key', IdentityType.SSH, random_account, email='ph-adp-ddm-lab@cern.ch')

        list_identities()

        del_account_identity('my_public_key', IdentityType.SSH, random_account)
        del_identity(random_account.external, IdentityType.SSH)


def test_userpass(rest_client, auth_token):
    """ ACCOUNT (REST): send a POST to add an identity to an account."""
    username = uuid()

    # normal addition
    headers_dict = {'X-Rucio-Username': username, 'X-Rucio-Password': 'secret', 'X-Rucio-Email': 'email'}
    response = rest_client.put('/identities/root/userpass', headers=headers(auth(auth_token), hdrdict(headers_dict)))
    assert response.status_code == 201


def test_verify_userpass_identity():
    """ Test if an identity exists in the db, mapping to at least one account. """
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': get_vo()}
    else:
        vo = {}
    account_name = account_name_generator()
    account = InternalAccount(account_name, **vo)
    username = ''.join(random.choice(string.ascii_letters) for i in range(10))
    email = username + '@email.com'

    add_account(account, AccountType.USER, email)

    password = ''.join(random.choice(string.ascii_letters) for i in range(10))
    add_identity(username, IdentityType.USERPASS, email=email, password=password)
    add_account_identity(username, IdentityType.USERPASS, account, email=username + '@email.com', password=password)

    with pytest.raises(IdentityError):
        verify_identity(username, IdentityType.X509, password=password)

    assert verify_identity(username, IdentityType.USERPASS, password=password) is True

    with pytest.raises(IdentityNotFound):
        verify_identity(username, IdentityType.USERPASS, password=password + 'wrong')

    del_account_identity(username, IdentityType.USERPASS, account)
    del_identity(username, IdentityType.USERPASS)
    del_account(account)


def test_verify_x509_identity():
    """ Test if an x509 identity exists in the db, mapped to at least one account. """
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': get_vo()}
    else:
        vo = {}
    account_name = account_name_generator()
    account = InternalAccount(account_name, **vo)
    dn = rfc2253_dn_generator()
    email = 'doesntmatter@email.com'

    add_account(account, AccountType.USER, email)

    add_identity(dn, IdentityType.X509, email=email)
    add_account_identity(dn, IdentityType.X509, account, email=email)

    with pytest.raises(IdentityError):
        verify_identity(f"{dn}/C=fail", IdentityType.X509)

    assert verify_identity(dn, IdentityType.X509) is True

    del_account_identity(dn, IdentityType.X509, account)
    del_identity(dn, IdentityType.X509)
    del_account(account)


class TestListAccountsByIdentity:
    """ Test the /identities/accounts endpoint """

    def test_list_accounts_by_identity(self, rest_client, auth_token, random_account):
        """ IDENTITY (REST): Test listing accounts by identity using query parameters """
        identity_key = uuid()
        email = identity_key + '@email.com'

        add_identity(identity_key, IdentityType.USERPASS, email=email, password='secret')
        add_account_identity(identity_key, IdentityType.USERPASS, random_account, email=email, password='secret')

        query_string = urlencode({'identity_key': identity_key, 'type': 'USERPASS'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 200
        accounts = response.get_json()
        assert random_account.external in accounts

        del_account_identity(identity_key, IdentityType.USERPASS, random_account)
        del_identity(identity_key, IdentityType.USERPASS)

    def test_list_accounts_by_identity_oidc_format(self, rest_client, auth_token, random_account):
        """ IDENTITY (REST): Test listing accounts by OIDC identity with slashes in identity_key """
        # OIDC identity format with slashes - use unique identifier to avoid conflicts
        unique_id = random_account.external
        identity_key = f'SUB={unique_id}, ISS=https://auth.example.com/realms/test'
        email = f'{unique_id}@email.com'

        add_identity(identity_key, IdentityType.OIDC, email=email)
        add_account_identity(identity_key, IdentityType.OIDC, random_account, email=email)

        query_string = urlencode({'identity_key': identity_key, 'type': 'OIDC'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 200
        accounts = response.get_json()
        assert random_account.external in accounts

        del_account_identity(identity_key, IdentityType.OIDC, random_account)
        del_identity(identity_key, IdentityType.OIDC)

    def test_list_accounts_by_identity_missing_identity_key(self, rest_client, auth_token):
        """ IDENTITY (REST): Test listing accounts by identity with missing identity_key """
        query_string = urlencode({'type': 'USERPASS'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 400
        assert 'identity_key parameter is required' in response.get_data(as_text=True)

    def test_list_accounts_by_identity_missing_type(self, rest_client, auth_token):
        """ IDENTITY (REST): Test listing accounts by identity with missing type """
        query_string = urlencode({'identity_key': 'test_identity'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 400
        assert 'type parameter is required' in response.get_data(as_text=True)

    def test_list_accounts_by_identity_invalid_type(self, rest_client, auth_token):
        """ IDENTITY (REST): Test listing accounts by identity with invalid type """
        query_string = urlencode({'identity_key': 'test_identity', 'type': 'INVALID_TYPE'})
        response = rest_client.get(f'/identities/accounts?{query_string}', headers=headers(auth(auth_token)))
        assert response.status_code == 400
        assert 'Invalid identity type' in response.get_data(as_text=True)


def test_identity_mapped_to_multiple_accounts_x509(vo, rest_client):
    """AUTHENTICATION (REST): Test authenticating with same X509 identity for different accounts returns correct account info."""
    from rucio.common.types import InternalAccount
    from rucio.tests.common import rfc2253_dn_generator

    account1 = InternalAccount('test_account1_x509')
    account2 = InternalAccount('test_account2_x509')
    dn = rfc2253_dn_generator()
    email = 'email@example.com'

    add_account(account1, AccountType.USER, email)

    add_account(account2, AccountType.USER, email)

    add_identity(dn, IdentityType.X509, email=email)
    add_account_identity(dn, IdentityType.X509, account1, email=email)
    add_account_identity(dn, IdentityType.X509, account2, email=email)

    # get rucio token for account1
    headers_dict = {'X-Rucio-Account': account1}

    response = rest_client.get('/auth/x509',
                               headers=headers(hdrdict(headers_dict)),
                               environ_base={'SSL_CLIENT_S_DN': dn})

    assert response.status_code == 200
    assert response.headers.get('X-Rucio-Auth-Token') is not None

    # get account info for account1
    headers_dict = {'X-Rucio-Account': account1,
                    'X-Rucio-Auth-Token': response.headers.get('X-Rucio-Auth-Token')}

    response = rest_client.get(f'/accounts/{str(account1)}',
                               headers=headers(hdrdict(headers_dict)))

    assert response.status_code == 200

    resp_dict = response.get_json()
    assert resp_dict['account'] == str(account1)

    # get rucio token for account2 using same x509 dn
    headers_dict = {'X-Rucio-Account': account2}

    response = rest_client.get('/auth/x509',
                               headers=headers(hdrdict(headers_dict)),
                               environ_base={'SSL_CLIENT_S_DN': dn})

    assert response.status_code == 200
    assert response.headers.get('X-Rucio-Auth-Token') is not None

    # get account info for account2
    headers_dict = {'X-Rucio-Account': account2,
                    'X-Rucio-Auth-Token': response.headers.get('X-Rucio-Auth-Token')}

    response = rest_client.get(f'/accounts/{str(account2)}',
                               headers=headers(hdrdict(headers_dict)))

    assert response.status_code == 200
    resp_dict = response.get_json()
    assert resp_dict['account'] == str(account2)

    del_account_identity(dn, IdentityType.X509, account1)
    del_account_identity(dn, IdentityType.X509, account2)
    del_identity(dn, IdentityType.X509)
    del_account(account1)
    del_account(account2)


def test_identity_mapped_to_multiple_accounts_ssh(vo, rest_client):
    """AUTHENTICATION (REST): Test authenticating with same SSH identity for different accounts returns correct account info."""
    from rucio.common.types import InternalAccount

    account1 = InternalAccount('test_account1_ssh')
    account2 = InternalAccount('test_account2_ssh')
    email = 'email@example.com'

    add_account(account1, AccountType.USER, email)

    add_account(account2, AccountType.USER, email)

    try:
        add_identity(PUBLIC_KEY, IdentityType.SSH, email=email)
    except (Duplicate, DatabaseException):
        pass

    add_account_identity(PUBLIC_KEY, IdentityType.SSH, account1, email=email)
    add_account_identity(PUBLIC_KEY, IdentityType.SSH, account2, email=email)

    challenge_token = get_ssh_challenge_token(account=str(account1),
                                              appid='test',
                                              ip='127.0.0.1', vo=vo).get('token')

    signature = ssh_sign(PRIVATE_KEY, challenge_token)

    # get auth token account1
    headers_dict = {'X-Rucio-Account': account1,
                    'X-Rucio-SSH-Signature': signature}

    response = rest_client.get('/auth/ssh',
                               headers=headers(hdrdict(headers_dict)))

    assert response.status_code == 200
    assert response.headers.get('X-Rucio-Auth-Token') is not None

    # get account info for account1
    headers_dict = {'X-Rucio-Account': account1,
                    'X-Rucio-Auth-Token': response.headers.get('X-Rucio-Auth-Token')}

    response = rest_client.get(f'/accounts/{str(account1)}',
                               headers=headers(hdrdict(headers_dict)))

    assert response.status_code == 200

    resp_dict = response.get_json()
    assert resp_dict['account'] == str(account1)

    # get rucio token for account2 using same ssh private key dn

    challenge_token = get_ssh_challenge_token(account=str(account2),
                                              appid='test',
                                              ip='127.0.0.1', vo=vo).get('token')

    signature = ssh_sign(PRIVATE_KEY, challenge_token)

    headers_dict = {'X-Rucio-Account': account2,
                    'X-Rucio-SSH-Signature': signature}

    response = rest_client.get('/auth/ssh',
                               headers=headers(hdrdict(headers_dict)))

    assert response.status_code == 200
    assert response.headers.get('X-Rucio-Auth-Token') is not None

    # get account info for account2
    headers_dict = {'X-Rucio-Account': account2,
                    'X-Rucio-Auth-Token': response.headers.get('X-Rucio-Auth-Token')}

    response = rest_client.get(f'/accounts/{str(account2)}',
                               headers=headers(hdrdict(headers_dict)))

    assert response.status_code == 200

    resp_dict = response.get_json()
    assert resp_dict['account'] == str(account2)

    del_account_identity(PUBLIC_KEY, IdentityType.SSH, account1)
    del_account_identity(PUBLIC_KEY, IdentityType.SSH, account2)
    del_identity(PUBLIC_KEY, IdentityType.SSH)
    del_account(account1)
    del_account(account2)
