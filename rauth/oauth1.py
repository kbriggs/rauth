# -*- coding: utf-8 -*-
'''
    rauth.oauth1
    ------------

    OAuth 1.0/a signing logic.
'''


import base64
import hmac

from copy import deepcopy
from hashlib import sha1
from random import random
from time import time
from urllib import quote, urlencode
from urlparse import urlsplit, urlunsplit

from rauth.utils import FORM_URLENCODED, OPTIONAL_OAUTH_PARAMS


def _encode_utf8(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    return unicode(s, 'utf-8').encode('utf-8')


def _escape(s):
    '''
    Escapes a string, ensuring it is encoded as a UTF-8 octet.

    :param s: A string to be encoded.
    :type s: str
    '''
    return quote(_encode_utf8(s), safe='~')


def _remove_qs(url):
    '''
    Removes a query string from a URL before signing.

    :param url: The URL to strip.
    :type url: str
    '''
    scheme, netloc, path, query, fragment = urlsplit(url)
    return urlunsplit((scheme, netloc, path, '', fragment))


def _normalize_params(oauth_params, req_kwargs):
    '''
    This process normalizes the request parameters as detailed in the OAuth
    1.0 spec.

    Additionally we apply a `Content-Type` header to the request of the
    `FORM_URLENCODE` type if the `Content-Type` was previously set, i.e. if
    this is a `POST` or `PUT` request. This ensures the correct header is
    set as per spec.

    Finally we sort the parameters in preparation for signing and return
    a URL encoded string of all normalized parameters.

    :param oauth_params: OAuth params to sign with.
    :type oauth_params: dict
    :param req_kwargs: Request kwargs to normalize.
    :type req_kwargs: dict
    '''
    normalized = []

    params = req_kwargs.get('params', {})
    data = req_kwargs.get('data', {})
    headers = req_kwargs.get('headers', {})

    # process request parameters
    for k, v in params.items():
        normalized += [(k, v)]

    # process request data
    if 'Content-Type' in headers and \
            headers['Content-Type'] == FORM_URLENCODED:
        for k, v in data.items():
            normalized += [(k, v)]

    # extract values from our list of tuples
    all_normalized = []
    for t in normalized:
        k, v = t
        all_normalized += [(k, v)]

    # add in the params from oauth_params for signing
    for k, v in oauth_params.items():
        if (k, v) in all_normalized:  # pragma: no cover
            continue
        all_normalized += [(k, v)]

    # sort the params as per the OAuth 1.0/a spec
    all_normalized.sort()

    # finally encode the params as a string
    return urlencode(all_normalized, True).replace('+', '%20')


def hmac_sha1_signer(consumer_secret,
                     access_token_secret,
                     method,
                     url,
                     oauth_params,
                     req_kwargs):
    '''
    Given a set of request params, signs them using the HMAC-SHA1 signature
    method. Returns the signature.

    :param consumer_secret: Consumer secret.
    :type consumer_secret: str
    :param access_token_secret: Access token secret.
    :type access_token_secret: str
    :param method: The method of this particular request.
    :type method: str
    :param url: The URL of this particular request.
    :type url: str
    :param oauth_params: OAuth parameters.
    :type oauth_params: dict
    :param req_kwargs: Keyworded args that will be sent to the request
        method.
    :type req_kwargs: dict
    '''
    url = _remove_qs(url)

    oauth_params = _normalize_params(oauth_params, req_kwargs)
    parameters = map(_escape, [method, url, oauth_params])

    key = _escape(consumer_secret) + '&'
    if access_token_secret is not None:
        key += _escape(access_token_secret)

    # build a Signature Base String
    signature_base_string = '&'.join(parameters)

    # hash the string with HMAC-SHA1
    hashed = hmac.new(key, signature_base_string, sha1)

    # return the signature
    return base64.b64encode(hashed.digest())


def rsa_sha1_signer(consumer_secret,
                    access_token_secret,
                    method,
                    url,
                    oauth_params,
                    req_kwargs):
    raise NotImplementedError


def plaintext_signer(consumer_secret,
                     access_token_secret,
                     method,
                     url,
                     oauth_params,
                     req_kwargs):
    raise NotImplementedError


signature_names = {hmac_sha1_signer: 'HMAC-SHA1',
                   rsa_sha1_signer: 'RSA-SHA1',
                   plaintext_signer: 'PLAINTEXT'}


def _parse_optional_params(oauth_params, req_kwargs):
    '''
    Parses and sets optional OAuth 1.0/a parameters on a request.

    :param oauth_params: The OAuth parameters to parse.
    :type oauth_param: str
    :param req_kwargs: The keyworded arguments passed to the request
        method.
    :type req_kwargs: dict
    '''
    params = req_kwargs.get('params', {})
    data = req_kwargs.get('data') or {}

    for oauth_param in OPTIONAL_OAUTH_PARAMS:
        if oauth_param in params:
            oauth_params[oauth_param] = params.pop(oauth_param)
        if oauth_param in data:
            oauth_params[oauth_param] = data.pop(oauth_param)

        if params:
            req_kwargs['params'] = params

        if data:
            req_kwargs['data'] = data


def get_params(req_kwargs,
               consumer_key,
               signature_name,
               access_token=None,
               version='1.0'):
    '''
    Given a dictionary, `req_kwargs`, returns a dictionary of OAuth 1.0/a
    signing parameters.

    :param req_kwargs: A request dictionary formatted such that a keyword
        `params` and a keyword `data` represent the request parameters and
        request body, respectively.
    :type request: dict
    '''
    oauth_params = {}

    oauth_params['oauth_consumer_key'] = consumer_key
    oauth_params['oauth_nonce'] = sha1(str(random())).hexdigest()
    oauth_params['oauth_signature_method'] = signature_name
    oauth_params['oauth_timestamp'] = time()

    if access_token is not None:
        oauth_params['oauth_token'] = access_token

    oauth_params['oauth_version'] = version

    _parse_optional_params(oauth_params, req_kwargs)

    return oauth_params


def get_auth_header(oauth_params, realm=None):
    '''
    Given a dictionary, `oauth_params`, constructs a header string suitable
    for header-based authentication. Returns the auth header string.

    :param oauth_params: A dictionary of OAuth 1.0/a parameters.
    :type oauth_params: dict
    :param realm: Authentication realm, defaults to `None`.
    :type realm: str
    '''
    auth_header = 'OAuth realm="{realm}"'.format(realm=realm or '')
    params = ''

    for k, v in oauth_params.items():
        params += ',{key}="{value}"'.format(key=k, value=quote(str(v)))

    auth_header += params
    return auth_header


def sign(req_kwargs,
         url,
         method,
         consumer_key,
         consumer_secret,
         access_token=None,
         access_token_secret=None,
         header_auth=False,
         realm=None,
         signer=hmac_sha1_signer):
    signature_name = signature_names[signer]

    # ensure we always create new instances of dictionary elements
    for key, value in req_kwargs.items():
        if isinstance(value, dict):
            req_kwargs[key] = deepcopy(value)

    oauth_params = get_params(req_kwargs,
                              consumer_key,
                              signature_name,
                              access_token)

    oauth_params['oauth_signature'] = signer(consumer_secret,
                                             access_token_secret,
                                             method,
                                             url,
                                             oauth_params,
                                             req_kwargs)

    if header_auth:
        return get_auth_header(oauth_params, realm)

    return oauth_params
