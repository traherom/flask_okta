from functools import wraps
import binascii
import json
import logging
import base64
from urllib.parse import urljoin, urlencode

LOG = logging.getLogger(__name__)

import requests
import jwt
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import current_app, make_response, request

# Find the stack on which we want to store the database connection.
# Starting with Flask 0.9, the _app_ctx_stack is the correct one,
# before that we need to use the _request_ctx_stack.
try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack


class AuthorizationError(Exception):
    """
    User is not authenicated. Generally a more specific exception will be thrown
    """
    pass

class NoAuthorizationError(AuthorizationError):
    """
    Indicates a request contains no authorization header
    """
    pass

class InvalidHeaderError(NoAuthorizationError):
    """
    Indicates the authorization header was invalid
    """
    pass

class TokenInvalidError(AuthorizationError):
    """
    Indicates token did not validate in some way
    """
    pass

class TokenExpiredSignatureError(TokenInvalidError):
    """
    Token is out-of-date
    """
    pass


class OktaOAuth:
    """
    Implements a basic OAuth client with Okta-specific methods to retrieve additional data`
    """
    app = None
    oauth_keys = {}
    redis = None

    def __init__(self, app=None, redis=None):
        """
        Receive Flask app and some configuration items

        If given, redis should be an instance of the py-redis class (or look like it
        a la flask-redis). It will be used for caching of Okta API calls.
        """
        self.redis = redis
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app, redis=None):
        app.config.setdefault('OAUTH_SERVER', None)
        app.config.setdefault('OAUTH_CLIENT_ID', None)
        app.config.setdefault('OAUTH_SECRET', None)
        app.config.setdefault('OAUTH_AUTH_SERVER_NAME', 'default')
        app.config.setdefault('OAUTH_AUTH_SERVER_AUD', 'api://default')
        app.config.setdefault('OAUTH_HEADER_NAME', 'Authorization')
        app.config.setdefault('OAUTH_HEADER_TYPE', 'Bearer')
        app.config.setdefault('OAUTH_VALIDATE', True)
        app.config.setdefault('OKTA_API_TOKEN', None)
        app.config.setdefault('OKTA_CACHE_KEY_PREFIX', 'oktaoauth_')
        app.config.setdefault('OKTA_SUPERUSER_GROUP_ID', None)

        if redis is not None:
            self.redis = redis

    def get_authorization_url(self):
        """
        Returns the authorization server URL in use
        """
        return self._get_discovery_doc()['authorization_endpoint']

    def get_token_url(self):
        """
        Returns the token server URL in use
        """
        return self._get_discovery_doc()['token_endpoint']

    def _get_url(self, *args):
        """
        Takes the server and all given path pieces and combines
        """
        pieces = [current_app.config['OAUTH_SERVER']]
        pieces.extend(args)
        return '/'.join(pieces)

    def _get_auth_server_url(self, *path):
        """
        Returns URL for oauth operations given the final path beyond the auth server name
        """
        return self._get_url('oauth2', current_app.config['OAUTH_AUTH_SERVER_NAME'], *path)

    def _call_api(self, method, *path, **kwargs):
        """
        Calls the Okta API with authentication information provided.

        Assume all API calls start with '/api/v1/'. Returns result as dictionary
        (assumes JSON return) unless an error occurs.

        May cache results unless cache=False is set.
        """
        headers = {
            'Authorization': "SSWS {}".format(current_app.config['OKTA_API_TOKEN']),
        }
        headers.update(kwargs.get('headers', {}))

        # Get from fastest source:
        local_cache = getattr(stack.top, 'okta_api_cache', {})
        url = self._get_url('/api/v1', *path)
        api_key = '{} {} {}'.format(current_app.config['OKTA_CACHE_KEY_PREFIX'], method, url)

        # Local?
        val = local_cache.get(api_key, None)

        # Redis?
        if val is None and self.redis:
            #LOG.debug('Local cache miss for API call %s', api_key)
            val = self.redis.get(api_key)
            if val is not None:
                val = json.loads(val.decode())

        # Okta?
        if val is None:
            LOG.debug('Remote cache miss for API call %s', api_key)
            resp = requests.request(method, url, headers=headers)
            resp.raise_for_status()
            val = resp.json()

            # Cache on Redis now only. Don't want to push if we just got the exact same value from redis
            if self.redis:
                self.redis.setex(api_key, 300, json.dumps(val))

        # Update local cache
        local_cache[api_key] = val
        stack.top.okta_api_cache = local_cache

        return val

    def _get_discovery_doc(self):
        """
        Get OAuth discovery document
        """
        if not hasattr(self, 'oauth_discovery_doc'):
            well_known_url = self._get_auth_server_url('.well-known/openid-configuration')
            LOG.info('Getting OAuth discovery document from %s', well_known_url)
            self.oauth_discovery_doc = requests.get(well_known_url).json()

        return self.oauth_discovery_doc

    def get_public_keys(self):
        """
        Retrieve access token signing keys from provider
        """
        jwks_uri = self._get_discovery_doc()['jwks_uri']
        return requests.get(
            jwks_uri,
            params={
                'client_id': current_app.config['OAUTH_CLIENT_ID'],
            },
        ).json()

    def exchange_auth_code_for_token(self, code, redirect_uri):
        """
        Takes an auth code (ie, from the widget) and returns access/id tokens
        """
        if not code:
            raise ValueError('Auth code may not be blank')

        #token_endpoint = self._get_discovery_doc()['token_endpoint']
        token_endpoint = self.get_token_url()
        return requests.post(
            token_endpoint,
            data=urlencode({
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': redirect_uri,
            }),
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            auth=(current_app.config['OAUTH_CLIENT_ID'], current_app.config['OAUTH_SECRET']),
        ).json()

    def _get_jwt(self):
        """
        Get and validate JWT
        """
        header_name = current_app.config['OAUTH_HEADER_NAME']
        header_type = current_app.config['OAUTH_HEADER_TYPE']

        # Verify we have the auth header
        jwt_header = request.headers.get(header_name, None)
        if not jwt_header:
            raise NoAuthorizationError("Missing {} Header".format(header_name))

        # Make sure the header is in a valid format that we are expecting, ie
        # <HeaderName>: <HeaderType(optional)> <JWT>
        parts = jwt_header.split()
        if not header_type:
            if len(parts) != 1:
                msg = "Bad {} header. Expected value '<JWT>'".format(header_name)
                raise InvalidHeaderError(msg)
            token = parts[0]
        else:
            if parts[0] != header_type or len(parts) != 2:
                msg = "Bad {} header. Expected value '{} <JWT>'".format(header_name, header_type)
                raise InvalidHeaderError(msg)
            token = parts[1]

        # Get the ID of the key we need to verify it
        validate = current_app.config.get('OAUTH_VALIDATE', True)
        if validate:
            header = self._get_jwt_header(token)
            LOG.debug('Expecting signing key "%s"', header['kid'])
            key, alg = self._get_signing_key(header['kid'])
        else:
            key = None
            alg = None

        # Decode and verify JWS and expiration time
        try:
            decoded = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=current_app.config['OAUTH_AUTH_SERVER_AUD'],
                issuer=self._get_auth_server_url(),
                verify=validate,
            )
        except jwt.ExpiredSignatureError as e:
            raise TokenExpiredSignatureError(str(e))

        # Verify cid (client id) claim is your client id.
        if decoded.get('cid') != current_app.config['OAUTH_CLIENT_ID']:
            raise TokenInvalidError('CID does not match')

        return decoded

    def _get_jwt_header(self, token):
        """
        Returns the header as a dict
        """
        if isinstance(token, str):
            token = token.encode('utf-8')

        if not issubclass(type(token), bytes):
            raise TokenInvalidError("Invalid token type. Token must be a {0}".format(bytes))

        try:
            signing_input, crypto_segment = token.rsplit(b'.', 1)
            header_segment, payload_segment = signing_input.split(b'.', 1)
        except ValueError:
            raise TokenInvalidError('Not enough segments')

        try:
            header_data = jwt.utils.base64url_decode(header_segment)
        except (TypeError, binascii.Error):
            raise TokenInvalidError('Invalid header padding')

        try:
            header = json.loads(header_data.decode('utf-8'))
        except ValueError as e:
            raise TokenInvalidError('Invalid header string: %s' % e)

        return header

    def _get_signing_key(self, kid):
        """
        Returns the signature key and algorithm for the given ID as tuple

        If the key is not found, attempts to refresh the cache from OAuth provider
        """
        if kid is None:
            raise TokenInvalidError('Not signing key specified in JWT header')

        try:
            return self.oauth_keys[kid]
        except (KeyError, AttributeError):
            LOG.warn('KID not found on initial lookup, refreshing cache')
            self.oauth_keys = self._build_signing_key_cache()

            try:
                return self.oauth_keys[kid]
            except KeyError:
                LOG.debug('KID %s not found in %s', kid, self.oauth_keys)
                raise TokenInvalidError('Signing key not found')

    def _build_signing_key_cache(self):
        """
        Gets latest signing keys from Okta
        """
        LOG.info('Refeshing OAuth signing key cache')

        key_return = self.get_public_keys()

        keys = self.get_public_keys().get('keys', [])
        LOG.debug('Signing keys: %s', keys)

        key_cache = {}
        for k in keys:
            if k.get('use') == 'sig':
                # Convert from e and n to an RSAPublicKey
                if k.get('kty') != 'RSA':
                    raise ValueError('Unable to handle non-RSA keys (got kty "{}")'.format(k.get('kty')))

                e = k.get('e').encode()
                n = k.get('n').encode()
                e = int(binascii.hexlify(jwt.utils.base64url_decode(e)), 16)
                n = int(binascii.hexlify(jwt.utils.base64url_decode(n)), 16)

                rsa_key = rsa.RSAPublicNumbers(e, n).public_key(cryptography.hazmat.backends.default_backend())

                key_cache[k.get('kid')] = (rsa_key, k.get('alg'))

        # Cache
        return key_cache

    def token_required(self, fn):
        """
        Decorator that ensures request contains a valid JWT token
        """
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Force-fetch current_token, which will cache for future use
            self.current_token
            return fn(*args, **kwargs)
        return wrapper

    @property
    def current_token(self):
        """
        Returns current token, if available. Returns None otherwise
        """
        if not hasattr(stack.top, 'jwt'):
            stack.top.jwt = self._get_jwt()
        return stack.top.jwt

    def _get_uid(self, token=None, uid=None):
        """
        Helper to get best-offered UID

        If no token is given, uses current_token
        """
        if uid is None:
            if token is None:
                token = self.current_token
            if not token:
                raise NoAuthorizationError('Unable to get user, no token or user ID found')
            uid = token['uid']
        return uid

    def get_user(self, token=None, uid=None):
        """
        Okta specific: Retrieves user info from Okta

        If no token is given, uses current_token
        """
        uid = self._get_uid(token, uid)
        return self._call_api('GET', 'users', uid)

    def get_user_id(self, token=None, uid=None):
        """
        Get ID of current user

        If no token is given, uses current_token
        """
        return self._get_uid(token, uid)

    def get_user_name(self, token=None, uid=None):
        """
        Okta specific: Retrieves user info from Okta

        If no token is given, uses current_token
        """
        user = self.get_user(token, uid)
        profile = user.get('profile', {})
        return f'{profile.get("firstName", "")} {profile.get("lastName", "")}'.strip()

    def get_user_groups(self, token=None, uid=None):
        """
        Okta specific: Retrieves user groups from Okta

        If no token is given, uses current_token
        """
        uid = self._get_uid(token, uid)
        return self._call_api('GET', 'users', uid, 'groups')

    def get_user_group_ids(self, token=None, uid=None):
        """
        Okta specific: Retrieves user groups IDs from Okta.

        Skips built-in okta groups to prevent "Everyone" from being included

        If no token is given, uses current_token
        """
        groups = self.get_user_groups(token, uid)
        return [g['id'] for g in groups if g.get('type') != 'BUILT_IN']

    def get_user_is_superuser(self, token=None, uid=None):
        """
        Returns true if the user is a superuser who has all privileges
        """
        if current_app.config['OKTA_SUPERUSER_GROUP_ID'] is None:
            LOG.warn('OKTA_SUPERUSER_GROUP_ID not set, no users will be marked as superusers')
            return False

        groups = self.get_user_group_ids(token, uid)
        return current_app.config['OKTA_SUPERUSER_GROUP_ID'] in groups

    def get_group(self, gid):
        """
        Returns group information
        """
        return self._call_api('GET', 'groups', gid)

    def get_group_name(self, gid):
        """
        Returns group name
        """
        return self.get_group(gid)['profile']['name']
