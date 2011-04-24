import logging

import oauth2

from django.http import HttpResponse
from django.contrib.auth.models import AnonymousUser

from piston.models import Consumer
from piston.oauth import OAuthError

"""
This is a simple 2-legged OAuth connector for django piston.
Dependencies: 
 - django piston: https://bitbucket.org/jespern/django-piston
 - python-oauth2: https://github.com/simplegeo/python-oauth2
Adapted from example:  
 - http://philipsoutham.com/post/2172924723/two-legged-oauth-in-python
"""


class TwoLeggedOAuthAuthentication(object):
    """
    Two Legged OAuth authenticator. 
    
    This Authentication method checks for a provided HTTP_AUTHORIZATION
    and looks up to see if this is a valid OAuth Consumer
    """
    def __init__(self, realm='API'):
        self.realm = realm

    def is_authenticated(self, request):
        """
        Verify 2-legged oauth request. Parameters accepted as
        values in "Authorization" header, or as a GET request
        or in a POST body.
        """
        logging.info("TwoLeggedOAuthAuthentication")

        oauth_server, oauth_request = initialize_oauth_server_request(request)
        try:
            key = request.GET.get('oauth_consumer_key')
            if not key:
                key = request.POST.get('oauth_consumer_key')
            if not key:
                auth_header_value = request.META.get('HTTP_AUTHORIZATION')
                key = get_oauth_consumer_key_from_header(auth_header_value)
            if not key:
                logging.error('TwoLeggedOAuthAuthentication. No consumer_key found.')
                return None
            # Raises exception if it doesn't pass 
            oauth_server.verify_request(oauth_request, get_consumer(key), None)
            # If OAuth authentication is successful, set oauth_consumer_key on request in case we need it later 
            request.META['oauth_consumer_key'] = key
            return True
        except oauth2.Error, e:
            logging.exception("Error in TwoLeggedOAuthAuthentication.")
            request.user = AnonymousUser()
            return False
        except KeyError, e:
            logging.exception("Error in TwoLeggedOAuthAuthentication.")
            request.user = AnonymousUser()
            return False
        except Exception, e:
            logging.exception("Error in TwoLeggedOAuthAuthentication.")
            return False

        return True

    def challenge(self):
        resp = HttpResponse("OAuth Authorization Required")
        resp['WWW-Authenticate'] = "Token Based Authentication"
        resp.status_code = 401
        return resp


def initialize_oauth_server_request(request):
    """
    OAuth initialization.
    """
    
    # Since 'Authorization' header comes through as 'HTTP_AUTHORIZATION', convert it back
    auth_header = {}
    if 'HTTP_AUTHORIZATION' in request.META:
        auth_header = {'Authorization':request.META.get('HTTP_AUTHORIZATION')}
    
    absolute_uri = request.build_absolute_uri()
    url = absolute_uri
    if absolute_uri.find('?') != -1:
        url = absolute_uri[:absolute_uri.find('?')]
        
    oauth_request = oauth2.Request.from_request(
            request.method, url, headers=auth_header, 
            parameters=dict(request.REQUEST.items()))
        
    if oauth_request:
        oauth_server = oauth2.Server(signature_methods={
            # Supported signature methods
            'HMAC-SHA1': oauth2.SignatureMethod_HMAC_SHA1()
        })

    else:
        oauth_server = None
        
    return oauth_server, oauth_request


def get_oauth_consumer_key_from_header(auth_header_value):
    key = None
    
    # Process Auth Header
    # Check that the authorization header is OAuth.
    if not auth_header_value:
        return None
    if auth_header_value[:6] == 'OAuth ':
        auth_header = auth_header_value[6:]
        try:
            # Get the parameters from the header.
            header_params = oauth2.Request._split_header(auth_header)
            if 'oauth_consumer_key' in header_params:
                key = header_params['oauth_consumer_key']
        except:
            raise Error('Unable to parse OAuth parameters from '
                'Authorization header.')
    return key


def get_consumer(oauth_consumer_key):
    consumer = lookup_consumer(oauth_consumer_key)
    if not consumer:
        raise OAuthError('Invalid consumer.')
    return consumer


def lookup_consumer(key):
    logging.info("lookup_consumer() key: " + repr(key))
    try:
        consumer = Consumer.objects.get(key=key)
        return consumer
    except Consumer.DoesNotExist:
        return None

