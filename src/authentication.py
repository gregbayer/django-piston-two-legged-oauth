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
        logging.info("TwoLeggedOAuthAuthentication request: " + repr(request))
        
        auth_header = {}
        if 'HTTP_AUTHORIZATION' in request.META:
            auth_header = {'Authorization':request.META.get('HTTP_AUTHORIZATION')}

        oauth_server, oauth_request = initialize_server_request(request)
        try:
            oauth_server.verify_request(oauth_request, 
                get_consumer(request.GET.get('oauth_consumer_key')),
                None)
            return True
        except oauth2.Error:
            logging.exception("Error in TwoLeggedOAuthAuthentication.")
            request.user = AnonymousUser()
            return False
        except KeyError:
            logging.exception("Error in TwoLeggedOAuthAuthentication.")
            request.user = AnonymousUser()
            return False

        return True

    def challenge(self):
        resp = HttpResponse("OAuth Authorization Required")
        resp['WWW-Authenticate'] = "Token Based Authentication"
        resp.status_code = 401
        return resp


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


def initialize_server_request(request):
    """
    Shortcut for initialization.
    """
    absolute_uri = request.build_absolute_uri()
    if absolute_uri.find('?') != -1:
        url = absolute_uri[:absolute_uri.find('?')]
    logging.info("url: " + url)
    oauth_request = oauth2.Request.from_request(
            request.method, url, headers=request.META, 
            parameters=dict(request.REQUEST.items()))
        
    if oauth_request:
        oauth_server = oauth2.Server(signature_methods={
            # Supported signature methods
            'HMAC-SHA1': oauth2.SignatureMethod_HMAC_SHA1()
        })

    else:
        oauth_server = None
        
    return oauth_server, oauth_request


