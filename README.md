# About

django-piston-two-legged-oauth is a simple 2-legged OAuth connector for Django Piston.


# Dependencies: 
* [django piston](https://bitbucket.org/jespern/django-piston)
* [python-oauth2](https://github.com/simplegeo/python-oauth2)


# Adapted from example:  
* [two-legged-oauth-in-python](http://philipsoutham.com/post/2172924723/two-legged-oauth-in-python)


# Related discussions:
* [django piston 2-legged OAuth authentication discussion](http://groups.google.com/group/django-piston/browse_thread/thread/7e6cff72a75013ce)
* [Beginner’s Guide to OAuth – Part II : Protocol Workflow](http://hueniverse.com/2007/10/beginners-guide-to-oauth-part-ii-protocol-workflow/)

# Example

\# urls.py

    from api.authentication import TwoLeggedOAuthAuthentication
    from api.handlers import DoSomethingHandler

    two_legged_oauth = TwoLeggedOAuthAuthentication(realm='API')

    class CsrfExemptResource( Resource ):
        def __init__( self, handler, authentication = None ):
            super( CsrfExemptResource, self ).__init__( handler, authentication )
            self.csrf_exempt = getattr( self.handler, 'csrf_exempt', True )

    def TwoLeggedOAuthAProtectedResource(handler):
        return CsrfExemptResource(handler=handler, authentication=two_legged_oauth)

    do_something = TwoLeggedOAuthAProtectedResource( DoSomethingHandler )

    urlpatterns = patterns('',
        url( r'^do_something', do_something, name='do_something'),
    )

