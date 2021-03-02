# -*- coding: utf-8 -*- 
################################################################################
# ZMSPASDangerousCookieAuthPlugin.py
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
################################################################################
""" Class: ZMSPASDangerousCookieAuthPlugin

$Id$
"""

from __future__ import absolute_import
from __future__ import print_function
from base64 import encodestring, decodestring
import binascii
from binascii import Error
from six.moves.urllib.parse import quote, unquote

from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.Permissions import view
from AccessControl.class_init import InitializeClass

from DateTime.DateTime import DateTime

from OFS.Folder import Folder
from zope.interface import Interface

from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PageTemplates.ZopePageTemplate import ZopePageTemplate

from Products.PluggableAuthService.interfaces.plugins import ILoginPasswordHostExtractionPlugin
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IRolesPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import ICredentialsResetPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserAdderPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements


class IZMSPASDangerousCookieAuthPlugin(Interface):
    """ Marker interface.
    """

manage_addZMSPASDangerousCookieAuthPluginForm = PageTemplateFile(
    'www/zpdcapAdd', globals(), __name__='manage_addZMSPASDangerousCookieAuthPluginForm')


def addZMSPASDangerousCookieAuthPlugin( dispatcher
                       , id
                       , title=None
                       , cookie_name=''
                       , REQUEST=None
                       ):
    """ Add a Dangerous Cookie Auth Plugin to a Pluggable Auth Service. """
    sp = ZMSPASDangerousCookieAuthPlugin(id, title, cookie_name)
    dispatcher._setObject(sp.getId(), sp)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace'
                                      '?manage_tabs_message='
                                      'ZMSPASDangerousCookieAuthPluginr+added.'
                                    % dispatcher.absolute_url() )


class ZMSPASDangerousCookieAuthPlugin(Folder, BasePlugin):
    """ Multi-plugin for managing details of Dangerouse Cookie Authentication. """

    meta_type = 'ZMS PluggableAuthService Dangerous Cookie Auth Plugin'
    cookie_name = '__ginger_snap'
    security = ClassSecurityInfo()

    mock = PageTemplateFile('www/zpdcapMock', globals())

    _properties = ( { 'id'    : 'title'
                    , 'label' : 'Title'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  , { 'id'    : 'cookie_name'
                    , 'label' : 'Cookie Name'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  , { 'id'     : 'secret_key'
                    , 'label'  : 'Secret Key'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': ''
                    }
                  )

    manage_options = ( BasePlugin.manage_options[:1]
                     + Folder.manage_options[:1]
                     + Folder.manage_options[2:]
                     )

    def __init__(self, id, title=None, cookie_name='', cookie_validity=600):
        self._setId(id)
        self.title = title
        self.secret_key = ''
        self.cookie_name = cookie_name
        self.cookie_validity = int(cookie_validity)


    def getSecretKey(self):
        from cryptography.fernet import Fernet
        if not getattr(self,'secret_key',''):
            self.secret_key = Fernet.generate_key()
        return self.secret_key
        
    
    def mockCookie(self, REQUEST):
        """ mockCookie """
        token = None
        if REQUEST.has_key('d'):
          d = REQUEST.get('d','').strip()
          if d.startswith('{') and d.endswith('}'):
            d = eval('(%s)'%d)
            if type(d) is dict:
              token = self.encryptCookie(d)
        if token:
            path = self.getPhysicalPath()
            path = path[:path.index('acl_users')]
            REQUEST.RESPONSE.setCookie(self.cookie_name, token,path='/'.join(path))
        elif self.cookie_name in REQUEST.cookies:
            REQUEST.RESPONSE.expireCookie(self.cookie_name)             
        return REQUEST.RESPONSE.redirect(REQUEST['HTTP_REFERER'])


    def encryptCookie(self, d):
        from itsdangerous import URLSafeSerializer
        auth_s = URLSafeSerializer(self.getSecretKey())
        token = auth_s.dumps(d)
        return token


    def decryptCookie(self, token):
        try:
            from itsdangerous import URLSafeSerializer
            auth_s = URLSafeSerializer(self.getSecretKey())
            d = auth_s.loads(token)
            return d
        except:
            return None


    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        """ Extract credentials from cookie or 'request'. """
        token = request.get(self.cookie_name, '')
        creds = self.decryptCookie(token)
        if creds:
            creds['remote_host'] = request.get('REMOTE_HOST', '')
            try:
                creds['remote_address'] = request.getClientAddr()
            except AttributeError:
                creds['remote_address'] = request.get('REMOTE_ADDR', '')
        return creds


    security.declarePrivate('challenge')
    def challenge(self, request, response, **kw):
        """ Challenge the user for credentials. """
        return self.unauthorized()


    #
    #    ICredentialsResetPlugin implementation
    #
    security.declarePrivate('resetCredentials')
    def resetCredentials(self, request, response):
        """ user has logged out.
        """
        # Clear Zope-Session.
        response.expireCookie(_ZopeId, path='/')
        # Reset Cookie.
        response.expireCookie(self.cookie_name, path='/')


    security.declarePrivate('unauthorized')
    def unauthorized(self):
        req = self.REQUEST
        resp = req['RESPONSE']

        # If we set the auth cookie before, delete it now.
        if self.cookie_name in resp.cookies:
            del resp.cookies[self.cookie_name]

        # Could not challenge.
        return 0


    #
    #    IAuthenticationPlugin implementation
    #
    security.declarePrivate( 'authenticateCredentials' )
    def authenticateCredentials( self, credentials, request=None ):

        """ See IAuthenticationPlugin.
        """
        request = self.REQUEST
        token = request.get(self.cookie_name, '')
        creds = self.decryptCookie(token)
        id = creds.get('id',creds.get('login',None))
        user_name = creds.get('name',id)
        # Check valid-until against current timestamp.
        valid_until = DateTime(creds['valid_until'])
        if valid_until.timeTime() < DateTime().timeTime():
            return None
        # Update valid-until timestamp.
        creds['valid_until'] = DateTime(DateTime().timeTime()+self.cookie_validity).ISO8601()
        token = self.encryptCookie(creds)
        path = self.getPhysicalPath()
        path = path[:path.index('acl_users')]
        request.RESPONSE.setCookie(self.cookie_name, token,path='/'.join(path))
        return (id, user_name)


    #
    #    IRolesPlugin implementation
    #
    security.declarePrivate( 'getRolesForPrincipal' )
    def getRolesForPrincipal( self, principal, request=None):
        """ See IAuthenticationPlugin.
        """
        roles = []
        token = request.get(self.cookie_name, '')
        creds = self.decryptCookie(token)
        id = creds.get('id',creds.get('login',None))
        user_name = creds.get('name',id)
        if principal.getId() == id and principal.getUserName() == user_name:
          roles.extend(creds.get('roles',[]))
        return roles


    #
    #    IUserAdderPlugin implementation
    #
    security.declarePrivate( 'doAddUser' )
    def doAddUser(self, login, password):
        """ Add a user record to a User Manager, with the given login
            and password.  It is up to the implementation to determine
            if the login is used as user id as well.

        o Return a Boolean indicating whether a user was added or not
        """
        logins = getattr(self,'_logins',[])
        if login not in logins:
          logins.append(login)
          self._logins = logins
        return True


    #
    #    IUserEnumerationPlugin implementation
    #
    security.declarePrivate( 'enumerateUsers' )
    def enumerateUsers(self, id=None, login=None, exact_match=False, sort_by=None,
                       max_results=None, **kw):
        """ -> (user_info_1, ... user_info_N)

        o Return mappings for users matching the given criteria.

        o 'id' or 'login', in combination with 'exact_match' true, will
          return at most one mapping per supplied ID ('id' and 'login'
          may be sequences).

        o If 'exact_match' is False, then 'id' and / or login may be
          treated by the plugin as "contains" searches (more complicated
          searches may be supported by some plugins using other keyword
          arguments).

        o If 'sort_by' is passed, the results will be sorted accordingly.
          known valid values are 'id' and 'login' (some plugins may support
          others).

        o If 'max_results' is specified, it must be a positive integer,
          limiting the number of returned mappings.  If unspecified, the
          plugin should return mappings for all users satisfying the criteria.

        o Minimal keys in the returned mappings:

          'id' -- (required) the user ID, which may be different than
                  the login name

          'login' -- (required) the login name

          'pluginid' -- (required) the plugin ID (as returned by getId())

          'editurl' -- (optional) the URL to a page for updating the
                       mapping's user

        o Plugin *must* ignore unknown criteria.

        o Plugin may raise ValueError for invalid criteria.

        o Insufficiently-specified criteria may have catastrophic
          scaling issues for some implementations.
        """
        logins = getattr(self,'_logins',[])
        return [{'id':x,'login':x,'pluginid':self.getId()} for x in logins]


classImplements( ZMSPASDangerousCookieAuthPlugin
               , IZMSPASDangerousCookieAuthPlugin
               , ILoginPasswordHostExtractionPlugin
               , IAuthenticationPlugin
               , IRolesPlugin
               , IChallengePlugin
               , ICredentialsResetPlugin
               , IUserAdderPlugin
               , IUserEnumerationPlugin
               )

InitializeClass(ZMSPASDangerousCookieAuthPlugin)
