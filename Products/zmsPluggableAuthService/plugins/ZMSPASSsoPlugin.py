# -*- coding: utf-8 -*- 
################################################################################
# ZMSPASSsoPlugin.py
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
""" Class: ZMSPASSsoPlugin

$Id$
"""

import logging
import re

try:
  from urllib.parse import quote
except ImportError:
  # Py2
  from urllib import quote


from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.class_init import InitializeClass

from OFS.Folder import Folder
from zope.interface import Interface

from Products.PageTemplates.PageTemplateFile import PageTemplateFile

from Products.PluggableAuthService.interfaces.plugins import ILoginPasswordHostExtractionPlugin
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import ICredentialsResetPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserAdderPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from Products.PluggableAuthService.interfaces.plugins import IRolesPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements

logger = logging.getLogger('ZMSPASSsoPlugin')

class IZMSPASSsoPlugin(Interface):
    """ Marker interface.
    """

manage_addZMSPASSsoPluginForm = PageTemplateFile(
    'www/zpssopAdd', globals(), __name__='manage_addZMSPASSsoPluginForm')


def addZMSPASSsoPlugin( dispatcher
                       , id
                       , title=None
                       , header_name=''
                       , login_path=''
                       , REQUEST=None
                       ):
    """ Add a SSO Plugin to a Pluggable Auth Service. """
    sp = ZMSPASSsoPlugin(id, title, header_name, login_path)
    dispatcher._setObject(sp.getId(), sp)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace'
                                      '?manage_tabs_message='
                                      'ZMSPASSsoPluginr+added.'
                                    % dispatcher.absolute_url() )

import logging
from functools import wraps
def logg_exception(wrapped):
  @wraps(wrapped)
  def wrapper(*args, **kwargs):
    try:
      return wrapped(*args, **kwargs)
    except:
      logging.exception('Logging otherwise swallowed exception')
      raise
  return wrapper

class ZMSPASSsoPlugin(Folder, BasePlugin):
    """ Multi-plugin for managing details of SSO Authentication. """

    meta_type = 'ZMS PluggableAuthService SSO Plugin'
    zmi_icon = 'fas fa-cookie-bite text-danger'
    zmi_show_add_dialog = True
    header_name = '__ginger_snap'
    security = ClassSecurityInfo()
    SALT = "zms_auth:login"

    manage_usersForm = PageTemplateFile('www/zpssopUsers', globals())

    _properties = ( { 'id'    : 'title'
                    , 'label' : 'Title'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  , { 'id'    : 'header_name'
                    , 'label' : 'Header Name'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    , 'default': 'HTTP_X_AUTH_RESULT'
                    }
                  , { 'id'     : 'secret_key'
                    , 'label'  : 'Secret Key'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': ''
                    }
                  , { 'id'     : 'login_path'
                    , 'label'  : 'Login Path'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': 'http://zms.hosting/auth/login'
                    }
                  , { 'id'     : 'login_pattern'
                    , 'label'  : 'Login Pattern'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': 'https?:\/\/(.*)\/manage'
                    }
                  , { 'id'     : 'came_from'
                    , 'label'  : 'Came From'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': 'came_from'
                    }
                  , { 'id'     : 'user_id_attrs'
                    , 'label'  : 'User ID Attributes'
                    , 'type'   : 'string'
                    , 'mode'   : 'w'
                    , 'default': 'user_id,sub'
                    }
                  )
    
    manage_options = ( BasePlugin.manage_options[:1]
                     + Folder.manage_options[:1]
                     + Folder.manage_options[2:]
                     + ({'label':'Users','action':'manage_usersForm'},)
                     )

    # Management Permissions.
    # -----------------------
    __viewPermissions__ = (
      'manage_page_header', 'manage_page_footer', 'manage_tabs'
      )
    __ac_permissions__=(
      ('View', __viewPermissions__),
      )

    def __init__(self, id, title=None, header_name='HTTP_X_AUTH_RESULT', login_path='http://zms.hosting/auth/login', login_pattern='https?:\/\/(.*)\/manage', user_id_attrs='user_id,sub'):
        self._setId(id)
        self.title = title
        self.secret_key = ''
        self.header_name = header_name
        self.login_path = login_path
        self.login_pattern = login_pattern
        self.came_from = 'came_from'
        self.user_id_attrs = user_id_attrs


    def getSecretKey(self):
        from cryptography.fernet import Fernet
        if not getattr(self,'secret_key',''):
            self.secret_key = Fernet.generate_key()
        return self.secret_key


    def matchPattern(self, p, s):
      prog = re.compile(p)
      result = prog.match(s)
      return result is not None


    def encryptToken(self, d):
        from itsdangerous import TimedSerializer
        coder = TimedSerializer(secret_key=self.getSecretKey(),salt=self.SALT)
        token = coder.dumps(d)
        return token


    def decryptToken(self, token, debug=False):
        d = {}
        try:
            from itsdangerous import TimedSerializer
            coder = TimedSerializer(secret_key=self.getSecretKey(),salt=self.SALT)
            if token:
                if isinstance(token,str):
                    token = token.decode('utf-8')
                d = coder.loads(token)
        except:
            logger.exception("can't decrypt token")
        return d


    #
    #    IExtractionPlugin implementation
    #
    security.declarePrivate('extractCredentials')
    @logg_exception
    def extractCredentials(self, request):
        """ request -> {...}

        o Return a mapping of any derived credentials.

        o Return an empty mapping to indicate that the plugin found no
          appropriate credentials.
        """
        logger.debug("ZMSPASSsoPlugin.extractCredentials")
        creds = {}

        login_pw = request._authUserPW()
        if login_pw is not None:
            name, password = login_pw
            creds['login'] = name
            creds['password'] = password
        
        else:

          # Mockup
          if getattr(self, "mockup", False):
              header = request.cookies.get(self.header_name,None)
              if header:
                token = eval(header)
                username = token["user_id"]
                logger.debug("ZMSPASSsoPlugin.extractCredentials: username=%s"%str(username))
                creds['login'] = username
                creds['password'] = "secret"
                return creds

          token = request.get(self.header_name, '')
          decoded_token = self.decryptToken(token)
          creds = decoded_token
        
        if creds:
            creds['remote_host'] = request.get('REMOTE_HOST', '')
            try:
                creds['remote_address'] = request.getClientAddr()
            except AttributeError:
                creds['remote_address'] = request.get('REMOTE_ADDR', '')
        
        return creds


    #
    #    IChallengePlugin implementation
    #
    security.declarePrivate('challenge')
    @logg_exception
    def challenge(self, request, response, **kw):
        """ Assert via the response that credentials will be gathered.

        Takes a REQUEST object and a RESPONSE object.

        Returns True if it fired, False otherwise.

        Two common ways to initiate a challenge:

          - Add a 'WWW-Authenticate' header to the response object.

            NOTE: add, since the HTTP spec specifically allows for
            more than one challenge in a given response.

          - Cause the response object to redirect to another URL (a
            login form page, for instance)
        """
        logger.debug("ZMSPASSsoPlugin.challenge")
        request = self.REQUEST
        resp = request['RESPONSE']

        # Redirect if desired.
        url = self.getLoginURL()
        if url is not None:
            came_from = request.get('came_from', None)

            if came_from is None:
                came_from = request.get('ACTUAL_URL', '')
                query = request.get('QUERY_STRING')
                if query:
                    if not query.startswith('?'):
                        query = '?' + query
                    came_from = came_from + query
            else:
                # If came_from contains a value it means the user
                # must be coming through here a second time
                # Reasons could be typos when providing credentials
                # or a redirect loop (see below)
                req_url = request.get('ACTUAL_URL', '')

                if req_url and req_url == url:
                    # Oops... The login_form cannot be reached by the user -
                    # it might be protected itself due to misconfiguration -
                    # the only sane thing to do is to give up because we are
                    # in an endless redirect loop.
                    return 0

            if '?' in url:
                sep = '&'
            else:
                sep = '?'

            # Mockup
            if getattr(self, "mockup", False):
                header = request.cookies.get(self.header_name,None)
                if header:
                  token = eval(header)
                  username = token["user_id"]
                  logger.debug("ZMSPASSsoPlugin.challenge: username=%s"%str(username))
                  if username is not None:
                    return 1

            # credentials exist
            token = request.get(self.header_name, '')
            decoded_token = self.decryptToken(token)
            if decoded_token:
                return 1

            # redirect to login_path if login_pattern matches
            if self.matchPattern(self.login_pattern,came_from):
                url = '%s%s%s=%s' % (url, sep, self.came_from, quote(came_from))
                resp.redirect(url, lock=1)
                resp.setHeader('Expires', 'Sat, 01 Jan 2000 00:00:00 GMT')
                resp.setHeader('Cache-Control', 'no-cache')
                return 1

        # Could not challenge.
        return 0


    #
    #    ICredentialsResetPlugin implementation
    #
    security.declarePrivate('resetCredentials')
    def resetCredentials(self, request, response):
        """ user has logged out.
        """
        # Hook for custom reset-credentials.
        try:
          self.customResetCredentials(request,response)
        except:
          logger.debug('can\'t customResetCredentials', exc_info=True)

        # Purge Data of Zope-Session.
        s = request.SESSION
        # s.invalidate()
        try:
          s = self.session_data_manager.getSessionData()
          s.clear()
          s.getBrowserIdManager().flushBrowserIdCookie()
        except:
          logger.debug('can\'t purge Data of Zope-Session', exc_info=True)
        
        # Clear Zope-Session.
        response.expireCookie("_ZopeId", path='/')


    security.declarePrivate('getLoginURL')
    def getLoginURL(self):
        """ Where to send people for logging in """
        if self.login_path.startswith('/') or '://' in self.login_path:
            return self.login_path
        elif self.login_path != '':
            return '%s/%s' % (self.absolute_url(), self.login_path)
        else:
            return None


    #
    #    IAuthenticationPlugin implementation
    #
    security.declarePrivate( 'authenticateCredentials' )
    @logg_exception
    def authenticateCredentials( self, credentials, request=None ):
        """ See IAuthenticationPlugin.
        """
        logger.debug("ZMSPASSsoPlugin.authenticateCredentials")
        request = self.REQUEST

        # Request.
        login_pw = request._authUserPW()
        if login_pw is None:
            # Mockup.
            if getattr(self, "mockup", False):
                header = request.cookies.get(self.header_name,None)
                if header:
                  token = eval(header)
                  username = token["user_id"]
                  logger.debug("ZMSPASSsoPlugin.authenticateCredentials: username=%s"%str(username))
                  return (username, username)

        token = request.get(self.header_name, '')
        user_id_attrs = self.get_user_id_attrs()
        decoded_token = self.decryptToken(token)
        if decoded_token:
          # refresh users
          self.doAddUser(None, None)
          # extract username
          for user_id_attr in user_id_attrs:
            if user_id_attr in decoded_token:
              username = decoded_token.get(user_id_attr,'')
              # ##########################################
              # CAVE: UNIBE SPECIAL (to be generalized!)
              # ##########################################
              if user_id_attr=='preferred_username':
                username = username.split('@')[0]
            logger.debug("ZMSPASSsoPlugin.authenticateCredentials: username=%s"%str((username)))
            return (username, username)
        return None

    def get_user_id_attrs(self):
      if not hasattr(self, 'user_id_attrs'):
        return ['onpremisessamaccountname','preferred_username']
        # self.manage_addProperty('user_id_attrs','onpremisessamaccountname,preferred_username','string')
      return [ x.strip() for x in self.user_id_attrs.split(',') ]

    #
    #    IUserAdderPlugin implementation
    #
    #--security.declarePrivate( 'doAddUser' )
    def doAddUser(self, login, password):
        """ Add a user record to a User Manager, with the given login
            and password.  It is up to the implementation to determine
            if the login is used as user id as well.

        o Return a Boolean indicating whether a user was added or not
        """
        request = self.REQUEST
        token = request.get(self.header_name, '')
        decoded_token = self.decryptToken(token)
        if decoded_token:
          user_id = decoded_token['user_id']
          users = getattr(self,'_users',{})
          if users.get(user_id,{}) != decoded_token:
            users[user_id] = decoded_token
            self._users = users
          return True
        return False

    def removeUser(self, login):
        """ Remove a user record from a User Manager, with the given login.

        o Return a Boolean indicating whether a user was removed or not
        """
        request = self.REQUEST
        token = request.get(self.header_name, '')
        decoded_token = self.decryptToken(token)
        if decoded_token:
          user_id = decoded_token['user_id']
          users = getattr(self,'_users',{})
          if user_id in users:
            del users[user_id]
            self._users = users
          return True
        return False

    def doDeleteUser(self, user_id):
        users = getattr(self,'_users',{})
        if user_id in users:
          del users[user_id]
          self._users = users
          return True
        return False

    #
    #    IUserEnumerationPlugin implementation
    #
    #--security.declarePrivate( 'enumerateUsers' )
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

        # Mockup
        if getattr(self, "mockup", False):
            users = {}
            users["foo"] = {"user_id":"foo","onpremisessamaccountname":"foo"} 
            users["janesmith"] = {"user_id":"janesmith","onpremisessamaccountname":"janesmith"} 
            users["johndoe"] = {"user_id":"johndoe","onpremisessamaccountname":"johndoe"} 
            return [{'id':x['user_id'],'login':x.get('onpremisessamaccountname','') if 'onpremisessamaccountname' in x else x.get('preferred_username','').split('@')[0],'pluginid':self.getId()} for x in users.values()]

        users = getattr(self,'_users',{})
        return [{'id':x['user_id'],'login':x.get('onpremisessamaccountname','') if 'onpremisessamaccountname' in x else x.get('preferred_username','').split('@')[0],'pluginid':self.getId()} for x in users.values()]

    #
    #    IRolesPlugin implementation
    #
    #--security.declarePrivate( 'getRolesForPrincipal' )
    def getRolesForPrincipal( self, principal, request=None ):
        """ See IRolesPlugin.
        """
        roles_attr = getattr(self,'roles_attr','') 
        if roles_attr:
          token = request.get(self.header_name, '')
          decoded_token = self.decryptToken(token)
          if decoded_token:
            return decoded_token.get(roles_attr,[])
        return None


classImplements( ZMSPASSsoPlugin
               , IZMSPASSsoPlugin
               , ILoginPasswordHostExtractionPlugin
               , IAuthenticationPlugin
               , IChallengePlugin
               , ICredentialsResetPlugin
               , IUserAdderPlugin
               , IUserEnumerationPlugin
               , IRolesPlugin
               )

InitializeClass(ZMSPASSsoPlugin)
