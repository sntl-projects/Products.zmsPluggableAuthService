# -*- coding: utf-8 -*- 
################################################################################
# __init__.py
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
from __future__ import absolute_import
from AccessControl.Permissions import manage_users as ManageUsers

from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin

from Products.zmsPluggableAuthService.plugins import ZMSPASCookieAuthHelper, ZMSPASSsoPlugin, ZMSPASRolePlugin, ZMSPASUserPlugin

registerMultiPlugin(ZMSPASCookieAuthHelper.ZMSPASCookieAuthHelper.meta_type)
registerMultiPlugin(ZMSPASSsoPlugin.ZMSPASSsoPlugin.meta_type)
registerMultiPlugin(ZMSPASRolePlugin.ZMSPASRolePlugin.meta_type)
registerMultiPlugin(ZMSPASUserPlugin.ZMSPASUserPlugin.meta_type)

def initialize(context):

    context.registerClass( ZMSPASSsoPlugin.ZMSPASSsoPlugin
                         , permission=ManageUsers
                         , constructors=(
                            ZMSPASSsoPlugin.manage_addZMSPASSsoPluginForm,
                            ZMSPASSsoPlugin.addZMSPASSsoPlugin, )
                         , visibility=None
                         , icon='plugins/www/plug.svg'
                         )

    context.registerClass( ZMSPASCookieAuthHelper.ZMSPASCookieAuthHelper
                         , permission=ManageUsers
                         , constructors=(
                            ZMSPASCookieAuthHelper.manage_addZMSPASCookieAuthHelperForm,
                            ZMSPASCookieAuthHelper.addZMSPASCookieAuthHelper, )
                         , visibility=None
                         , icon='plugins/www/plug.svg'
                         )

    context.registerClass( ZMSPASRolePlugin.ZMSPASRolePlugin
                         , permission=ManageUsers
                         , constructors=(
                            ZMSPASRolePlugin.manage_addZMSPASRolePluginForm,
                            ZMSPASRolePlugin.addZMSPASRolePlugin, )
                         , visibility=None
                         , icon='plugins/www/plug.svg'
                         )

    context.registerClass( ZMSPASUserPlugin.ZMSPASUserPlugin
                         , permission=ManageUsers
                         , constructors=(
                            ZMSPASUserPlugin.manage_addZMSPASUserPluginForm,
                            ZMSPASUserPlugin.addZMSPASUserPlugin, )
                         , visibility=None
                         , icon='plugins/www/plug.svg'
                         )
