# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import ctypes
import os
import sys

import ida_auto
import ida_diskio
import ida_idp
import ida_kernwin
import ida_netnode

from PyQt5.QtCore import QCoreApplication, QFileInfo  # noqa: I202

from .hooks import HexRaysHooks, IDBHooks, IDPHooks
from ..module import Module
from ..shared.commands import (
    JoinSession,
    LeaveSession,
    ListDatabases,
    UpdateLocation,
)

if sys.version_info > (3,):
    long = int


class Core(Module):
    """
    This is the core module. It is responsible for interacting with the IDA
    kernel. It will handle hooking, sending, and replaying of user events.
    """

    NETNODE_NAME = "$ idarling"

    @staticmethod
    def get_ida_dll(app_name=None):
        if app_name is None:
            app_path = QCoreApplication.applicationFilePath()
            app_name = QFileInfo(app_path).fileName()
        idaname = "ida64" if "64" in app_name else "ida"
        if sys.platform == "win32":
            dllname, dlltype = idaname + ".dll", ctypes.windll
        elif sys.platform in ["linux", "linux2"]:
            dllname, dlltype = "lib" + idaname + ".so", ctypes.cdll
        elif sys.platform == "darwin":
            dllname, dlltype = "lib" + idaname + ".dylib", ctypes.cdll
        dllpath = ida_diskio.idadir(None)
        if not os.path.exists(os.path.join(dllpath, dllname)):
            dllpath = dllpath.replace("ida64", "ida")
        return dlltype[os.path.join(dllpath, dllname)]

    def __init__(self, plugin):
        super(Core, self).__init__(plugin)
        self._project = None
        self._database = None
        self._tick = 0
        self._users = {}

        self._idb_hooks = None
        self._idp_hooks = None
        self._hxe_hooks = None

        self._idb_hooks_core = None
        self._idp_hooks_core = None
        self._ui_hooks_core = None
        self._view_hooks_core = None
        self._hooked = False

    @property
    def project(self):
        return self._project

    @project.setter
    def project(self, project):
        self._project = project
        self.save_netnode()

    @property
    def database(self):
        return self._database

    @database.setter
    def database(self, database):
        self._database = database
        self.save_netnode()

    @property
    def tick(self):
        return self._tick

    @tick.setter
    def tick(self, tick):
        self._tick = tick
        self.save_netnode()

    def add_user(self, name, user):
        self._users[name] = user
        self._plugin.interface.painter.refresh()
        self._plugin.interface.widget.refresh()

    def remove_user(self, name):
        user = self._users.pop(name)
        self._plugin.interface.painter.refresh()
        self._plugin.interface.widget.refresh()
        return user

    def get_user(self, name):
        return self._users[name]

    def get_users(self):
        return self._users

    def _install(self):
        # Instantiate the hooks
        self._idb_hooks = IDBHooks(self._plugin)
        self._idp_hooks = IDPHooks(self._plugin)
        self._hxe_hooks = HexRaysHooks(self._plugin)

        core = self
        self._plugin.logger.debug("Installing core hooks")

        class IDBHooksCore(ida_idp.IDB_Hooks):
            def closebase(self):
                core._plugin.logger.trace("Closebase hook")
                core.leave_session()
                core.save_netnode()

                core.project = None
                core.database = None
                core.ticks = 0
                return 0

        self._idb_hooks_core = IDBHooksCore()
        self._idb_hooks_core.hook()

        class IDPHooksCore(ida_idp.IDP_Hooks):
            def ev_get_bg_color(self, color, ea):
                core._plugin.logger.trace("Get bg color hook")
                value = core._plugin.interface.painter.get_bg_color(ea)
                if value is not None:
                    ctypes.c_uint.from_address(long(color)).value = value
                    return 1
                return 0

            def ev_auto_queue_empty(self, arg):
                core._plugin.logger.debug("Auto queue empty hook")
                if ida_auto.get_auto_state() == ida_auto.AU_NONE:
                    client = core._plugin.network.client
                    if client:
                        client.call_events()
                return super(self.__class__, self).ev_auto_queue_empty(arg)

        self._idp_hooks_core = IDPHooksCore()
        self._idp_hooks_core.hook()

        class UIHooksCore(ida_kernwin.UI_Hooks):
            def ready_to_run(self):
                core._plugin.logger.trace("Ready to run hook")
                core.load_netnode()
                core.join_session()
                core._plugin.interface.painter.ready_to_run()

            def get_ea_hint(self, ea):
                core._plugin.logger.trace("Get ea hint hook")
                return core._plugin.interface.painter.get_ea_hint(ea)

            def widget_visible(self, widget):
                core._plugin.logger.trace("Widget visible")
                core._plugin.interface.painter.widget_visible(widget)

        self._ui_hooks_core = UIHooksCore()
        self._ui_hooks_core.hook()

        class ViewHooksCore(ida_kernwin.View_Hooks):
            def view_loc_changed(self, view, now, was):
                core._plugin.logger.trace("View loc changed hook")
                if now.plce.toea() != was.plce.toea():
                    name = core._plugin.config["user"]["name"]
                    color = core._plugin.config["user"]["color"]
                    core._plugin.network.send_packet(
                        UpdateLocation(name, now.plce.toea(), color)
                    )

        self._view_hooks_core = ViewHooksCore()
        self._view_hooks_core.hook()
        return True

    def _uninstall(self):
        self._plugin.logger.debug("Uninstalling core hooks")
        self._idb_hooks_core.unhook()
        self._ui_hooks_core.unhook()
        self._view_hooks_core.unhook()
        self.unhook_all()
        return True

    def hook_all(self):
        """Install all the user events hooks."""
        if self._hooked:
            return

        self._plugin.logger.debug("Installing hooks")
        self._idb_hooks.hook()
        self._idp_hooks.hook()
        self._hxe_hooks.hook()
        self._hooked = True

    def unhook_all(self):
        """Uninstall all the user events hooks."""
        if not self._hooked:
            return

        self._plugin.logger.debug("Uninstalling hooks")
        self._idb_hooks.unhook()
        self._idp_hooks.unhook()
        self._hxe_hooks.unhook()
        self._hooked = False

    def load_netnode(self):
        """
        Load data from our custom netnode. Netnodes are the mechanism used by
        IDA to load and save information into a database. IDArling uses its own
        netnode to remember which project and database a database belongs to.
        """
        node = ida_netnode.netnode(Core.NETNODE_NAME, 0, True)

        self._project = node.hashstr("project") or None
        self._database = node.hashstr("database") or None
        self._tick = int(node.hashstr("tick") or "0")

        self._plugin.logger.debug(
            "Loaded netnode: project=%s, database=%s, tick=%d"
            % (self._project, self._database, self._tick)
        )

    def save_netnode(self):
        """Save data into our custom netnode."""
        node = ida_netnode.netnode(Core.NETNODE_NAME, 0, True)

        # node.hashset does not work anymore with direct string
        # use of hashet_buf instead
        # (see https://github.com/idapython/src/blob/master/swig/netnode.i#L162)
        if self._project:
            node.hashset_buf("project", str(self._project))
        if self._database:
            node.hashset_buf("database", str(self._database))
        if self._tick:
            node.hashset_buf("tick", str(self._tick))

        self._plugin.logger.debug(
            "Saved netnode: project=%s, database=%s, tick=%d"
            % (self._project, self._database, self._tick)
        )

    def join_session(self):
        """Join the collaborative session."""
        self._plugin.logger.debug("Joining session")
        if self._project and self._database:

            def databases_listed(reply):
                if any(d.name == self._database for d in reply.databases):
                    self._plugin.logger.debug("Database is on the server")
                else:
                    self._plugin.logger.debug("Database is not on the server")
                    return  # Do not go further

                name = self._plugin.config["user"]["name"]
                color = self._plugin.config["user"]["color"]
                ea = ida_kernwin.get_screen_ea()
                self._plugin.network.send_packet(
                    JoinSession(
                        self._project,
                        self._database,
                        self._tick,
                        name,
                        color,
                        ea,
                    )
                )
                self.hook_all()
                self._users.clear()

            d = self._plugin.network.send_packet(
                ListDatabases.Query(self._project)
            )
            if d:
                d.add_callback(databases_listed)
                d.add_errback(self._plugin.logger.exception)

    def leave_session(self):
        """Leave the collaborative session."""
        self._plugin.logger.debug("Leaving session")
        if self._project and self._database:
            name = self._plugin.config["user"]["name"]
            self._plugin.network.send_packet(LeaveSession(name))
            self._users.clear()
            self.unhook_all()
