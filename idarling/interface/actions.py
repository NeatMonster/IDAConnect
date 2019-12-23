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
from functools import partial
import os
import shutil
import tempfile

import ida_auto
import ida_idaapi
import ida_kernwin
import ida_loader

from PyQt5.QtCore import QCoreApplication, QFileInfo, Qt  # noqa: I202
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QMessageBox, QProgressDialog

from .dialogs import OpenDialog, SaveDialog
from ..shared.commands import DownloadFile, UpdateFile


class Action(object):
    """
    An action is attached to a specific menu, has a custom text, icon, tooltip
    and finally a handler that is called when it is clicked by the user.
    """

    _ACTION_ID = None

    def __init__(self, plugin, menu, text, tooltip, icon, handler):
        super(Action, self).__init__()
        self._plugin = plugin

        self._menu = menu
        self._text = text
        self._tooltip = tooltip
        self._icon = icon
        self._icon_id = ida_idaapi.BADADDR
        self._handler = handler

    @property
    def handler(self):
        return self._handler

    def install(self):
        action_name = self.__class__.__name__

        # Read and load the icon file
        icon_data_fd = open(self._icon, "rb")
        icon_data = icon_data_fd.read()
        icon_data_fd.close()
        self._icon_id = ida_kernwin.load_custom_icon(data=icon_data)

        # Create the action descriptor
        action_desc = ida_kernwin.action_desc_t(
            self._ACTION_ID,
            self._text,
            self._handler,
            None,
            self._tooltip,
            self._icon_id,
        )

        # Register the action using its descriptor
        result = ida_kernwin.register_action(action_desc)
        if not result:
            raise RuntimeError("Failed to register action %s" % action_name)

        # Attach the action to the chosen menu
        result = ida_kernwin.attach_action_to_menu(
            self._menu, self._ACTION_ID, ida_kernwin.SETMENU_APP
        )
        if not result:
            action_name = self.__class__.__name__
            raise RuntimeError("Failed to install action %s" % action_name)

        self._plugin.logger.debug("Installed action %s" % action_name)
        return True

    def uninstall(self):
        action_name = self.__class__.__name__

        # Detach the action from the chosen menu
        result = ida_kernwin.detach_action_from_menu(
            self._menu, self._ACTION_ID
        )
        if not result:
            return False

        # Un-register the action using its id
        result = ida_kernwin.unregister_action(self._ACTION_ID)
        if not result:
            return False

        # Free the custom icon using its id
        ida_kernwin.free_custom_icon(self._icon_id)
        self._icon_id = ida_idaapi.BADADDR

        self._plugin.logger.debug("Uninstalled action %s" % action_name)
        return True

    def update(self):
        """Check if the action should be enabled or not."""
        ida_kernwin.update_action_state(
            self._ACTION_ID, self._handler.update(None)
        )


class ActionHandler(ida_kernwin.action_handler_t):
    """An action handler will display one of the dialogs to the user."""

    _DIALOG = None

    @staticmethod
    def _on_progress(progress, count, total):
        """Called when some progress has been made."""
        progress.setRange(0, total)
        progress.setValue(count)

    def __init__(self, plugin):
        super(ActionHandler, self).__init__()
        self._plugin = plugin

    def update(self, ctx):
        """Update the state of the associated action."""
        if self._plugin.network.connected:
            return ida_kernwin.AST_ENABLE
        return ida_kernwin.AST_DISABLE

    def activate(self, ctx):
        """Called when the action is clicked by the user."""
        dialog_name = self._DIALOG.__name__
        self._plugin.logger.debug("Showing dialog %s" % dialog_name)
        dialog = self._DIALOG(self._plugin)
        dialog.accepted.connect(partial(self._dialog_accepted, dialog))
        dialog.exec_()
        return 1

    def _dialog_accepted(self, dialog):
        """Called when the dialog is accepted by the user."""
        raise NotImplementedError("dialog_accepted() not implemented")


class OpenAction(Action):
    """The "Open from server..." action installed in the "File" menu."""

    _ACTION_ID = "idarling:open"

    def __init__(self, plugin):
        super(OpenAction, self).__init__(
            plugin,
            "File/Open",
            "Open from server...",
            "Load a database from server",
            plugin.plugin_resource("download.png"),
            OpenActionHandler(plugin),
        )


class OpenActionHandler(ActionHandler):
    """The action handler for the "Open from server..." action."""

    _DIALOG = OpenDialog

    def _dialog_accepted(self, dialog):
        project, database = dialog.get_result()

        # Create the download progress dialog
        text = "Downloading database from server, please wait..."
        progress = QProgressDialog(text, "Cancel", 0, 1)
        progress.setCancelButton(None)  # Remove cancel button
        progress.setModal(True)  # Set as a modal dialog
        window_flags = progress.windowFlags()  # Disable close button
        progress.setWindowFlags(window_flags & ~Qt.WindowCloseButtonHint)
        progress.setWindowTitle("Open from server")
        icon_path = self._plugin.plugin_resource("download.png")
        progress.setWindowIcon(QIcon(icon_path))

        # Send a packet to download the file
        packet = DownloadFile.Query(project.name, database.name)
        callback = partial(self._on_progress, progress)

        def set_download_callback(reply):
            reply.downback = callback

        d = self._plugin.network.send_packet(packet)
        d.add_initback(set_download_callback)
        d.add_callback(partial(self._file_downloaded, database, progress))
        d.add_errback(self._plugin.logger.exception)
        progress.show()

    def _file_downloaded(self, database, progress, reply):
        """Called when the file has been downloaded."""
        progress.close()

        # Get the absolute path of the file
        app_path = QCoreApplication.applicationFilePath()
        app_name = QFileInfo(app_path).fileName()
        file_ext = "i64" if "64" in app_name else "idb"
        file_name = "%s_%s.%s" % (database.project, database.name, file_ext)
        file_path = self._plugin.user_resource("files", file_name)

        # Write the file to disk
        with open(file_path, "wb") as output_file:
            output_file.write(reply.content)
        self._plugin.logger.info("Saved file %s" % file_name)

        # Save the old database
        database = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if database:
            ida_loader.save_database(database, ida_loader.DBFL_TEMP)

        # This is a very ugly hack used to open a database into IDA. We don't
        # have any function for this in the SDK, so I sorta hijacked the
        # snapshot functionality in this effect.

        # Get the library to call functions not present in the bindings
        dll = self._plugin.core.get_ida_dll(app_name)

        # Close the old database using the term_database library function
        old_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if old_path:
            dll.term_database()

        # Open the new database using the init_database library function
        # This call only won't be enough because the user interface won't
        # be initialized, this is why the snapshot functionality is used for
        args = [app_name, file_path]
        argc = len(args)
        argv = (ctypes.POINTER(ctypes.c_char) * (argc + 1))()
        for i, arg in enumerate(args):
            arg = arg.encode("utf-8")
            argv[i] = ctypes.create_string_buffer(arg)

        v = ctypes.c_int(0)
        av = ctypes.addressof(v)
        pv = ctypes.cast(av, ctypes.POINTER(ctypes.c_int))
        dll.init_database(argc, argv, pv)

        # Create a temporary copy of the new database because we cannot use
        # the snapshot functionality to restore the currently opened database
        file_ext = ".i64" if "64" in app_name else ".idb"
        tmp_file, tmp_path = tempfile.mkstemp(suffix=file_ext)
        shutil.copyfile(file_path, tmp_path)

        # This hook is used to delete the temporary database when all done
        class UIHooks(ida_kernwin.UI_Hooks):
            def database_inited(self, is_new_database, idc_script):
                self.unhook()

                os.close(tmp_file)
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        hooks = UIHooks()
        hooks.hook()

        # Call the restore_database_snapshot library function
        # This will initialize the user interface, completing the process
        s = ida_loader.snapshot_t()
        s.filename = tmp_path  # Use the temporary database
        ida_kernwin.restore_database_snapshot(s, None, None)


class SaveAction(Action):
    """The "Save to server..." action installed in the "File" menu."""

    _ACTION_ID = "idarling:save"

    def __init__(self, plugin):
        super(SaveAction, self).__init__(
            plugin,
            "File/Save",
            "Save to server...",
            "Save a database to server",
            plugin.plugin_resource("upload.png"),
            SaveActionHandler(plugin),
        )


class SaveActionHandler(ActionHandler):
    """The action handler for the "Save to server..." action."""

    _DIALOG = SaveDialog

    @staticmethod
    def upload_file(plugin, packet):
        # Save the current database
        plugin.core.save_netnode()
        input_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        ida_loader.save_database(input_path, 0)

        with open(input_path, "rb") as input_file:
            packet.content = input_file.read()

        # Create the upload progress dialog
        text = "Uploading database to server, please wait..."
        progress = QProgressDialog(text, "Cancel", 0, 1)
        progress.setCancelButton(None)  # Remove cancel button
        progress.setModal(True)  # Set as a modal dialog
        window_flags = progress.windowFlags()  # Disable close button
        progress.setWindowFlags(window_flags & ~Qt.WindowCloseButtonHint)
        progress.setWindowTitle("Save to server")
        icon_path = plugin.plugin_resource("upload.png")
        progress.setWindowIcon(QIcon(icon_path))

        # Send the packet to upload the file
        packet.upback = partial(SaveActionHandler._on_progress, progress)
        d = plugin.network.send_packet(packet)
        if d:
            d.add_callback(
                partial(SaveActionHandler.file_uploaded, plugin, progress)
            )
            d.add_errback(plugin.logger.exception)
        progress.show()

    @staticmethod
    def file_uploaded(plugin, progress, _):
        progress.close()

        # Show a success dialog
        success = QMessageBox()
        success.setIcon(QMessageBox.Information)
        success.setStandardButtons(QMessageBox.Ok)
        success.setText("Database successfully uploaded!")
        success.setWindowTitle("Save to server")
        icon_path = plugin.plugin_resource("upload.png")
        success.setWindowIcon(QIcon(icon_path))
        success.exec_()

        # Subscribe to the event stream
        plugin.core.join_session()

    def update(self, ctx):
        if not ida_loader.get_path(ida_loader.PATH_TYPE_IDB):
            return ida_kernwin.AST_DISABLE
        if not ida_auto.auto_is_ok():
            return ida_kernwin.AST_DISABLE
        return super(SaveActionHandler, self).update(ctx)

    def _dialog_accepted(self, dialog):
        project, database = dialog.get_result()
        self._plugin.core.project = project.name
        self._plugin.core.database = database.name

        # Create the packet that will hold the file
        packet = UpdateFile.Query(project.name, database.name)
        SaveActionHandler.upload_file(self._plugin, packet)
