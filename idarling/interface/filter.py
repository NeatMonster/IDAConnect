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
import ida_funcs
import ida_kernwin

from PyQt5.QtCore import QEvent, QObject, Qt  # noqa: I202
from PyQt5.QtGui import QContextMenuEvent, QIcon, QImage, QPixmap, QShowEvent
from PyQt5.QtWidgets import (
    QAction,
    qApp,
    QDialog,
    QGroupBox,
    QLabel,
    QMenu,
    QTableView,
    QWidget,
)

from .widget import StatusWidget
from ..shared.commands import InviteToLocation


class EventFilter(QObject):
    """
    This Qt event filter is used to replace the IDA icon with our
    own and to setup the invites context menu in the disassembler view.
    """

    def __init__(self, plugin, parent=None):
        super(EventFilter, self).__init__(parent)
        self._plugin = plugin
        self._intercept = False
        self._label = None

    def install(self):
        self._plugin.logger.debug("Installing the event filter")
        # qApp.instance().installEventFilter(self)

    def uninstall(self):
        self._plugin.logger.debug("Uninstalling the event filter")
        qApp.instance().removeEventFilter(self)

    def _replace_icon(self, label):
        pixmap = QPixmap(self._plugin.plugin_resource("idarling.png"))
        pixmap = pixmap.scaled(
            label.sizeHint().width(),
            label.sizeHint().height(),
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation,
        )
        label.setPixmap(pixmap)

    def _insert_menu(self, obj):
        # Find where to install our submenu
        sep = None
        for act in obj.actions():
            if act.isSeparator():
                sep = act
            if "Undefine" in act.text():
                break
        obj.insertSeparator(sep)

        # Setup our custom menu text and icon
        menu = QMenu("Invite to location", obj)
        pixmap = QPixmap(self._plugin.plugin_resource("invite.png"))
        menu.setIcon(QIcon(pixmap))

        # Setup our first submenu entry text and icon
        everyone = QAction("Everyone", menu)
        pixmap = QPixmap(self._plugin.plugin_resource("users.png"))
        everyone.setIcon(QIcon(pixmap))

        def invite_to(name):
            """Send an invitation to the current location."""
            loc = ida_kernwin.get_screen_ea()
            packet = InviteToLocation(name, loc)
            self._plugin.network.send_packet(packet)

        # Handler for when the action is clicked
        def invite_to_everyone():
            invite_to("everyone")

        everyone.triggered.connect(invite_to_everyone)
        menu.addAction(everyone)

        menu.addSeparator()
        template = self._plugin.plugin_resource("user.png")

        def create_action(name, color):
            action = QAction(name, menu)
            pixmap = StatusWidget.make_icon(template, color)
            action.setIcon(QIcon(pixmap))

            # Handler for when the action is clicked
            def invite_to_user():
                invite_to(name)

            action.triggered.connect(invite_to_user)
            return action

        # Insert an action for each connected user
        for name, user in self._plugin.core.get_users().items():
            menu.addAction(create_action(name, user["color"]))
        obj.insertMenu(sep, menu)

    def _set_tooltip(self, obj, ev):
        cursors = self._plugin.config["cursors"]
        if not cursors["funcs"]:
            return

        obj.setToolTip("")
        index = obj.parent().indexAt(ev.pos())
        func_ea = int(index.sibling(index.row(), 2).data(), 16)
        func = ida_funcs.get_func(func_ea)

        # Find the corresponding username
        for name, user in self._plugin.core.get_users().items():
            if ida_funcs.func_contains(func, user["ea"]):
                # Set the tooltip
                obj.setToolTip(name)
                break

    def eventFilter(self, obj, ev):  # noqa: N802
        # Is it a QShowEvent on a QDialog named "Dialog"?
        if (
            ev.__class__ == ev,
            QShowEvent
            and obj.__class__ == QDialog
            and obj.windowTitle() == "About",
        ):
            if self._label is not None:
                self._replace_icon(self._label)
            else:
                # Find a child QGroupBox
                for groupBox in obj.children():
                    if groupBox.__class__ == QGroupBox:
                        # Find a child QLabel with an icon
                        for label in groupBox.children():
                            if isinstance(label, QLabel) and label.pixmap():
                                self._replace_icon(label)
                                self._label = label

        # Is it a QContextMenuEvent on a QWidget?
        if isinstance(obj, QWidget) and isinstance(ev, QContextMenuEvent):
            # Find a parent titled "IDA View"
            parent = obj
            while parent:
                if parent.windowTitle().startswith("IDA View"):
                    # Intercept the next context menu
                    self._intercept = True
                parent = parent.parent()

        # Is it a QShowEvent on a QMenu?
        if isinstance(obj, QMenu) and isinstance(ev, QShowEvent):
            # Should we intercept?
            if self._intercept:
                self._insert_menu(obj)
                self._intercept = False

        # Is it a ToolTip event on a QWidget with a parent?
        if (
            ev.type() == QEvent.ToolTip
            and obj.__class__ == QWidget
            and obj.parent()
        ):
            table_view = obj.parent()
            # Is it a QTableView with a parent?
            if table_view.__class__ == QTableView and table_view.parent():
                func_window = table_view.parent()
                # Is it a QWidget titled "Functions window"?
                if (
                    func_window.__class__ == QWidget
                    and func_window.windowTitle() == "Functions window"
                ):
                    self._set_tooltip(obj, ev)

        return False
