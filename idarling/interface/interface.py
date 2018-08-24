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
import logging

from PyQt5.QtCore import QObject, Qt
from PyQt5.QtGui import QShowEvent, QPixmap
from PyQt5.QtWidgets import qApp, QMainWindow,\
                            QDialog, QGroupBox, QLabel,\
                            QApplication

from ..module import Module
from .actions import OpenAction, SaveAction
from .painter import Painter
from .widgets import StatusWidget

logger = logging.getLogger('IDArling.Interface')


class Interface(Module):
    """
    The interface module, responsible for all interactions with the user.
    """

    @staticmethod
    def _find_main_window():
        """
        Return the main window instance using Qt.

        :return: the main window
        """
        for widget in qApp.topLevelWidgets():
            if isinstance(widget, QMainWindow):
                return widget

    def __init__(self, plugin):
        super(Interface, self).__init__(plugin)
        self._window = self._find_main_window()

        self._openAction = OpenAction(plugin)
        self._saveAction = SaveAction(plugin)
        self._painter = Painter()

        class EventHandler(QObject):

            def __init__(self, plugin, parent=None):
                super(EventHandler, self).__init__(parent)
                self._plugin = plugin

            @staticmethod
            def replace_icon(label):
                pixmap = QPixmap(self._plugin.resource('idarling.png'))
                pixmap = pixmap.scaled(
                    label.sizeHint().width(), label.sizeHint().height(),
                    Qt.KeepAspectRatio, Qt.SmoothTransformation)
                label.setPixmap(pixmap)

            def eventFilter(self, obj, ev):
                if isinstance(obj, QDialog) and isinstance(ev, QShowEvent):
                    if obj.windowTitle() == 'About':
                        for child in obj.children():
                            if isinstance(child, QGroupBox):
                                for subchild in child.children():
                                    if isinstance(subchild, QLabel) \
                                            and subchild.pixmap():
                                        EventHandler.replace_icon(subchild)
                return False
        self._eventFilter = EventHandler(self._plugin)
        self._statusWidget = StatusWidget(self._plugin)

    def _install(self):
        self._openAction.install()
        self._saveAction.install()
        self._install_our_icon()
        self._painter.install()

        self._window.statusBar().addPermanentWidget(self._statusWidget)
        logger.debug("Installed widgets in status bar")
        return True

    def _uninstall(self):
        self._openAction.uninstall()
        self._saveAction.uninstall()
        self._uninstall_our_icon()
        self._painter.uninstall()

        self._window.statusBar().removeWidget(self._statusWidget)
        logger.debug("Uninstalled widgets from status bar")
        return True

    def _update_actions(self):
        """
        Force to update the actions' status (enabled/disabled).
        """
        self._openAction.update()
        self._saveAction.update()

    def _install_our_icon(self):
        """
        Install our icon into the about dialog.
        """
        QApplication.instance().installEventFilter(self._eventFilter)

    def _uninstall_our_icon(self):
        """
        Uninstall our icon from the about dialog.
        """
        QApplication.instance().removeEventFilter(self._eventFilter)

    def notify_disconnected(self):
        self._statusWidget.set_state(StatusWidget.STATE_DISCONNECTED)
        self._statusWidget.set_server(None)
        self._update_actions()

    def notify_connecting(self):
        self._statusWidget.set_state(StatusWidget.STATE_CONNECTING)
        self._statusWidget.set_server(self._plugin.network.server)
        self._update_actions()

    def notify_connected(self):
        self._statusWidget.set_state(StatusWidget.STATE_CONNECTED)
        self._update_actions()

    @property
    def painter(self):
        return self._painter
