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
import colorsys
from functools import partial, lru_cache
import time

from PyQt5.QtCore import QPoint, QRect, QSize, Qt, QTimer
from PyQt5.QtGui import QIcon, QImage, QPainter, QPixmap, QRegion
from PyQt5.QtWidgets import QAction, QActionGroup, QLabel, QMenu, QWidget

from .dialogs import SettingsDialog


class StatusWidget(QWidget):
    """
    This is the widget that is displayed in the status bar of the window. It
    allow the user to connect to server, as well as to access the settings.
    """

    @staticmethod
    def ida_to_python(c):
        # IDA colors are 0xBBGGRR.
        r = (c & 255) / 255.0
        g = ((c >> 8) & 255) / 255.0
        b = ((c >> 16) & 255) / 255.0
        return r, g, b

    @staticmethod
    def python_to_qt(r, g, b):
        # Qt colors are 0xRRGGBB
        r = int(r * 255) << 16
        g = int(g * 255) << 8
        b = int(b * 255)
        return 0xFF000000 | r | g | b

    @staticmethod
    @lru_cache(maxsize=32)
    def make_icon(template, color):
        """
        Create an icon for the specified user color. It will be used to
        generate on the fly an icon representing the user.
        """
        # Get a light and dark version of the user color
        r, g, b = StatusWidget.ida_to_python(color)
        h, l, s = colorsys.rgb_to_hls(r, g, b)
        r, g, b = colorsys.hls_to_rgb(h, 0.5, 1.0)
        light = StatusWidget.python_to_qt(r, g, b)
        r, g, b = colorsys.hls_to_rgb(h, 0.25, 1.0)
        dark = StatusWidget.python_to_qt(r, g, b)

        # Replace the icon pixel with our two colors
        image = QImage(template)
        for x in range(image.width()):
            for y in range(image.height()):
                c = image.pixel(x, y)
                if (c & 0xFFFFFF) == 0xFFFFFF:
                    image.setPixel(x, y, light)
                if (c & 0xFFFFFF) == 0x000000:
                    image.setPixel(x, y, dark)
        return QPixmap(image)

    def __init__(self, plugin):
        super(StatusWidget, self).__init__()
        self._plugin = plugin

        # Create the sub-widgets
        def new_label():
            widget = QLabel()
            widget.setAutoFillBackground(False)
            widget.setAttribute(Qt.WA_PaintOnScreen)
            widget.setAttribute(Qt.WA_TranslucentBackground)
            return widget

        self._servers_text_widget = new_label()
        self._servers_icon_widget = new_label()
        self._invites_text_widget = new_label()
        self._invites_icon_widget = new_label()
        self._users_text_widget = new_label()
        self._users_icon_widget = new_label()

        # Set a custom context menu policy
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)

        # Timer signaling it is time to update the widget
        self._timer = QTimer()
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.refresh)

    def install(self, window):
        self._plugin.logger.debug("Installing the status bar widget")
        window.statusBar().addPermanentWidget(self)
        self._timer.start()
        self.refresh()

    def uninstall(self, window):
        self._plugin.logger.debug("Uninstalling the status bar widget")
        window.statusBar().removeWidget(self)
        self._timer.stop()

    def refresh(self):
        """Called to update the widget when the network state has changed."""
        self._plugin.logger.trace("Refreshing the status bar widget")

        # Get the corresponding color, text and icon
        if self._plugin.network.connected:
            color, text, icon = "green", "Connected", "connected.png"
        elif self._plugin.network.client:
            color, text, icon = "orange", "Connecting", "connecting.png"
        else:
            color, text, icon = "red", "Disconnected", "disconnected.png"

        # Update the text of the server widgets
        server = self._plugin.network.server
        if server is None:
            server = "&lt;no server&gt;"
        else:
            server = "%s:%d" % (server["host"], server["port"])
        text_format = '%s | %s -- <span style="color: %s;">%s</span>'
        self._servers_text_widget.setText(
            text_format % (self._plugin.description(), server, color, text)
        )
        self._servers_text_widget.adjustSize()

        # Update the icon of the server widgets
        pixmap = QPixmap(self._plugin.plugin_resource(icon))
        pixmap_height = self._servers_text_widget.sizeHint().height()
        self._servers_icon_widget.setPixmap(
            pixmap.scaled(
                pixmap_height,
                pixmap_height,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        )

        # Get all active invites
        invites = self._plugin.interface.invites
        # Find the most recent one
        most_recent = 0
        if invites:
            most_recent = max(invite.time for invite in invites)

        # Get the corresponding icon
        if most_recent > 0 and time.time() - most_recent < 60.0:
            icon = "hot.png"
        elif most_recent > 0 and time.time() - most_recent < 300.0:
            icon = "warm.png"
        elif most_recent > 0:
            icon = "cold.png"
        else:
            icon = "empty.png"

        # Update the text of the invites widgets
        self._invites_text_widget.setText(" | %d " % len(invites))
        self._invites_text_widget.adjustSize()

        # Update the icon of the invites widgets
        pixmap = QPixmap(self._plugin.plugin_resource(icon))
        pixmap_height = self._servers_text_widget.sizeHint().height()
        self._invites_icon_widget.setPixmap(
            pixmap.scaled(
                pixmap_height,
                pixmap_height,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        )

        # Update the text of the users widget
        users = len(self._plugin.core.get_users())
        self._users_text_widget.setText(" | %d" % users)
        self._users_text_widget.adjustSize()

        # Update the icon of the users widget
        template = self._plugin.plugin_resource("user.png")
        color = self._plugin.config["user"]["color"]
        pixmap = self.make_icon(template, color)
        pixmap_height = self._servers_text_widget.sizeHint().height()
        self._users_icon_widget.setPixmap(
            pixmap.scaled(
                pixmap_height,
                pixmap_height,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        )

        # Update the size of the widget
        self.updateGeometry()

    def sizeHint(self):  # noqa: N802
        """Called when the widget size is being determined internally."""
        width = 3 + self._servers_text_widget.sizeHint().width()
        width += 3 + self._servers_icon_widget.sizeHint().width()
        width += 3 + self._invites_text_widget.sizeHint().width()
        width += 3 + self._invites_icon_widget.sizeHint().width()
        width += 3 + self._users_text_widget.sizeHint().width()
        width += 3 + self._users_icon_widget.sizeHint().width()
        return QSize(width, self._servers_text_widget.sizeHint().height())

    def _context_menu(self, point):
        """Called when the context menu is being requested."""
        width_server = 3 + self._servers_text_widget.sizeHint().width()
        width_server += 3 + self._servers_icon_widget.sizeHint().width()
        width_invites = width_server
        width_invites += 3 + self._invites_text_widget.sizeHint().width()
        width_invites += 3 + self._invites_icon_widget.sizeHint().width()

        if point.x() < width_server + 3:
            self._servers_context_menu(point)
        elif width_server < point.x() < width_invites + 3:
            self._invites_context_menu(point)
        else:
            self._users_context_menu(point)

    def _servers_context_menu(self, point):
        """Populates the server context menu."""
        menu = QMenu(self)

        # Add the settings action
        settings = QAction("Settings...", menu)
        icon_path = self._plugin.plugin_resource("settings.png")
        settings.setIcon(QIcon(icon_path))

        # Add a handler on the action
        def settings_action_triggered():
            SettingsDialog(self._plugin).exec_()

        settings.triggered.connect(settings_action_triggered)
        menu.addAction(settings)

        # Add the integrated server action
        menu.addSeparator()
        integrated = QAction("Integrated Server", menu)
        integrated.setCheckable(True)

        def integrated_action_triggered():
            # Start or stop the server
            if integrated.isChecked():
                self._plugin.network.start_server()
            else:
                self._plugin.network.stop_server()

        integrated.setChecked(self._plugin.network.started)
        integrated.triggered.connect(integrated_action_triggered)
        menu.addAction(integrated)

        def create_servers_group(servers):
            """Create an action group for the specified servers."""
            servers_group = QActionGroup(self)
            current_server = self._plugin.network.server

            for server in servers:
                is_connected = (
                    current_server is not None
                    and server["host"] == current_server["host"]
                    and server["port"] == current_server["port"]
                )
                server_text = "%s:%d" % (server["host"], server["port"])
                server_action = QAction(server_text, menu)
                server_action._server = server
                server_action.setCheckable(True)
                server_action.setChecked(is_connected)
                servers_group.addAction(server_action)

            def server_action_triggered(server_action):
                """
                Called when a action is clicked. Connects to the new server
                or disconnects from the old server.
                """
                server = server_action._server
                was_connected = self._plugin.network.server == server
                self._plugin.network.stop_server()
                self._plugin.network.disconnect()
                if not was_connected:
                    self._plugin.network.connect(server)

            servers_group.triggered.connect(server_action_triggered)

            return servers_group

        # Add the discovered servers
        user_servers = self._plugin.config["servers"]
        disc_servers = self._plugin.network.discovery.servers
        disc_servers = [s for s, t in disc_servers if time.time() - t < 10.0]
        disc_servers = [s for s in disc_servers if s not in user_servers]
        if (
            self._plugin.network.started
            and self._plugin.network.server in disc_servers
        ):
            disc_servers.remove(self._plugin.network.server)
        if disc_servers:
            menu.addSeparator()
            servers_group = create_servers_group(disc_servers)
            menu.addActions(servers_group.actions())

        # Add the configured servers
        if user_servers:
            menu.addSeparator()
            servers_group = create_servers_group(user_servers)
            menu.addActions(servers_group.actions())

        # Show the context menu
        menu.exec_(self.mapToGlobal(point))

    def _invites_context_menu(self, point):
        """Populate the invites context menu."""
        menu = QMenu(self)

        # Get all active invites
        invites = self._plugin.interface.invites
        # Sort invites by time ascending
        invites = sorted(invites, key=lambda x: x.time)

        clear = QAction("Clear invites", menu)
        icon_path = self._plugin.plugin_resource("clear.png")
        clear.setIcon(QIcon(icon_path))
        clear.triggered.connect(self._plugin.interface.clear_invites)
        clear.setEnabled(bool(invites))
        menu.addAction(clear)

        if invites:
            menu.addSeparator()

            # Add an action for each invite
            for invite in invites:
                action = QAction(invite.text, menu)
                action.setIcon(QIcon(invite.icon))

                def action_triggered():
                    if invite.callback:
                        invite.callback()
                    invite.triggered = True
                    self.refresh()

                action.triggered.connect(action_triggered)
                menu.addAction(action)

        # Show the context menu
        menu.exec_(self.mapToGlobal(point))

    def _users_context_menu(self, point):
        """Populate the invites context menu."""
        menu = QMenu(self)

        template = self._plugin.plugin_resource("user.png")

        users = self._plugin.core.get_users()
        follow_all = QAction("Follow all", menu)
        pixmap = QPixmap(self._plugin.plugin_resource("users.png"))
        follow_all.setIcon(QIcon(pixmap))
        follow_all.setEnabled(bool(users))
        follow_all.setCheckable(True)
        follow_all.setChecked(self._plugin.interface.followed == "everyone")

        def follow_triggered(name):
            interface = self._plugin.interface
            interface.followed = name if interface.followed != name else None

        follow_all.triggered.connect(partial(follow_triggered, "everyone"))
        menu.addAction(follow_all)

        unfollow = QAction("Unfollow", menu)
        pixmap = QPixmap(self._plugin.plugin_resource("unfollow.png"))
        unfollow.setIcon(QIcon(pixmap))
        unfollow.setEnabled(bool(users))
        unfollow.setCheckable(True)
        unfollow.setChecked(self._plugin.interface.followed == None)
        unfollow.triggered.connect(partial(follow_triggered, None))
        menu.addAction(unfollow)

        if users:
            menu.addSeparator()

            # Get all active users
            for name, user in users.items():
                is_followed = self._plugin.interface.followed == name
                text = "Follow %s" % name
                action = QAction(text, menu)
                action.setCheckable(True)
                action.setChecked(is_followed)
                pixmap = StatusWidget.make_icon(template, user["color"])
                action.setIcon(QIcon(pixmap))

                action.triggered.connect(partial(follow_triggered, name))
                menu.addAction(action)

        menu.exec_(self.mapToGlobal(point))

    def paintEvent(self, event):  # noqa: N802
        """Called when the widget is being painted."""
        # Adjust the buffer size according to the pixel ratio
        dpr = self.devicePixelRatioF()
        buffer = QPixmap(self.width() * dpr, self.height() * dpr)
        buffer.setDevicePixelRatio(dpr)
        buffer.fill(Qt.transparent)

        painter = QPainter(buffer)

        # Paint the server text widget
        region = QRegion(
            QRect(QPoint(0, 0), self._servers_text_widget.sizeHint())
        )
        self._servers_text_widget.render(painter, QPoint(0, 0), region)
        # Paint the server icon widget
        region = QRegion(
            QRect(QPoint(0, 0), self._servers_icon_widget.sizeHint())
        )
        x = self._servers_text_widget.sizeHint().width() + 3
        self._servers_icon_widget.render(painter, QPoint(x, 0), region)
        # Paint the invites text widget
        region = QRegion(
            QRect(QPoint(0, 0), self._invites_text_widget.sizeHint())
        )
        x += self._servers_icon_widget.sizeHint().width() + 3
        self._invites_text_widget.render(painter, QPoint(x, 0), region)
        # Paint the invites icon widget
        region = QRegion(
            QRect(QPoint(0, 0), self._invites_icon_widget.sizeHint())
        )
        x += self._invites_text_widget.sizeHint().width() + 3
        self._invites_icon_widget.render(painter, QPoint(x, 0), region)
        # Paint the users text widget
        region = QRegion(
            QRect(QPoint(0, 0), self._users_text_widget.sizeHint())
        )
        x += self._invites_icon_widget.sizeHint().width() + 3
        self._users_text_widget.render(painter, QPoint(x, 0), region)
        # Paint the users icon widget
        region = QRegion(
            QRect(QPoint(0, 0), self._users_icon_widget.sizeHint())
        )
        x += self._users_text_widget.sizeHint().width() + 3
        self._users_icon_widget.render(painter, QPoint(x, 0), region)
        painter.end()

        painter = QPainter(self)
        painter.drawPixmap(event.rect(), buffer, buffer.rect())
        painter.end()
