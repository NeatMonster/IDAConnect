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
from PyQt5.QtCore import (
    pyqtProperty,
    QPoint,
    QPropertyAnimation,
    QRect,
    Qt,
    QTimer,
)
from PyQt5.QtGui import QBrush, QColor, QPainter
from PyQt5.QtWidgets import QHBoxLayout, QLabel, QWidget


class Invite(QWidget):
    """
    An invite is a small notification being displayed in the bottom right
    corner of the window. It fades in and out, and is used to invite an user
    to jump to a certain location. Some other uses might be added later.
    """

    def __init__(self, plugin, parent=None):
        super(Invite, self).__init__(parent)
        self._plugin = plugin
        self._time = 0

        self.setWindowFlags(
            Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WA_TranslucentBackground)

        self._icon = QLabel()
        self._icon.setAutoFillBackground(False)
        self._icon.setAttribute(Qt.WA_TranslucentBackground)

        self._text = QLabel()
        self._text.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

        self._layout = QHBoxLayout()
        self._layout.addWidget(self._text)
        self.setLayout(self._layout)

        # Fade in and out animation
        self._popup_opacity = 0.0
        self._animation = QPropertyAnimation()
        self._animation.setTargetObject(self)
        self._animation.setPropertyName(b"popup_opacity")
        self._animation.finished.connect(self.hide)

        # Timer used to auto-close the window
        self._timer = QTimer()
        self._timer.timeout.connect(self.hide_animation)
        self._callback = None
        self._triggered = False

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, time):
        self._time = time

    @property
    def text(self):
        return self._text.text()

    @text.setter
    def text(self, text):
        self._text.setText(text)
        self.adjustSize()

    @property
    def icon(self):
        return self._icon.pixmap()

    @icon.setter
    def icon(self, pixmap):
        # Resize the given pixmap
        pixmap_height = self._text.sizeHint().height()
        self._icon.setPixmap(
            pixmap.scaled(
                pixmap_height,
                pixmap_height,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        )
        self._layout.insertWidget(0, self._icon)

    @property
    def callback(self):
        return self._callback

    @callback.setter
    def callback(self, callback):
        self._callback = callback

    @property
    def triggered(self):
        return self._triggered

    @triggered.setter
    def triggered(self, triggered):
        self._triggered = triggered

    def paintEvent(self, event):  # noqa: N802
        """We override the painting event to draw the invite ourselves."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = QRect(self.rect())

        # Draw the border
        painter.setBrush(QBrush(QColor(122, 122, 122)))
        painter.setPen(Qt.NoPen)
        painter.drawRect(rect)

        rect.setX(rect.x() + 1)
        rect.setY(rect.y() + 1)
        rect.setWidth(rect.width() - 1)
        rect.setHeight(rect.height() - 1)

        # Draw the background
        painter.setBrush(QBrush(QColor(255, 255, 225)))
        painter.setPen(Qt.NoPen)
        painter.drawRect(rect)

    def mouseReleaseEvent(self, event):  # noqa: N802
        """
        This function is called when the user clicks the invite. It triggers
        the callback function is it has been specified, and hides the invite.
        """
        if self._callback:
            self._callback()
        self._triggered = True
        self._popup_opacity = 0.0
        self.hide()

    def show(self):
        """Shows the invite to user. It triggers a fade in effect."""
        self._plugin.logger.debug("Showing invite %s" % self.text)
        self.setWindowOpacity(0.0)

        self._animation.setDuration(500)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)

        # Map the notification to the bottom right corner
        pos = QPoint(self.parent().width() - 25, self.parent().height() - 50)
        pos = self.parent().mapToGlobal(pos)

        self.setGeometry(
            pos.x() - self.width(),
            pos.y() - self.height(),
            self.width(),
            self.height(),
        )
        super(Invite, self).show()

        self._animation.start()
        self._timer.start(3500)

    def hide(self):
        """Hides the invite only if it is fully transparent."""
        if self._popup_opacity == 0.0:
            self._plugin.interface.widget.refresh()
            super(Invite, self).hide()

    def hide_animation(self):
        """Hides the invite. It triggers the fade out animation."""
        self._timer.stop()
        self._animation.setDuration(500)
        self._animation.setStartValue(1.0)
        self._animation.setEndValue(0.0)
        self._animation.start()

    @pyqtProperty(float)
    def popup_opacity(self):
        return self._popup_opacity

    @popup_opacity.setter
    def popup_opacity(self, opacity):
        self._popup_opacity = opacity
        self.setWindowOpacity(opacity)
