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
from PyQt5.QtGui import QBrush, QColor, QPainter, QPixmap
from PyQt5.QtWidgets import QHBoxLayout, QLabel, QWidget


class Toast(QWidget):
    def __init__(self, parent=None):
        super(Toast, self).__init__(parent)
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

        self._popup_opacity = 0.0
        self._animation = QPropertyAnimation()
        self._animation.setTargetObject(self)
        self._animation.setPropertyName("popup_opacity")
        self._animation.finished.connect(self.hide)

        self._timer = QTimer()
        self._timer.timeout.connect(self.hide_animation)
        self._callback = None

    def paintEvent(self, event):  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = QRect(self.rect())

        painter.setBrush(QBrush(QColor(122, 122, 122)))
        painter.setPen(Qt.NoPen)
        painter.drawRect(rect)

        rect.setX(rect.x() + 1)
        rect.setY(rect.y() + 1)
        rect.setWidth(rect.width() - 1)
        rect.setHeight(rect.height() - 1)

        painter.setBrush(QBrush(QColor(255, 255, 225)))
        painter.setPen(Qt.NoPen)
        painter.drawRect(rect)

    def mouseReleaseEvent(self, event):  # noqa: N802
        if self._callback:
            self._callback()
        self.hide_animation()

    def set_text(self, text):
        self._text.setText(text)
        self.adjustSize()

    def set_icon(self, path):
        pixmap = QPixmap(path)
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

    def set_callback(self, callback):
        self._callback = callback

    def show(self):
        self.setWindowOpacity(0.0)

        self._animation.setDuration(500)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(1.0)

        pos = QPoint(self.parent().width() - 25, self.parent().height() - 50)
        pos = self.parent().mapToGlobal(pos)

        self.setGeometry(
            pos.x() - self.width(),
            pos.y() - self.height(),
            self.width(),
            self.height(),
        )
        super(Toast, self).show()

        self._animation.start()
        self._timer.start(3500)

    def hide(self):
        if self._popup_opacity == 0.0:
            super(Toast, self).hide()

    def hide_animation(self):
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
