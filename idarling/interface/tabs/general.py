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

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QCheckBox,
    QColorDialog,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QWidget,
)


class _TabCfgGeneral:
    _instance = None  # Keep instance reference

    def __init__(self, program, parent):
        """
        Initialize General Settings in the Settings dialog

        Use "get" method to get after initialized

        :param: parent: Parent QTabWidget
        :param: program: current program
        :return: a QWidget containing general settings
        """
        if _TabCfgGeneral._instance:
            raise ValueError("You should only create TabCfgServer once")
        _TabCfgGeneral._instance = self
        self.program = program
        self.parent = parent

    def get(self):
        parent = self.parent
        program = self.program
        # TODO: code cleaning
        assert type(parent) == QTabWidget

        tab = QWidget(parent)
        # Set general layout
        layout = QFormLayout(tab)
        layout.setFormAlignment(Qt.AlignVCenter)

        # Add widgets and restore settings
        user_widget = QWidget(tab)
        user_layout = QHBoxLayout(user_widget)
        layout.addRow(user_widget)

        # User info settings: Color
        program._color_button = QPushButton("")
        program._color_button.setFixedSize(50, 30)

        # Add a handler on clicking color button
        def color_button_activated(_):
            program._set_color(qt_color=QColorDialog.getColor().rgb())

        program._color = program._plugin.config["user"]["color"]
        program._set_color(ida_color=program._color)
        program._color_button.clicked.connect(color_button_activated)
        user_layout.addWidget(program._color_button)

        # User info settings: Name
        program._name_line_edit = QLineEdit()
        name = program._plugin.config["user"]["name"]
        program._name_line_edit.setText(name)
        user_layout.addWidget(program._name_line_edit)

        # User info settings: Notifications and Cursors
        text = "Show other users in the navigation bar"
        program._navbar_colorizer_checkbox = QCheckBox(text)
        layout.addRow(program._navbar_colorizer_checkbox)
        checked = program._plugin.config["user"]["navbar_colorizer"]
        program._navbar_colorizer_checkbox.setChecked(checked)

        text = "Allow other users to send notifications"
        program._notifications_checkbox = QCheckBox(text)
        layout.addRow(program._notifications_checkbox)
        checked = program._plugin.config["user"]["notifications"]
        program._notifications_checkbox.setChecked(checked)

        # User info settings: Debug Level
        debug_level_label = QLabel("Logging Level: ")
        program._debug_level_combo_box = QComboBox()
        program._debug_level_combo_box.addItem("CRITICAL", logging.CRITICAL)
        program._debug_level_combo_box.addItem("ERROR", logging.ERROR)
        program._debug_level_combo_box.addItem("WARNING", logging.WARNING)
        program._debug_level_combo_box.addItem("INFO", logging.INFO)
        program._debug_level_combo_box.addItem("DEBUG", logging.DEBUG)
        program._debug_level_combo_box.addItem("TRACE", logging.TRACE)
        level = program._plugin.config["level"]
        index = program._debug_level_combo_box.findData(level)
        program._debug_level_combo_box.setCurrentIndex(index)
        layout.addRow(debug_level_label, program._debug_level_combo_box)

        return tab
