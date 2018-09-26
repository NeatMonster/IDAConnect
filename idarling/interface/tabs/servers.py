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
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


class _TabCfgServer:
    _instance = None  # Keep instance reference

    def __init__(self, program, parent):
        """
        Initialize server settings in the Settings dialog

        Use "get" method to get after initialized

        :param: parent: Parent QTabWidget
        :param: program: current program
        :return: a QWidget containing server settings
        """
        if _TabCfgServer._instance:
            raise ValueError("You should only create TabCfgServer once")
        _TabCfgServer._instance = self
        self.program = program
        self.parent = parent

    def get(self):
        parent = self.parent
        program = self.program

        assert type(parent) == QTabWidget

        # TODO: code cleaning
        tab = QWidget(parent)
        layout = QVBoxLayout(tab)

        program._servers = program._plugin.config["servers"]
        program._servers_table = QTableWidget(
            len(program._servers), 2, program
        )
        layout.addWidget(program._servers_table)

        for i, server in enumerate(program._servers):
            # Server host and port
            item = QTableWidgetItem("%s:%d" % (server["host"], server["port"]))
            item.setData(Qt.UserRole, server)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if program._plugin.network.server == server:
                item.setFlags((item.flags() & ~Qt.ItemIsSelectable))
            program._servers_table.setItem(i, 0, item)

            # Is SSL enabled for server
            checkbox = QTableWidgetItem()
            state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
            checkbox.setCheckState(state)
            checkbox.setFlags((checkbox.flags() & ~Qt.ItemIsEditable))
            checkbox.setFlags((checkbox.flags() & ~Qt.ItemIsUserCheckable))
            if program._plugin.network.server == server:
                checkbox.setFlags((checkbox.flags() & ~Qt.ItemIsSelectable))
            program._servers_table.setItem(i, 1, checkbox)

        program._servers_table.setHorizontalHeaderLabels(("Servers", ""))
        horizontal_header = program._servers_table.horizontalHeader()
        horizontal_header.setSectionsClickable(False)
        horizontal_header.setSectionResizeMode(0, QHeaderView.Stretch)
        horizontal_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        program._servers_table.verticalHeader().setVisible(False)
        program._servers_table.setSelectionBehavior(QTableWidget.SelectRows)
        program._servers_table.setSelectionMode(QTableWidget.SingleSelection)
        program._servers_table.itemClicked.connect(program._server_clicked)
        program._servers_table.itemDoubleClicked.connect(
            program._server_double_clicked
        )
        program._servers_table.setMaximumHeight(100)

        buttons_widget = QWidget(tab)
        buttons_layout = QHBoxLayout(buttons_widget)
        layout.addWidget(buttons_widget)

        # Add server button
        program._addButton = QPushButton("Add Server")
        program._addButton.clicked.connect(program._add_button_clicked)
        buttons_layout.addWidget(program._addButton)

        # Edit server button
        program._editButton = QPushButton("Edit Server")
        program._editButton.setEnabled(False)
        program._editButton.clicked.connect(program._edit_button_clicked)
        buttons_layout.addWidget(program._editButton)

        # Delete server button
        program._deleteButton = QPushButton("Delete Server")
        program._deleteButton.setEnabled(False)
        program._deleteButton.clicked.connect(program._delete_button_clicked)
        buttons_layout.addWidget(program._deleteButton)

        layout.addWidget(buttons_widget)

        return tab
