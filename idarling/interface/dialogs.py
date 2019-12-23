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
import datetime
from functools import partial
import logging

import ida_loader
import ida_nalt

from PyQt5.QtCore import QRegExp, Qt  # noqa: I202
from PyQt5.QtGui import QIcon, QRegExpValidator
from PyQt5.QtWidgets import (
    QCheckBox,
    QColorDialog,
    QComboBox,
    QDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..shared.commands import (
    CreateDatabase,
    CreateProject,
    ListDatabases,
    ListProjects,
    UpdateUserColor,
    UpdateUserName,
)
from ..shared.models import Database, Project


class OpenDialog(QDialog):
    """This dialog is shown to user to select which remote database to load."""

    def __init__(self, plugin):
        super(OpenDialog, self).__init__()
        self._plugin = plugin
        self._projects = None
        self._databases = None

        # General setup of the dialog
        self.setWindowTitle("Open from Remote Server")
        icon_path = self._plugin.plugin_resource("download.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(900, 450)

        # Setup of the layout and widgets
        layout = QVBoxLayout(self)
        main = QWidget(self)
        main_layout = QGridLayout(main)
        layout.addWidget(main)

        self._left_side = QWidget(main)
        self._left_layout = QVBoxLayout(self._left_side)
        self._projects_table = QTableWidget(0, 1, self._left_side)
        self._projects_table.setHorizontalHeaderLabels(("Projects",))
        self._projects_table.horizontalHeader().setSectionsClickable(False)
        self._projects_table.horizontalHeader().setStretchLastSection(True)
        self._projects_table.verticalHeader().setVisible(False)
        self._projects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._projects_table.setSelectionMode(QTableWidget.SingleSelection)
        self._projects_table.itemSelectionChanged.connect(
            self._project_clicked
        )
        self._left_layout.addWidget(self._projects_table)
        main_layout.addWidget(self._left_side, 0, 0)
        main_layout.setColumnStretch(0, 1)

        right_side = QWidget(main)
        right_layout = QVBoxLayout(right_side)
        details_group = QGroupBox("Details", right_side)
        details_layout = QGridLayout(details_group)
        self._file_label = QLabel("<b>File:</b>")
        details_layout.addWidget(self._file_label, 0, 0)
        self._hash_label = QLabel("<b>Hash:</b>")
        details_layout.addWidget(self._hash_label, 1, 0)
        details_layout.setColumnStretch(0, 1)
        self._type_label = QLabel("<b>Type:</b>")
        details_layout.addWidget(self._type_label, 0, 1)
        self._date_label = QLabel("<b>Date:</b>")
        details_layout.addWidget(self._date_label, 1, 1)
        details_layout.setColumnStretch(1, 1)
        right_layout.addWidget(details_group)
        main_layout.addWidget(right_side, 0, 1)
        main_layout.setColumnStretch(1, 2)

        self._databases_group = QGroupBox("Databases", right_side)
        self._databases_layout = QVBoxLayout(self._databases_group)
        self._databases_table = QTableWidget(0, 3, self._databases_group)
        labels = ("Name", "Date", "Ticks")
        self._databases_table.setHorizontalHeaderLabels(labels)
        horizontal_header = self._databases_table.horizontalHeader()
        horizontal_header.setSectionsClickable(False)
        horizontal_header.setSectionResizeMode(0, horizontal_header.Stretch)
        self._databases_table.verticalHeader().setVisible(False)
        self._databases_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._databases_table.setSelectionMode(QTableWidget.SingleSelection)
        self._databases_table.itemSelectionChanged.connect(
            self._database_clicked
        )
        self._databases_table.itemDoubleClicked.connect(
            self._database_double_clicked
        )
        self._databases_layout.addWidget(self._databases_table)
        right_layout.addWidget(self._databases_group)

        buttons_widget = QWidget(self)
        buttons_layout = QHBoxLayout(buttons_widget)
        buttons_layout.addStretch()
        self._accept_button = QPushButton("Open", buttons_widget)
        self._accept_button.setEnabled(False)
        self._accept_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Cancel", buttons_widget)
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(self._accept_button)
        layout.addWidget(buttons_widget)

        # Ask the server for the list of projects
        d = self._plugin.network.send_packet(ListProjects.Query())
        d.add_callback(self._projects_listed)
        d.add_errback(self._plugin.logger.exception)

    def _projects_listed(self, reply):
        """Called when the projects list is received."""
        self._projects = reply.projects
        self._refresh_projects()

    def _refresh_projects(self):
        """Refreshes the projects table."""
        self._projects_table.setRowCount(len(self._projects))
        for i, project in enumerate(self._projects):
            item = QTableWidgetItem(project.name)
            item.setData(Qt.UserRole, project)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._projects_table.setItem(i, 0, item)

    def _project_clicked(self):
        """Called when a project item is clicked."""
        project = self._projects_table.selectedItems()[0].data(Qt.UserRole)
        self._file_label.setText("<b>File:</b> %s" % str(project.file))
        self._hash_label.setText("<b>Hash:</b> %s" % str(project.hash))
        self._type_label.setText("<b>Type:</b> %s" % str(project.type))
        self._date_label.setText("<b>Date:</b> %s" % str(project.date))

        # Ask the server for the list of databases
        d = self._plugin.network.send_packet(ListDatabases.Query(project.name))
        d.add_callback(partial(self._databases_listed))
        d.add_errback(self._plugin.logger.exception)

    def _databases_listed(self, reply):
        """Called when the databases list is received."""
        self._databases = reply.databases
        self._refresh_databases()

    def _refresh_databases(self):
        """Refreshes the table of databases."""

        def create_item(text, database):
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, database)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if database.tick == -1:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            return item

        self._databases_table.setRowCount(len(self._databases))
        for i, database in enumerate(self._databases):
            self._databases_table.setItem(
                i, 0, create_item(database.name, database)
            )
            self._databases_table.setItem(
                i, 1, create_item(database.date, database)
            )
            tick = str(database.tick) if database.tick != -1 else "<none>"
            self._databases_table.setItem(i, 2, create_item(tick, database))

    def _database_clicked(self):
        self._accept_button.setEnabled(True)

    def _database_double_clicked(self):
        self.accept()

    def get_result(self):
        """Get the project and database selected by the user."""
        project = self._projects_table.selectedItems()[0].data(Qt.UserRole)
        database = self._databases_table.selectedItems()[0].data(Qt.UserRole)
        return project, database


class SaveDialog(OpenDialog):
    """
    This dialog is shown to user to select which remote database to save. We
    extend the save dialog to reuse most of the UI setup code.
    """

    def __init__(self, plugin):
        super(SaveDialog, self).__init__(plugin)
        self._project = None

        # General setup of the dialog
        self.setWindowTitle("Save to Remote Server")
        icon_path = self._plugin.plugin_resource("upload.png")
        self.setWindowIcon(QIcon(icon_path))

        # Change the accept button text
        self._accept_button.setText("Save")

        # Add a button to create a project
        create_project_button = QPushButton("Create Project", self._left_side)
        create_project_button.clicked.connect(self._create_project_clicked)
        self._left_layout.addWidget(create_project_button)

        # Add a button to create a database
        self._create_database_button = QPushButton(
            "Create Database", self._databases_group
        )
        self._create_database_button.setEnabled(False)
        self._create_database_button.clicked.connect(
            self._create_database_clicked
        )
        self._databases_layout.addWidget(self._create_database_button)

    def _project_clicked(self):
        super(SaveDialog, self)._project_clicked()
        self._project = self._projects_table.selectedItems()[0].data(
            Qt.UserRole
        )
        self._create_database_button.setEnabled(True)

    def _create_project_clicked(self):
        dialog = CreateProjectDialog(self._plugin)
        dialog.accepted.connect(partial(self._create_project_accepted, dialog))
        dialog.exec_()

    def _create_project_accepted(self, dialog):
        """Called when the project creation dialog is accepted."""
        name = dialog.get_result()
        # Ensure we don't already have a project with that name
        if any(project.name == name for project in self._projects):
            failure = QMessageBox()
            failure.setIcon(QMessageBox.Warning)
            failure.setStandardButtons(QMessageBox.Ok)
            failure.setText("A project with that name already exists!")
            failure.setWindowTitle("New Project")
            icon_path = self._plugin.plugin_resource("upload.png")
            failure.setWindowIcon(QIcon(icon_path))
            failure.exec_()
            return

        # Get all the information we need and sent it to the server
        hash = ida_nalt.retrieve_input_file_md5().lower()
        # Remove the trailing null byte, if exists
        if hash.endswith(b'\x00'):
          hash = hash[0:-1]
        # This decode is safe, because we have an hash in hex format
        hash = hash.decode('utf-8')
        file = ida_nalt.get_root_filename()
        ftype = ida_loader.get_file_type_name()
        date_format = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(date_format)
        project = Project(name, hash, file, ftype, date)
        d = self._plugin.network.send_packet(CreateProject.Query(project))
        d.add_callback(partial(self._project_created, project))
        d.add_errback(self._plugin.logger.exception)

    def _project_created(self, project, _):
        """Called when the create project reply is received."""
        self._projects.append(project)
        self._refresh_projects()
        row = len(self._projects) - 1
        self._projects_table.selectRow(row)
        self._accept_button.setEnabled(False)

    def _refresh_projects(self):
        super(SaveDialog, self)._refresh_projects()
        hash = ida_nalt.retrieve_input_file_md5().lower()
        if hash.endswith(b'\x00'):
            hash = hash[0:-1]
        hash = hash.decode('utf-8')
        for row in range(self._projects_table.rowCount()):
            item = self._projects_table.item(row, 0)
            project = item.data(Qt.UserRole)
            if project.hash != hash:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)

    def _create_database_clicked(self):
        """Called when the create database button is clicked."""
        dialog = CreateDatabaseDialog(self._plugin)
        dialog.accepted.connect(
            partial(self._create_database_accepted, dialog)
        )
        dialog.exec_()

    def _create_database_accepted(self, dialog):
        """Called when the database creation dialog is accepted."""
        name = dialog.get_result()

        # Ensure we don't already have a database with that name
        if any(database.name == name for database in self._databases):
            failure = QMessageBox()
            failure.setIcon(QMessageBox.Warning)
            failure.setStandardButtons(QMessageBox.Ok)
            failure.setText("A database with that name already exists!")
            failure.setWindowTitle("New Database")
            icon_path = self._plugin.plugin_resource("upload.png")
            failure.setWindowIcon(QIcon(icon_path))
            failure.exec_()
            return

        # Get all the information we need and sent it to the server
        date_format = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(date_format)
        database = Database(self._project.name, name, date, -1)
        d = self._plugin.network.send_packet(CreateDatabase.Query(database))
        d.add_callback(partial(self._database_created, database))
        d.add_errback(self._plugin.logger.exception)

    def _database_created(self, database, _):
        """Called when the new database reply is received."""
        self._databases.append(database)
        self._refresh_databases()
        row = len(self._databases) - 1
        self._databases_table.selectRow(row)

    def _refresh_databases(self):
        super(SaveDialog, self)._refresh_databases()
        for row in range(self._databases_table.rowCount()):
            for col in range(3):
                item = self._databases_table.item(row, col)
                item.setFlags(item.flags() | Qt.ItemIsEnabled)


class CreateProjectDialog(QDialog):
    """The dialog shown when an user wants to create a project."""

    def __init__(self, plugin):
        super(CreateProjectDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        self._plugin.logger.debug("Create project dialog")
        self.setWindowTitle("Create Project")
        icon_path = plugin.plugin_resource("upload.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(100, 100)

        # Set up the layout and widgets
        layout = QVBoxLayout(self)

        self._nameLabel = QLabel("<b>Project Name</b>")
        layout.addWidget(self._nameLabel)
        self._nameEdit = QLineEdit()
        self._nameEdit.setValidator(QRegExpValidator(QRegExp("[a-zA-Z0-9-]+")))
        layout.addWidget(self._nameEdit)

        buttons = QWidget(self)
        buttons_layout = QHBoxLayout(buttons)
        create_button = QPushButton("Create")
        create_button.clicked.connect(self.accept)
        buttons_layout.addWidget(create_button)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(cancel_button)
        layout.addWidget(buttons)

    def get_result(self):
        """Get the name entered by the user."""
        return self._nameEdit.text()


class CreateDatabaseDialog(CreateProjectDialog):
    """
    The dialog shown when an user wants to create a database. We extend the
    create project dialog to avoid duplicating the UI setup code.
    """

    def __init__(self, plugin):
        super(CreateDatabaseDialog, self).__init__(plugin)
        self.setWindowTitle("Create Database")
        self._nameLabel.setText("<b>Database Name</b>")


class SettingsDialog(QDialog):
    """
    The dialog allowing an user to configure the plugin. It has multiple tabs
    used to group the settings by category (general, network, etc.).
    """

    def __init__(self, plugin):
        super(SettingsDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        self._plugin.logger.debug("Showing settings dialog")
        self.setWindowTitle("Settings")
        icon_path = self._plugin.plugin_resource("settings.png")
        self.setWindowIcon(QIcon(icon_path))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowCloseButtonHint)

        window_widget = QWidget(self)
        window_layout = QVBoxLayout(window_widget)
        tabs = QTabWidget(window_widget)
        window_layout.addWidget(tabs)

        # "General Settings" tab
        tab = QWidget(tabs)
        layout = QFormLayout(tab)
        layout.setFormAlignment(Qt.AlignVCenter)
        tabs.addTab(tab, "General Settings")

        user_widget = QWidget(tab)
        user_layout = QHBoxLayout(user_widget)
        layout.addRow(user_widget)

        # User color
        self._color_button = QPushButton("")
        self._color_button.setFixedSize(50, 30)

        def color_button_activated(_):
            self._set_color(qt_color=QColorDialog.getColor().rgb())

        self._color = self._plugin.config["user"]["color"]
        self._set_color(ida_color=self._color)
        self._color_button.clicked.connect(color_button_activated)
        user_layout.addWidget(self._color_button)

        # User name
        self._name_line_edit = QLineEdit()
        name = self._plugin.config["user"]["name"]
        self._name_line_edit.setText(name)
        user_layout.addWidget(self._name_line_edit)

        text = "Disable all user cursors"
        self._disable_all_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_all_cursors_checkbox)
        navbar_checked = not self._plugin.config["cursors"]["navbar"]
        funcs_checked = not self._plugin.config["cursors"]["funcs"]
        disasm_checked = not self._plugin.config["cursors"]["disasm"]
        all_checked = navbar_checked and funcs_checked and disasm_checked
        self._disable_all_cursors_checkbox.setChecked(all_checked)

        def state_changed(state):
            enabled = state == Qt.Unchecked
            self._disable_navbar_cursors_checkbox.setChecked(not enabled)
            self._disable_navbar_cursors_checkbox.setEnabled(enabled)
            self._disable_funcs_cursors_checkbox.setChecked(not enabled)
            self._disable_funcs_cursors_checkbox.setEnabled(enabled)
            self._disable_disasm_cursors_checkbox.setChecked(not enabled)
            self._disable_disasm_cursors_checkbox.setEnabled(enabled)

        self._disable_all_cursors_checkbox.stateChanged.connect(state_changed)

        style_sheet = """QCheckBox{ margin-left: 20px; }"""

        text = "Disable navigation bar user cursors"
        self._disable_navbar_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_navbar_cursors_checkbox)
        self._disable_navbar_cursors_checkbox.setChecked(navbar_checked)
        self._disable_navbar_cursors_checkbox.setEnabled(not all_checked)
        self._disable_navbar_cursors_checkbox.setStyleSheet(style_sheet)

        text = "Disable functions window user cursors"
        self._disable_funcs_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_funcs_cursors_checkbox)
        self._disable_funcs_cursors_checkbox.setChecked(funcs_checked)
        self._disable_funcs_cursors_checkbox.setEnabled(not all_checked)
        self._disable_funcs_cursors_checkbox.setStyleSheet(style_sheet)

        text = "Disable disassembly view user cursors"
        self._disable_disasm_cursors_checkbox = QCheckBox(text)
        layout.addRow(self._disable_disasm_cursors_checkbox)
        self._disable_disasm_cursors_checkbox.setChecked(disasm_checked)
        self._disable_disasm_cursors_checkbox.setEnabled(not all_checked)
        self._disable_disasm_cursors_checkbox.setStyleSheet(style_sheet)

        text = "Allow other users to send notifications"
        self._notifications_checkbox = QCheckBox(text)
        layout.addRow(self._notifications_checkbox)
        checked = self._plugin.config["user"]["notifications"]
        self._notifications_checkbox.setChecked(checked)

        # Log level
        debug_level_label = QLabel("Logging level: ")
        self._debug_level_combo_box = QComboBox()
        self._debug_level_combo_box.addItem("CRITICAL", logging.CRITICAL)
        self._debug_level_combo_box.addItem("ERROR", logging.ERROR)
        self._debug_level_combo_box.addItem("WARNING", logging.WARNING)
        self._debug_level_combo_box.addItem("INFO", logging.INFO)
        self._debug_level_combo_box.addItem("DEBUG", logging.DEBUG)
        self._debug_level_combo_box.addItem("TRACE", logging.TRACE)
        level = self._plugin.config["level"]
        index = self._debug_level_combo_box.findData(level)
        self._debug_level_combo_box.setCurrentIndex(index)
        layout.addRow(debug_level_label, self._debug_level_combo_box)

        # "Network Settings" tab
        tab = QWidget(tabs)
        layout = QVBoxLayout(tab)
        tab.setLayout(layout)
        tabs.addTab(tab, "Network Settings")

        top_widget = QWidget(tab)
        layout.addWidget(top_widget)
        top_layout = QHBoxLayout(top_widget)

        self._servers = list(self._plugin.config["servers"])
        self._servers_table = QTableWidget(len(self._servers), 2, self)
        top_layout.addWidget(self._servers_table)
        for i, server in enumerate(self._servers):
            # Server host and port
            item = QTableWidgetItem("%s:%d" % (server["host"], server["port"]))
            item.setData(Qt.UserRole, server)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if self._plugin.network.server == server:
                item.setFlags((item.flags() & ~Qt.ItemIsSelectable))
            self._servers_table.setItem(i, 0, item)

            # Server has SSL enabled?
            checkbox = QTableWidgetItem()
            state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
            checkbox.setCheckState(state)
            checkbox.setFlags((checkbox.flags() & ~Qt.ItemIsEditable))
            checkbox.setFlags((checkbox.flags() & ~Qt.ItemIsUserCheckable))
            if self._plugin.network.server == server:
                checkbox.setFlags((checkbox.flags() & ~Qt.ItemIsSelectable))
            self._servers_table.setItem(i, 1, checkbox)

        self._servers_table.setHorizontalHeaderLabels(("Servers", ""))
        horizontal_header = self._servers_table.horizontalHeader()
        horizontal_header.setSectionsClickable(False)
        horizontal_header.setSectionResizeMode(0, QHeaderView.Stretch)
        horizontal_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._servers_table.verticalHeader().setVisible(False)
        self._servers_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._servers_table.setSelectionMode(QTableWidget.SingleSelection)
        self._servers_table.itemClicked.connect(self._server_clicked)
        self._servers_table.itemDoubleClicked.connect(
            self._server_double_clicked
        )
        self._servers_table.setMaximumHeight(100)

        buttons_widget = QWidget(top_widget)
        buttons_layout = QVBoxLayout(buttons_widget)
        top_layout.addWidget(buttons_widget)

        # Add server button
        self._add_button = QPushButton("Add Server")
        self._add_button.clicked.connect(self._add_button_clicked)
        buttons_layout.addWidget(self._add_button)

        # Edit server button
        self._edit_button = QPushButton("Edit Server")
        self._edit_button.setEnabled(False)
        self._edit_button.clicked.connect(self._edit_button_clicked)
        buttons_layout.addWidget(self._edit_button)

        # Delete server button
        self._delete_button = QPushButton("Delete Server")
        self._delete_button.setEnabled(False)
        self._delete_button.clicked.connect(self._delete_button_clicked)
        buttons_layout.addWidget(self._delete_button)

        bottom_widget = QWidget(tab)
        bottom_layout = QFormLayout(bottom_widget)
        layout.addWidget(bottom_widget)

        # TCP Keep-Alive settings
        keep_cnt_label = QLabel("Keep-Alive Count: ")
        self._keep_cnt_spin_box = QSpinBox(bottom_widget)
        self._keep_cnt_spin_box.setRange(0, 86400)
        self._keep_cnt_spin_box.setValue(self._plugin.config["keep"]["cnt"])
        self._keep_cnt_spin_box.setSuffix(" packets")
        bottom_layout.addRow(keep_cnt_label, self._keep_cnt_spin_box)

        keep_intvl_label = QLabel("Keep-Alive Interval: ")
        self._keep_intvl_spin_box = QSpinBox(bottom_widget)
        self._keep_intvl_spin_box.setRange(0, 86400)
        self._keep_intvl_spin_box.setValue(
            self._plugin.config["keep"]["intvl"]
        )
        self._keep_intvl_spin_box.setSuffix(" seconds")
        bottom_layout.addRow(keep_intvl_label, self._keep_intvl_spin_box)

        keep_idle_label = QLabel("Keep-Alive Idle: ")
        self._keep_idle_spin_box = QSpinBox(bottom_widget)
        self._keep_idle_spin_box.setRange(0, 86400)
        self._keep_idle_spin_box.setValue(self._plugin.config["keep"]["idle"])
        self._keep_idle_spin_box.setSuffix(" seconds")
        bottom_layout.addRow(keep_idle_label, self._keep_idle_spin_box)

        # Buttons commons to all tabs
        actions_widget = QWidget(self)
        actions_layout = QHBoxLayout(actions_widget)

        # Cancel = do not save the changes and close the dialog
        def cancel(_):
            self.reject()

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(cancel)
        actions_layout.addWidget(cancel_button)

        # Reset = reset all settings from all tabs to default values
        reset_button = QPushButton("Reset")
        reset_button.clicked.connect(self._reset)
        actions_layout.addWidget(reset_button)

        # Save = save the changes and close the dialog
        def save(_):
            self._commit()
            self.accept()

        save_button = QPushButton("Save")
        save_button.clicked.connect(save)
        actions_layout.addWidget(save_button)
        window_layout.addWidget(actions_widget)

        # Do not allow the user to resize the dialog
        self.setFixedSize(
            window_widget.sizeHint().width(), window_widget.sizeHint().height()
        )

    def _set_color(self, ida_color=None, qt_color=None):
        """Sets the color of the user color button."""
        # IDA represents colors as 0xBBGGRR
        if ida_color is not None:
            r = ida_color & 255
            g = (ida_color >> 8) & 255
            b = (ida_color >> 16) & 255

        # Qt represents colors as 0xRRGGBB
        if qt_color is not None:
            r = (qt_color >> 16) & 255
            g = (qt_color >> 8) & 255
            b = qt_color & 255

        ida_color = r | g << 8 | b << 16
        qt_color = r << 16 | g << 8 | b

        # Set the stylesheet of the button
        css = "QPushButton {background-color: #%06x; color: #%06x;}"
        self._color_button.setStyleSheet(css % (qt_color, qt_color))
        self._color = ida_color

    def _server_clicked(self, _):
        self._edit_button.setEnabled(True)
        self._delete_button.setEnabled(True)

    def _server_double_clicked(self, _):
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        # If not the current server, connect to it
        if (
            not self._plugin.network.connected
            or self._plugin.network.server != server
        ):
            self._plugin.network.stop_server()
            self._plugin.network.connect(server)
        self.accept()

    def _add_button_clicked(self, _):
        dialog = ServerInfoDialog(self._plugin, "Add server")
        dialog.accepted.connect(partial(self._add_dialog_accepted, dialog))
        dialog.exec_()

    def _edit_button_clicked(self, _):
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        dialog = ServerInfoDialog(self._plugin, "Edit server", server)
        dialog.accepted.connect(partial(self._edit_dialog_accepted, dialog))
        dialog.exec_()

    def _delete_button_clicked(self, _):
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        self._servers.remove(server)
        self._plugin.save_config()
        self._servers_table.removeRow(item.row())
        self.update()

    def _add_dialog_accepted(self, dialog):
        """Called when the dialog to add a server is accepted."""
        server = dialog.get_result()
        self._servers.append(server)
        row_count = self._servers_table.rowCount()
        self._servers_table.insertRow(row_count)

        new_server = QTableWidgetItem(
            "%s:%d" % (server["host"], server["port"])
        )
        new_server.setData(Qt.UserRole, server)
        new_server.setFlags(new_server.flags() & ~Qt.ItemIsEditable)
        self._servers_table.setItem(row_count, 0, new_server)

        new_checkbox = QTableWidgetItem()
        state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
        new_checkbox.setCheckState(state)
        new_checkbox.setFlags((new_checkbox.flags() & ~Qt.ItemIsEditable))
        new_checkbox.setFlags(new_checkbox.flags() & ~Qt.ItemIsUserCheckable)
        self._servers_table.setItem(row_count, 1, new_checkbox)
        self.update()

    def _edit_dialog_accepted(self, dialog):
        """Called when the dialog to edit a server is accepted."""
        server = dialog.get_result()
        item = self._servers_table.selectedItems()[0]
        self._servers[item.row()] = server

        item.setText("%s:%d" % (server["host"], server["port"]))
        item.setData(Qt.UserRole, server)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)

        checkbox = self._servers_table.item(item.row(), 1)
        state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
        checkbox.setCheckState(state)
        self.update()

    def _reset(self, _):
        """Resets all the form elements to their default value."""
        config = self._plugin.default_config()

        self._name_line_edit.setText(config["user"]["name"])
        self._set_color(ida_color=config["user"]["color"])

        navbar_checked = not config["cursors"]["navbar"]
        funcs_checked = not config["cursors"]["funcs"]
        disasm_checked = not config["cursors"]["disasm"]
        all_checked = navbar_checked and funcs_checked and disasm_checked
        self._disable_all_cursors_checkbox.setChecked(all_checked)

        self._disable_navbar_cursors_checkbox.setChecked(navbar_checked)
        self._disable_navbar_cursors_checkbox.setEnabled(not all_checked)
        self._disable_funcs_cursors_checkbox.setChecked(funcs_checked)
        self._disable_funcs_cursors_checkbox.setEnabled(not all_checked)
        self._disable_disasm_cursors_checkbox.setChecked(disasm_checked)
        self._disable_disasm_cursors_checkbox.setEnabled(not all_checked)

        checked = config["user"]["notifications"]
        self._notifications_checkbox.setChecked(checked)

        index = self._debug_level_combo_box.findData(config["level"])
        self._debug_level_combo_box.setCurrentIndex(index)

        del self._servers[:]
        self._servers_table.clearContents()
        self._keep_cnt_spin_box.setValue(config["keep"]["cnt"])
        self._keep_intvl_spin_box.setValue(config["keep"]["intvl"])
        self._keep_idle_spin_box.setValue(config["keep"]["idle"])

    def _commit(self):
        """Commits all the changes made to the form elements."""
        name = self._name_line_edit.text()
        if self._plugin.config["user"]["name"] != name:
            old_name = self._plugin.config["user"]["name"]
            self._plugin.network.send_packet(UpdateUserName(old_name, name))
            self._plugin.config["user"]["name"] = name

        if self._plugin.config["user"]["color"] != self._color:
            name = self._plugin.config["user"]["name"]
            old_color = self._plugin.config["user"]["color"]
            packet = UpdateUserColor(name, old_color, self._color)
            self._plugin.network.send_packet(packet)
            self._plugin.config["user"]["color"] = self._color
            self._plugin.interface.widget.refresh()

        all_ = self._disable_all_cursors_checkbox.isChecked()
        checked = self._disable_navbar_cursors_checkbox.isChecked()
        self._plugin.config["cursors"]["navbar"] = not all_ and not checked
        checked = self._disable_funcs_cursors_checkbox.isChecked()
        self._plugin.config["cursors"]["funcs"] = not all_ and not checked
        checked = self._disable_disasm_cursors_checkbox.isChecked()
        self._plugin.config["cursors"]["disasm"] = not all_ and not checked

        checked = self._notifications_checkbox.isChecked()
        self._plugin.config["user"]["notifications"] = checked

        index = self._debug_level_combo_box.currentIndex()
        level = self._debug_level_combo_box.itemData(index)
        self._plugin.logger.setLevel(level)
        self._plugin.config["level"] = level

        self._plugin.config["servers"] = self._servers
        cnt = self._keep_cnt_spin_box.value()
        self._plugin.config["keep"]["cnt"] = cnt
        intvl = self._keep_intvl_spin_box.value()
        self._plugin.config["keep"]["intvl"] = intvl
        idle = self._keep_idle_spin_box.value()
        self._plugin.config["keep"]["idle"] = idle
        if self._plugin.network.client:
            self._plugin.network.client.set_keep_alive(cnt, intvl, idle)

        self._plugin.save_config()


class ServerInfoDialog(QDialog):
    """The dialog shown when an user creates or edits a server."""

    def __init__(self, plugin, title, server=None):
        super(ServerInfoDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        self._plugin.logger.debug("Showing server info dialog")
        self.setWindowTitle(title)
        icon_path = plugin.plugin_resource("settings.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(100, 100)

        # Setup the layout and widgets
        layout = QVBoxLayout(self)

        self._server_name_label = QLabel("<b>Server Host</b>")
        layout.addWidget(self._server_name_label)
        self._server_name = QLineEdit()
        self._server_name.setPlaceholderText("127.0.0.1")
        layout.addWidget(self._server_name)

        self._server_name_label = QLabel("<b>Server Port</b>")
        layout.addWidget(self._server_name_label)
        self._server_port = QLineEdit()
        self._server_port.setPlaceholderText("31013")
        layout.addWidget(self._server_port)

        self._no_ssl_checkbox = QCheckBox("Disable SSL")
        layout.addWidget(self._no_ssl_checkbox)

        # Set the form elements values if we have a base
        if server is not None:
            self._server_name.setText(server["host"])
            self._server_port.setText(str(server["port"]))
            self._no_ssl_checkbox.setChecked(server["no_ssl"])

        down_side = QWidget(self)
        buttons_layout = QHBoxLayout(down_side)
        self._add_button = QPushButton("OK")
        self._add_button.clicked.connect(self.accept)
        buttons_layout.addWidget(self._add_button)
        self._cancel_button = QPushButton("Cancel")
        self._cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(self._cancel_button)
        layout.addWidget(down_side)

    def get_result(self):
        """Get the server resulting from the form elements values."""
        return {
            "host": self._server_name.text() or "127.0.0.1",
            "port": int(self._server_port.text() or "31013"),
            "no_ssl": self._no_ssl_checkbox.isChecked(),
        }
