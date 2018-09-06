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

from .tabs import TabCfgServer, TabCfgGeneral, TabCfgNetwork
from ..shared.commands import (
    GetBranches,
    GetRepositories,
    NewBranch,
    NewRepository,
    UserColorChanged,
    UserRenamed,
)
from ..shared.models import Branch, Repository

logger = logging.getLogger("IDArling.Interface")


class OpenDialog(QDialog):
    """
    The open dialog allowing an user to select a remote database to download.
    """

    def __init__(self, plugin):
        """
        Initialize the open dialog.

        :param plugin: the plugin instance
        """
        super(OpenDialog, self).__init__()
        self._plugin = plugin
        self._repos = None
        self._branches = None

        # General setup of the dialog
        logger.debug("Showing the database selection dialog")
        self.setWindowTitle("Open from Remote Server")
        icon_path = self._plugin.resource("download.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(900, 450)

        # Setup of the layout and widgets
        layout = QVBoxLayout(self)
        main = QWidget(self)
        main_layout = QHBoxLayout(main)
        layout.addWidget(main)

        self._left_side = QWidget(main)
        self._left_layout = QVBoxLayout(self._left_side)
        self._repos_table = QTableWidget(0, 1, self._left_side)
        self._repos_table.setHorizontalHeaderLabels(("Repositories",))
        self._repos_table.horizontalHeader().setSectionsClickable(False)
        self._repos_table.horizontalHeader().setStretchLastSection(True)
        self._repos_table.verticalHeader().setVisible(False)
        self._repos_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._repos_table.setSelectionMode(QTableWidget.SingleSelection)
        self._repos_table.itemSelectionChanged.connect(self._repo_clicked)
        self._left_layout.addWidget(self._repos_table)
        main_layout.addWidget(self._left_side)

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
        main_layout.addWidget(right_side)

        self._branches_group = QGroupBox("Branches", right_side)
        self._branches_layout = QVBoxLayout(self._branches_group)
        self._branches_table = QTableWidget(0, 3, self._branches_group)
        labels = ("Name", "Date", "Ticks")
        self._branches_table.setHorizontalHeaderLabels(labels)
        horizontal_header = self._branches_table.horizontalHeader()
        horizontal_header.setSectionsClickable(False)
        horizontal_header.setSectionResizeMode(0, horizontal_header.Stretch)
        self._branches_table.verticalHeader().setVisible(False)
        self._branches_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._branches_table.setSelectionMode(QTableWidget.SingleSelection)
        self._branches_table.itemSelectionChanged.connect(self._branch_clicked)
        branch_double_clicked = self._branch_double_clicked
        self._branches_table.itemDoubleClicked.connect(branch_double_clicked)
        self._branches_layout.addWidget(self._branches_table)
        right_layout.addWidget(self._branches_group)

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

        # Ask the server for the list of repositories
        d = self._plugin.network.send_packet(GetRepositories.Query())
        d.add_callback(self._on_get_repos)
        d.add_errback(logger.exception)

    def _on_get_repos(self, reply):
        """
        Called when the list of repositories is received.

        :param reply: the reply from the server
        """
        self._repos = reply.repos
        self._refresh_repos()

    def _refresh_repos(self):
        """
        Refreshes the table of repositories.
        """
        self._repos_table.setRowCount(len(self._repos))
        for i, repo in enumerate(self._repos):
            item = QTableWidgetItem(repo.name)
            item.setData(Qt.UserRole, repo)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._repos_table.setItem(i, 0, item)

    def _repo_clicked(self):
        """
        Called when a repository item is clicked, will update the display.
        """
        repo = self._repos_table.selectedItems()[0].data(Qt.UserRole)
        self._file_label.setText("<b>File:</b> %s" % str(repo.file))
        self._hash_label.setText("<b>Hash:</b> %s" % str(repo.hash))
        self._type_label.setText("<b>Type:</b> %s" % str(repo.type))
        self._date_label.setText("<b>Date:</b> %s" % str(repo.date))

        # Ask the server for the list of branches
        d = self._plugin.network.send_packet(GetBranches.Query(repo.name))
        d.add_callback(partial(self._on_get_branches))
        d.add_errback(logger.exception)

    def _on_get_branches(self, reply):
        """
        Called when the list of branches is received.

        :param reply: the reply from the server
        """
        self._branches = reply.branches
        self._refresh_branches()

    def _refresh_branches(self):
        """
        Refreshes the table of branches.
        """

        def create_item(text, branch):
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, branch)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if branch.tick == -1:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            return item

        self._branches_table.setRowCount(len(self._branches))
        for i, branch in enumerate(self._branches):
            self._branches_table.setItem(
                i, 0, create_item(branch.name, branch)
            )
            self._branches_table.setItem(
                i, 1, create_item(branch.date, branch)
            )
            tick = str(branch.tick) if branch.tick != -1 else "<none>"
            self._branches_table.setItem(i, 2, create_item(tick, branch))

    def _branch_clicked(self):
        """
        Called when a branch item is clicked.
        """
        self._accept_button.setEnabled(True)

    def _branch_double_clicked(self):
        """
        Called when a branch item is double-clicked.
        """
        self.accept()

    def get_result(self):
        """
        Get the result (repo, branch) from this dialog.

        :return: the result
        """
        repo = self._repos_table.selectedItems()[0].data(Qt.UserRole)
        return repo, self._branches_table.selectedItems()[0].data(Qt.UserRole)


class SaveDialog(OpenDialog):
    """
    The save dialog allowing an user to select a remote database to upload to.
    """

    def __init__(self, plugin):
        """
        Initialize the save dialog.

        :param plugin: the plugin instance
        """
        super(SaveDialog, self).__init__(plugin)
        self._repo = None

        # General setup of the dialog
        self.setWindowTitle("Save to Remote Server")
        icon_path = self._plugin.resource("upload.png")
        self.setWindowIcon(QIcon(icon_path))

        # Setup the layout and widgets
        self._accept_button.setText("Save")

        new_repo_button = QPushButton("New Repository", self._left_side)
        new_repo_button.clicked.connect(self._new_repo_clicked)
        self._left_layout.addWidget(new_repo_button)

        self._new_branch_button = QPushButton(
            "New Branch", self._branches_group
        )
        self._new_branch_button.setEnabled(False)
        self._new_branch_button.clicked.connect(self._new_branch_clicked)
        self._branches_layout.addWidget(self._new_branch_button)

    def _repo_clicked(self):
        super(SaveDialog, self)._repo_clicked()
        self._repo = self._repos_table.selectedItems()[0].data(Qt.UserRole)
        self._new_branch_button.setEnabled(True)

    def _new_repo_clicked(self):
        """
        Called when the new repository button is clicked.
        """
        dialog = NewRepoDialog(self._plugin)
        dialog.accepted.connect(partial(self._new_repo_accepted, dialog))
        dialog.exec_()

    def _new_repo_accepted(self, dialog):
        """
        Called when the new repository dialog is accepted by the user.

        :param dialog: the dialog
        """
        name = dialog.get_result()
        if any(repo.name == name for repo in self._repos):
            failure = QMessageBox()
            failure.setIcon(QMessageBox.Warning)
            failure.setStandardButtons(QMessageBox.Ok)
            failure.setText("A repository with that name already exists!")
            failure.setWindowTitle("New Repository")
            icon_path = self._plugin.resource("upload.png")
            failure.setWindowIcon(QIcon(icon_path))
            failure.exec_()
            return

        hash = ida_nalt.retrieve_input_file_md5().lower()
        file = ida_nalt.get_root_filename()
        type = ida_loader.get_file_type_name()
        date_format = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(date_format)
        repo = Repository(name, hash, file, type, date)
        d = self._plugin.network.send_packet(NewRepository.Query(repo))
        d.add_callback(partial(self._on_new_repo, repo))
        d.add_errback(logger.exception)

    def _on_new_repo(self, repo, _):
        """
        Called when the new repository reply is received.

        :param repo: the new repo
        """
        self._repos.append(repo)
        self._refresh_repos()
        row = len(self._repos) - 1
        self._repos_table.selectRow(row)
        self._accept_button.setEnabled(False)

    def _refresh_repos(self):
        super(SaveDialog, self)._refresh_repos()
        hash = ida_nalt.retrieve_input_file_md5().lower()
        for row in range(self._repos_table.rowCount()):
            item = self._repos_table.item(row, 0)
            repo = item.data(Qt.UserRole)
            if repo.hash != hash:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)

    def _new_branch_clicked(self):
        """
        Called when the new branch button is clicked.
        """
        dialog = NewBranchDialog(self._plugin)
        dialog.accepted.connect(partial(self._new_branch_accepted, dialog))
        dialog.exec_()

    def _new_branch_accepted(self, dialog):
        """
        Called when the new branch dialog is accepted by the user.

        :param dialog: the dialog
        """
        name = dialog.get_result()
        if any(br.name == name for br in self._branches):
            failure = QMessageBox()
            failure.setIcon(QMessageBox.Warning)
            failure.setStandardButtons(QMessageBox.Ok)
            failure.setText("A branch with that name already exists!")
            failure.setWindowTitle("New Branch")
            icon_path = self._plugin.resource("upload.png")
            failure.setWindowIcon(QIcon(icon_path))
            failure.exec_()
            return

        date_format = "%Y/%m/%d %H:%M"
        date = datetime.datetime.now().strftime(date_format)
        branch = Branch(self._repo.name, name, date, -1)
        d = self._plugin.network.send_packet(NewBranch.Query(branch))
        d.add_callback(partial(self._on_new_branch, branch))
        d.add_errback(logger.exception)

    def _on_new_branch(self, branch, _):
        """
        Called when the new branch reply is received.

        :param branch: the new branch
        """
        self._branches.append(branch)
        self._refresh_branches()
        row = len(self._branches) - 1
        self._branches_table.selectRow(row)

    def _refresh_branches(self):
        super(SaveDialog, self)._refresh_branches()
        for row in range(self._branches_table.rowCount()):
            for col in range(3):
                item = self._branches_table.item(row, col)
                item.setFlags(item.flags() | Qt.ItemIsEnabled)


class NewRepoDialog(QDialog):
    """
    The dialog allowing an user to create a new repository.
    """

    def __init__(self, plugin):
        """
        Initialize the new repo dialog.

        :param plugin: the plugin instance
        """
        super(NewRepoDialog, self).__init__()

        # General setup of the dialog
        logger.debug("New repo dialog")
        self.setWindowTitle("New Repository")
        icon_path = plugin.resource("upload.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(100, 100)

        layout = QVBoxLayout(self)

        self._nameLabel = QLabel("<b>Repository Name</b>")
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
        """
        Get the user-specified name from this dialog.

        :return: the name
        """
        return self._nameEdit.text()


class NewBranchDialog(NewRepoDialog):
    """
    The dialog allowing an user to create a new branch.
    """

    def __init__(self, plugin):
        """
        Initialize the new branch dialog.

        :param plugin: the plugin instance
        """
        super(NewBranchDialog, self).__init__(plugin)
        self.setWindowTitle("New Branch")
        self._nameLabel.setText("<b>Branch Name</b>")


class SettingsDialog(QDialog):
    """
    The dialog allowing an user to select a remote server to connect to.
    """

    def __init__(self, plugin):
        """
        Initialize the settings dialog.

        :param plugin: the plugin instance
        """
        super(SettingsDialog, self).__init__()
        self._plugin = plugin

        # General setup of the dialog
        logger.debug("Showing settings dialog")
        self.setWindowTitle("Settings")
        iconPath = self._plugin.resource('settings.png')
        self.setWindowIcon(QIcon(iconPath))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowCloseButtonHint)

        windowWidget = QWidget(self)
        windowLayout = QVBoxLayout(windowWidget)

        # Settings Tabs Container
        tabs = QTabWidget(windowWidget)
        windowLayout.addWidget(tabs)

        # General Settings tab
        tab_general = TabCfgGeneral(self, tabs)
        tabs.addTab(tab_general, "General Settings")

        # Server Settings tab
        tab_servers = TabCfgServer(self, tabs)
        tabs.addTab(tab_servers, "Server Settings")

        # Network Settings tab
        tab_network = TabCfgNetwork(self, tabs)
        tabs.addTab(tab_network, "Network Settings")

        # Action Buttons Container
        actionsWidget = QWidget(windowWidget)
        actionsLayout = QHBoxLayout(actionsWidget)
        windowLayout.addWidget(actionsWidget)

        # Save button
        def save(_):
            self._commit()
            self.accept()
        saveButton = QPushButton("Save")
        saveButton.clicked.connect(save)
        actionsLayout.addWidget(saveButton)

        # Reset button
        resetButton = QPushButton("Reset to Default")
        resetButton.clicked.connect(self._reset)
        actionsLayout.addWidget(resetButton)

        # Cancel button
        def cancel(_):
            self.reject()
        cancelButton = QPushButton("Cancel")
        cancelButton.clicked.connect(cancel)
        actionsLayout.addWidget(cancelButton)

        self.setFixedSize(
            windowWidget.sizeHint().width(),
            windowWidget.sizeHint().height()
        )

    def _set_color(self, ida_color=None, qt_color=None):
        """
        Sets the Qt color of the button.

        :param ida_color: the IDA color
        :param qt_color: the Qt color
        """
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

        css = "QPushButton {background-color: #%06x; color: #%06x;}"
        self._color_button.setStyleSheet(css % (qt_color, qt_color))
        self._color = ida_color

    # Here we would like to provide some public methods
    # So methods of widgets do not need to be exported there
    def _single_click(self, _):
        """
        Called when a server item is clicked.
        """
        self._edit_button.setEnabled(True)
        self._delete_button.setEnabled(True)

    def _double_click(self, _):
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        if (
            not self._plugin.network.connected
            or self._plugin.network.server != server
        ):
            self._plugin.network.stop_server()
            self._plugin.network.connect(server)
        self.accept()

    def _add_button_clicked(self, _):
        """
        Called when the add button is clicked.
        """
        dialog = ServerInfoDialog(self._plugin, "Add server")
        dialog.accepted.connect(partial(self._add_dialog_accepted, dialog))
        dialog.exec_()

    def _edit_button_clicked(self, _):
        """
        Called when the add button is clicked.
        """
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        dialog = ServerInfoDialog(self._plugin, "Edit server", server)
        dialog.accepted.connect(partial(self._edit_dialog_accepted, dialog))
        dialog.exec_()

    def _add_dialog_accepted(self, dialog):
        """
        Called when the add server dialog is accepted by the user.

        :param dialog: the add server dialog
        """
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
        """
        Called when the add server dialog is accepted by the user.

        :param dialog: the edit server dialog
        """
        server = dialog.get_result()
        item = self._servers_table.selectedItems()[0]
        self._servers[item.row()] = server

        item.set_text("%s:%d" % (server["host"], server["port"]))
        item.setData(Qt.UserRole, server)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)

        checkbox = self._servers_table.item(item.row(), 1)
        state = Qt.Unchecked if server["no_ssl"] else Qt.Checked
        checkbox.setCheckState(state)
        self.update()

    def _delete_button_clicked(self, _):
        """
        Called when the delete button is clicked.
        """
        item = self._servers_table.selectedItems()[0]
        server = item.data(Qt.UserRole)
        self._servers.remove(server)
        self._plugin.save_config()
        self._servers_table.removeRow(item.row())
        self.update()

    def _reset(self, _):
        config = self._plugin.default_config()

        self._name_line_edit.setText(config["user"]["name"])
        self._set_color(ida_color=config["user"]["color"])

        checked = config["user"]["navbar_colorizer"]
        self._navbar_colorizer_checkbox.setChecked(checked)
        checked = config["user"]["notifications"]
        self._notifications_checkbox.setChecked(checked)

        index = self._debug_level_combo_box.findData(config["level"])
        self._debug_level_combo_box.setCurrentIndex(index)

        self._servers = []
        self._servers_table.clearContents()
        self._keep_cnt_spin_box.setValue(config["keep"]["cnt"])
        self._keep_intvl_spin_box.setValue(config["keep"]["intvl"])
        self._keep_idle_spin_box.setValue(config["keep"]["idle"])

    def _commit(self):
        name = self._name_line_edit.text()
        if self._plugin.config["user"]["name"] != name:
            old_name = self._plugin.config["user"]["name"]
            self._plugin.network.send_packet(UserRenamed(old_name, name))
            self._plugin.config["user"]["name"] = name

        if self._plugin.config["user"]["color"] != self._color:
            name = self._plugin.config["user"]["name"]
            old_color = self._plugin.config["user"]["color"]
            packet = UserColorChanged(name, old_color, self._color)
            self._plugin.network.send_packet(packet)
            self._plugin.config["user"]["color"] = self._color

        checked = self._navbar_colorizer_checkbox.isChecked()
        self._plugin.config["user"]["navbar_colorizer"] = checked
        checked = self._notifications_checkbox.isChecked()

        self._plugin.config["user"]["notifications"] = checked

        from idarling.plugin import logger

        index = self._debug_level_combo_box.currentIndex()
        level = self._debug_level_combo_box.itemData(index)
        logger.setLevel(level)
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
    """
    The dialog allowing an user to add a remote server to connect to.
    """

    def __init__(self, plugin, title, server=None):
        """
        Initialize the network setting dialog.

        :param plugin: the plugin instance
        :param title: the dialog title
        :param server: the current server information
        """
        super(ServerInfoDialog, self).__init__()

        # General setup of the dialog
        logger.debug("Showing server info dialog")
        self.setWindowTitle(title)
        icon_path = plugin.resource("settings.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(100, 100)

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
        """
        Get the result (server, port) from this dialog.

        :return: the result
        """
        new_server = {
            "host": self._server_name.text() or "127.0.0.1",
            "port": int(self._server_port.text() or "31013"),
            "no_ssl": self._no_ssl_checkbox.isChecked(),
        }
        return new_server
