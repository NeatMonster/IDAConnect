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
from PyQt5.QtWidgets import QFormLayout, QLabel, QSpinBox, QWidget


class _TabCfgNetwork:
    _instance = None  # Keep instance reference. Singleton.

    def __init__(self, program, parent):
        if _TabCfgNetwork._instance:
            raise ValueError("You should only create TabCfgServer once")
        _TabCfgNetwork._instance = self
        self.program = program
        self.parent = parent

    def get(self):
        parent = self.parent
        program = self.program

        tab = QWidget(parent)
        layout = QFormLayout(tab)

        keep_cnt_label = QLabel("Keep-Alive Count: ")
        program._keep_cnt_spin_box = QSpinBox(tab)
        program._keep_cnt_spin_box.setRange(0, 86400)
        program._keep_cnt_spin_box.setValue(
            program._plugin.config["keep"]["cnt"]
        )
        program._keep_cnt_spin_box.setSuffix(" packets")
        layout.addRow(keep_cnt_label, program._keep_cnt_spin_box)

        keep_intvl_label = QLabel("Keep-Alive Interval: ")
        program._keep_intvl_spin_box = QSpinBox(keep_intvl_label)
        program._keep_intvl_spin_box.setRange(0, 86400)
        program._keep_intvl_spin_box.setValue(
            program._plugin.config["keep"]["intvl"]
        )
        program._keep_intvl_spin_box.setSuffix(" seconds")
        layout.addRow(keep_intvl_label, program._keep_intvl_spin_box)

        keep_idle_label = QLabel("Keep-Alive Idle: ")
        program._keep_idle_spin_box = QSpinBox(keep_idle_label)
        program._keep_idle_spin_box.setRange(0, 86400)
        program._keep_idle_spin_box.setValue(
            program._plugin.config["keep"]["idle"]
        )
        program._keep_idle_spin_box.setSuffix(" seconds")
        layout.addRow(keep_idle_label, program._keep_idle_spin_box)

        return tab
