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
import json
import logging
import os
import random

import ida_diskio
import ida_idaapi
import ida_kernwin

from .core.core import Core
from .interface.interface import Interface
from .network.network import Network
from .shared.utils import start_logging


class Plugin(ida_idaapi.plugin_t):
    """
    This is the main class of the plugin. It subclasses plugin_t as required
    by IDA. It holds the modules of plugin, which themselves provides the
    functionality of the plugin (hooking/events, interface, networking, etc.).
    """

    # Mandatory definitions
    PLUGIN_NAME = "IDArling"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "The IDArling Team"

    # These flags specify that the plugin should persist between databases
    # loading and saving, and should not have a menu entry.
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE
    comment = "Collaborative Reverse Engineering plugin"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    @staticmethod
    def description():
        """Return the description displayed in the console."""
        return "{} v{}".format(Plugin.PLUGIN_NAME, Plugin.PLUGIN_VERSION)

    @staticmethod
    def plugin_resource(filename):
        """
        Return the absolute path to a plugin resource located within the
        plugin's installation folder (should be within idarling/resources).
        """
        plugin_path = os.path.abspath(os.path.dirname(__file__))
        return os.path.join(plugin_path, "resources", filename)

    @staticmethod
    def user_resource(directory, filename):
        """
        Return the absolute path to a resource located in the user directory.
        It should be:
        * %APPDATA%\\Roaming\\Hex-Rays\\IDA Pro\\plugin\\idarling under Windows
        * $HOME/.idapro/plugins/idarling under Linux and MacOS.
        """
        user_dir = ida_diskio.get_user_idadir()
        plug_dir = os.path.join(user_dir, "plugins")
        local_dir = os.path.join(plug_dir, "idarling")
        res_dir = os.path.join(local_dir, directory)
        if not os.path.exists(res_dir):
            os.makedirs(res_dir, 493)  # 0755
        return os.path.join(res_dir, filename)

    @staticmethod
    def default_config():
        """
        Return the default configuration options. This is used to initialize
        the configuration file the first time the plugin is launched, and also
        when the user is resetting the settings via the dialog.
        """
        r, g, b = colorsys.hls_to_rgb(random.random(), 0.5, 1.0)
        color = int(b * 255) << 16 | int(g * 255) << 8 | int(r * 255)
        return {
            "level": logging.INFO,
            "servers": [],
            "keep": {"cnt": 4, "intvl": 15, "idle": 240},
            "cursors": {"navbar": True, "funcs": True, "disasm": True},
            "user": {"color": color, "name": "unnamed", "notifications": True},
        }

    def __init__(self):
        # Check if the plugin is running with IDA terminal
        if not ida_kernwin.is_idaq():
            raise RuntimeError("IDArling cannot be used in terminal mode")

        # Load the default configuration
        self._config = self.default_config()
        # Then setup the default logger
        log_path = self.user_resource("logs", "idarling.%s.log" % os.getpid())
        level = self.config["level"]
        self._logger = start_logging(log_path, "IDArling.Plugin", level)

        self._core = Core(self)
        self._interface = Interface(self)
        self._network = Network(self)

    @property
    def config(self):
        return self._config

    @property
    def logger(self):
        return self._logger

    @property
    def core(self):
        return self._core

    @property
    def interface(self):
        return self._interface

    @property
    def network(self):
        return self._network

    def init(self):
        """
        This method is called when IDA is loading the plugin. It will first
        load the configuration file, then initialize all the modules.
        """
        try:
            self.load_config()

            self._interface.install()
            self._network.install()
            self._core.install()
        except Exception as e:
            self._logger.error("Failed to initialize")
            self._logger.exception(e)
            skip = ida_idaapi.PLUGIN_SKIP
            return skip

        self._print_banner()
        self._logger.info("Initialized properly")
        keep = ida_idaapi.PLUGIN_KEEP
        return keep

    def _print_banner(self):
        """Print the banner that you see in the console."""
        copyright = "(c) %s" % self.PLUGIN_AUTHORS
        self._logger.info("-" * 75)
        self._logger.info("%s - %s" % (self.description(), copyright))
        self._logger.info("-" * 75)

    def term(self):
        """
        This method is called when IDA is unloading the plugin. It will
        terminated all the modules, then save the configuration file.
        """
        try:
            self._core.uninstall()
            self._network.uninstall()
            self._interface.uninstall()

            self.save_config()
        except Exception as e:
            self._logger.error("Failed to terminate properly")
            self._logger.exception(e)
            return

        self._logger.info("Terminated properly")

    def run(self, _):
        """
        This method is called when IDA is running the plugin as a script.
        Because IDArling isn't runnable per se, we need to return False.
        """
        ida_kernwin.warning("IDArling cannot be run as a script")
        return False

    def load_config(self):
        """
        Load the configuration file. It is a JSON file that contains all the
        settings of the plugin. The configured log level is set here.
        """
        config_path = self.user_resource("files", "config.json")
        if not os.path.isfile(config_path):
            return
        with open(config_path, "rb") as config_file:
            try:
                self._config.update(json.loads(config_file.read()))
            except ValueError:
                self._logger.warning("Couldn't load config file")
                return
            self._logger.setLevel(self._config["level"])
            self._logger.debug("Loaded config: %s" % self._config)

    def save_config(self):
        """Save the configuration file."""
        config_path = self.user_resource("files", "config.json")
        with open(config_path, "w") as config_file:
            config_file.write(json.dumps(self._config))
            self._logger.debug("Saved config: %s" % self._config)
