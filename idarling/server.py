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
import argparse
import logging
import os
import signal
import sys
import traceback

from PyQt5.QtCore import QCoreApplication, QTimer

from .shared.server import Server


class DedicatedServer(Server):
    """
    The dedicated server implementation.
    """

    @staticmethod
    def start_logging():
        Server.add_trace_level()
        logger = logging.getLogger("IDArling.Server")

        # Get path to the log file
        log_dir = os.path.join(os.path.dirname(__file__), "logs")
        log_dir = os.path.abspath(log_dir)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        log_path = os.path.join(log_dir, "idarling.%s.log" % os.getpid())

        # Configure the logger
        log_format = "[%(asctime)s][%(levelname)s] %(message)s"
        formatter = logging.Formatter(fmt=log_format, datefmt="%H:%M:%S")

        # Log to the console
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        # Log to the log file
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger

    def __init__(self, ssl, level, parent=None):
        logger = DedicatedServer.start_logging()
        logger.setLevel(getattr(logging, level))
        Server.__init__(self, logger, ssl, parent)

    def local_file(self, filename):
        files_dir = os.path.join(os.path.dirname(__file__), "files")
        files_dir = os.path.abspath(files_dir)
        if not os.path.exists(files_dir):
            os.makedirs(files_dir)
        return os.path.join(files_dir, filename)


def start(args):
    """
    The entry point of a Python program.
    """
    app = QCoreApplication(sys.argv)
    sys.excepthook = traceback.print_exception

    server = DedicatedServer(args.ssl, args.level)
    server.start(args.host, args.port)

    # Allow the use of Ctrl-C to stop the server
    def sigint_handler(_, __):
        server.stop()
        app.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    def safe_timer(timeout, func, *args, **kwargs):
        def timer_event():
            try:
                func(*args, **kwargs)
            finally:
                QTimer.singleShot(timeout, timer_event)

        QTimer.singleShot(timeout, timer_event)

    safe_timer(50, lambda: None)
    return app.exec_()


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--help", action="help", help="show this help message and exit"
    )

    parser.add_argument(
        "-h",
        "--host",
        type=str,
        default="127.0.0.1",
        help="the hostname to start listening on",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=31013,
        help="the port to start listening on",
    )

    security = parser.add_mutually_exclusive_group(required=True)
    security.add_argument(
        "--ssl",
        type=str,
        nargs=2,
        metavar=("fullchain.pem", "privkey.pem"),
        help="the certificate and private key files",
    )
    security.add_argument(
        "--no-ssl", action="store_true", help="disable SSL (not recommended)"
    )

    levels = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"]
    parser.add_argument(
        "-l",
        "--level",
        type=str,
        choices=levels,
        default="INFO",
        help="the log level",
    )

    start(parser.parse_args())
