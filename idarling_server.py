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

from idarling.shared.server import Server


class DedicatedServer(Server):
    """
    The dedicated server implementation.
    """

    def __init__(self, ssl, parent=None):
        logger = self.start_logging()
        Server.__init__(self, logger, ssl, parent)

    def local_file(self, filename):
        filesDir = os.path.join(os.path.dirname(__file__), 'files')
        filesDir = os.path.abspath(filesDir)
        if not os.path.exists(filesDir):
            os.makedirs(filesDir)
        return os.path.join(filesDir, filename)

    def start_logging(self):
        logger = logging.getLogger('IDArling.Server')

        # Get path to the log file
        logDir = os.path.join(os.path.dirname(__file__), 'logs')
        logDir = os.path.abspath(logDir)
        if not os.path.exists(logDir):
            os.makedirs(logDir)
        logPath = os.path.join(logDir, 'idarling.%s.log' % os.getpid())

        # Configure the logger
        # logger.setLevel(logging.DEBUG)
        logFormat = '[%(asctime)s][%(levelname)s] %(message)s'
        formatter = logging.Formatter(fmt=logFormat, datefmt='%H:%M:%S')

        # Log to the console
        streamHandler = logging.StreamHandler()
        streamHandler.setFormatter(formatter)
        logger.addHandler(streamHandler)

        # Log to the log file
        fileHandler = logging.FileHandler(logPath)
        fileHandler.setFormatter(formatter)
        logger.addHandler(fileHandler)

        return logger


def main(args):
    """
    The entry point of a Python program.
    """
    app = QCoreApplication(sys.argv)
    sys.excepthook = traceback.print_exception

    server = DedicatedServer(args.ssl)
    server.start(args.host, args.port)

    # Allow the use of Ctrl-C to stop the server
    def sigint_handler(signum, frame):
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--help', action='help',
                        help='show this help message and exit')

    parser.add_argument('-h', '--host', type=str, default='127.0.0.1',
                        help='the hostname to start listening on')
    parser.add_argument('-p', '--port', type=int, default=31013,
                        help='the port to start listening on')

    security = parser.add_mutually_exclusive_group(required=True)
    security.add_argument('--ssl', type=str, nargs=2,
                          metavar=('fullchain.pem', 'privkey.pem'),
                          help='the certificate and private key files')
    security.add_argument('--no-ssl', action='store_true',
                          help='disable SSL (not recommended)')

    main(parser.parse_args())
