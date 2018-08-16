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
import os
import socket
import ssl

from .database import Database
from .commands import (GetRepositories, GetBranches,
                       NewRepository, NewBranch,
                       UploadDatabase, DownloadDatabase,
                       Subscribe, Unsubscribe)
from .packets import Command, Event
from .sockets import ClientSocket, ServerSocket


class ServerClient(ClientSocket):
    """
    The client (server-side) implementation.
    """

    def __init__(self, logger, parent=None):
        ClientSocket.__init__(self, logger, parent)
        self._repo = None
        self._branch = None
        self._handlers = {}

    def connect(self, sock):
        ClientSocket.connect(self, sock)

        # Add host and port as a prefix to our logger
        prefix = '%s:%d' % sock.getpeername()

        class CustomAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                return '(%s) %s' % (prefix, msg), kwargs
        self._logger = CustomAdapter(self._logger, {})
        self._logger.info("Connected")

        # Setup command handlers
        self._handlers = {
            GetRepositories.Query: self._handle_get_repositories,
            GetBranches.Query: self._handle_get_branches,
            NewRepository.Query: self._handle_new_repository,
            NewBranch.Query: self._handle_new_branch,
            UploadDatabase.Query: self._handle_upload_database,
            DownloadDatabase.Query: self._handle_download_database,
            Subscribe: self._handle_subscribe,
            Unsubscribe: self._handle_unsubscribe,
        }

    @property
    def repo(self):
        """
        Get the current repository.

        :return: the name
        """
        return self._repo

    @property
    def branch(self):
        """
        Get the current branch.

        :return: the name
        """
        return self._branch

    def disconnect(self, err=None):
        ClientSocket.disconnect(self, err)
        self.parent().unregister_client(self)
        self._logger.info("Disconnected")

    def recv_packet(self, packet):
        if isinstance(packet, Command):
            # Call the corresponding handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            if not self._repo or not self._branch:
                self._logger.warning(
                    "Received a packet from an unsubscribed client")
                return True

            # Check for de-synchronization
            tick = self.parent().database.last_tick(self.repo, self.branch)
            if tick >= packet.tick:
                self._logger.warning("De-synchronization detected!")
                packet.tick = tick + 1

            # Save the event into the database
            self.parent().database.insert_event(self, packet)

            # Forward the event to the other clients
            def should_forward(client):
                return client.repo == self._repo \
                    and client.branch == self._branch and client != self

            for client in self.parent().find_clients(should_forward):
                client.send_packet(packet)
        else:
            return False
        return True

    def _handle_get_repositories(self, query):
        repos = self.parent().database.select_repos()
        self.send_packet(GetRepositories.Reply(query, repos))

    def _handle_get_branches(self, query):
        branches = self.parent().database.select_branches(query.repo)
        for branch in branches:
            branchInfo = branch.repo, branch.name
            fileName = '%s_%s.idb' % branchInfo
            filePath = self.parent().local_file(fileName)
            if os.path.isfile(filePath):
                branch.tick = self.parent().database.last_tick(*branchInfo)
            else:
                branch.tick = -1
        self.send_packet(GetBranches.Reply(query, branches))

    def _handle_new_repository(self, query):
        self.parent().database.insert_repo(query.repo)
        self.send_packet(NewRepository.Reply(query))

    def _handle_new_branch(self, query):
        self.parent().database.insert_branch(query.branch)
        self.send_packet(NewBranch.Reply(query))

    def _handle_upload_database(self, query):
        branch = self.parent().database.select_branch(query.repo, query.branch)
        fileName = '%s_%s.idb' % (branch.repo, branch.name)
        filePath = self.parent().local_file(fileName)

        # Write the file received to disk
        with open(filePath, 'wb') as outputFile:
            outputFile.write(query.content)
        self._logger.info("Saved file %s" % fileName)
        self.send_packet(UploadDatabase.Reply(query))

    def _handle_download_database(self, query):
        branch = self.parent().database.select_branch(query.repo, query.branch)
        fileName = '%s_%s.idb' % (branch.repo, branch.name)
        filePath = self.parent().local_file(fileName)

        # Read file from disk and sent it
        reply = DownloadDatabase.Reply(query)
        with open(filePath, 'rb') as inputFile:
            reply.content = inputFile.read()
        self.send_packet(reply)

    def _handle_subscribe(self, packet):
        self._repo = packet.repo
        self._branch = packet.branch
        self.parent().register_client(self)

        # Send all missed events
        events = self.parent().database.select_events(self._repo, self._branch,
                                                      packet.tick)
        self._logger.debug('Sending %d missed events' % len(events))
        for event in events:
            self.send_packet(event)

    def _handle_unsubscribe(self, _):
        self.parent().unregister_client(self)
        self._repo = None
        self._branch = None


class Server(ServerSocket):
    """
    The server implementation used by dedicated and integrated.
    """

    def __init__(self, logger, ssl, parent=None):
        ServerSocket.__init__(self, logger, parent)
        self._clients = []
        self._database = Database(self.local_file('database.db'))
        self._database.initialize()
        self._ssl = ssl

    def start(self, host, port=0):
        """
        Starts the server on the specified host and port.

        :param host: the host
        :param port: the port
        :return: did the operation succeed?
        """
        self._logger.info("Starting server on %s:%d" % (host, port))
        if self._ssl:
            cert, key = self._ssl
            self._ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self._ssl.load_cert_chain(certfile=cert, keyfile=key)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except socket.error as e:
            self._logger.warning("Could not start server")
            self._logger.exception(e)
            return False
        sock.settimeout(0)
        sock.setblocking(0)
        sock.listen(5)
        self.connect(sock)
        return True

    def stop(self):
        """
        Stops the server.

        :return: did the operation succeed?
        """
        self._logger.info("Shutting down server")
        for client in self._clients:
            client.disconnect()
        self.disconnect()
        return True

    @property
    def host(self):
        """
        Gets the host name.

        :return: the host name
        """
        return self._socket.getsockname()[0]

    @property
    def port(self):
        """
        Gets the port number.
        :return:
        """
        return self._socket.getsockname()[1]

    def _accept(self, sock):
        client = ServerClient(self._logger, self)
        if self._ssl:
            sock = self._ssl.wrap_socket(sock, server_side=True)
        sock.settimeout(0)
        sock.setblocking(0)
        client.connect(sock)

    def local_file(self, filename):
        """
        Get the absolute path of a local file.

        :param filename: the file name
        :return: the path
        """
        raise NotImplementedError("local_file() not implemented")

    def find_clients(self, func):
        """
        Find all the clients matching the specified criterion.

        :param func: the filtering function
        :return: the matching clients
        """
        return filter(func, self._clients)

    def register_client(self, client):
        """
        Add a client to the list of connected clients.

        :param client: the client
        """
        if client not in self._clients:
            self._clients.append(client)

    def unregister_client(self, client):
        """
        Remove a client to the list of connected clients.

        :param client: the client
        """
        if client in self._clients:
            self._clients.remove(client)

    @property
    def database(self):
        """
        Get the server's database.

        :return: the database
        """
        return self._database
