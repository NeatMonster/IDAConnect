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
import collections
import errno
import msgpack
import socket
import ssl

from PyQt5.QtCore import QCoreApplication, QEvent, QObject, QSocketNotifier

from .packets import Packet, PacketDeferred, Query, Reply, Container


class PacketEvent(QEvent):
    """
    A Qt-event fired when a new packet is received by the client.
    """

    def __init__(self):
        """
        Initializes the new packet event.
        """
        evtype = QEvent.Type(QEvent.registerEventType())
        super(PacketEvent, self).__init__(evtype)


class ClientSocket(QObject):
    """
    A class wrapping a Python socket and integrated into the Qt event loop.
    """
    MAX_READ_SIZE = 4096
    MAX_WRITE_SIZE = 65535

    def __init__(self, logger, parent=None):
        """
        Initializes the client socket.

        :param logger: the logger to user
        """
        QObject.__init__(self, parent)
        self._logger = logger
        self._socket = None
        self._server = parent and isinstance(parent, ServerSocket)

        self._unpacker = msgpack.Unpacker(raw=False)
        self._read_buffer = bytearray()
        self._read_notifier = None
        self._read_packet = None

        self._write_buffer = bytearray()
        self._write_notifier = None
        self._write_packet = None

        self._connected = False
        self._outgoing = collections.deque()
        self._incoming = collections.deque()

    @property
    def connected(self):
        """
        Returns if the socket is connected.

        :return: is connected?
        """
        return self._connected

    def connect(self, sock):
        """
        Wraps the socket with the current object.

        :param sock: the socket
        """
        self._read_notifier = QSocketNotifier(sock.fileno(),
                                              QSocketNotifier.Read, self)
        self._read_notifier.activated.connect(self._notify_read)
        self._read_notifier.setEnabled(True)

        self._write_notifier = QSocketNotifier(sock.fileno(),
                                               QSocketNotifier.Write, self)
        self._write_notifier.activated.connect(self._notify_write)
        self._write_notifier.setEnabled(False)

        self._socket = sock
        self._connected = True

    def disconnect(self, err=None):
        """
        Terminates the current connection.

        :param err: the reason or None
        """
        if not self._socket:
            return
        if err:
            self._logger.warning("Connection lost")
            self._logger.exception(err)
        self._read_notifier.setEnabled(False)
        self._write_notifier.setEnabled(False)
        try:
            self._socket.close()
        except socket.error:
            pass
        self._socket = None
        self._connected = False

    def _notify_read(self):
        """
        Callback called when some data is ready to be read on the socket.
        """
        # Read as much data as is available
        while True:
            try:
                data = self._socket.recv(ClientSocket.MAX_READ_SIZE)
                if not data:
                    self.disconnect()
                    break
            except socket.error as e:
                if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK) \
                        and not isinstance(e, ssl.SSLWantReadError) \
                        and not isinstance(e, ssl.SSLWantWriteError):
                    self.disconnect(e)
                break  # No more data available
            self._unpacker.feed(data)

        for raw_packet in self._unpacker:
            if self._read_packet is None:
                try:
                    self._read_packet = Packet.parse_packet(raw_packet,
                                                            self._server)
                except Exception as e:
                    msg = "Invalid packet received: %r" % raw_packet
                    self._logger.warning(msg)
                    self._logger.exception(e)
                    continue
                if isinstance(self._read_packet, Container):
                    continue
            else:
                # Trigger the downback
                # total = self._read_packet.size
                # if self._read_packet.downback:
                #     self._read_packet.downback(min(avail, total), total)

                # raw_packet should be a bytestring containing the payload
                assert isinstance(raw_packet, bytes)
                self._read_packet.content = raw_packet

            self._incoming.append(self._read_packet)
            self._read_packet = None

        if self._incoming:
            QCoreApplication.instance().postEvent(self, PacketEvent())

    def _notify_write(self):
        """
        Callback called when some data is ready to written on the socket.
        """
        while True:
            if not self._write_buffer:
                if not self._outgoing:
                    break  # No more packets to send
                self._write_packet = self._outgoing.popleft()

                try:
                    packed = msgpack.packb(self._write_packet.build_packet(),
                                           use_bin_type=True)
                except Exception as e:
                    msg = "Invalid packet being sent: %s" % self._write_packet
                    self._logger.warning(msg)
                    self._logger.exception(e)
                    continue

                # Write the container's content
                self._write_buffer.extend(packed)
                if isinstance(self._write_packet, Container):
                    packed = msgpack.packb(self._write_packet.content,
                                           use_bin_type=True)
                    self._write_buffer.extend(packed)
                    self._write_packet.size += len(packed)

            # Send as many bytes as possible
            try:
                count = min(len(self._write_buffer),
                            ClientSocket.MAX_WRITE_SIZE)
                sent = self._socket.send(self._write_buffer[:count])
                self._write_buffer = self._write_buffer[sent:]
            except socket.error as e:
                if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK) \
                        and not isinstance(e, ssl.SSLWantReadError) \
                        and not isinstance(e, ssl.SSLWantWriteError):
                    self.disconnect(e)
                break  # Can't write anything

            # Trigger the upback
            if isinstance(self._write_packet, Container) \
                    and self._write_packet.upback:
                self._write_packet.size -= sent
                total = len(self._write_packet.content)
                sent = max(total - self._write_packet.size, 0)
                self._write_packet.upback(sent, total)
                break

        if not self._write_buffer:
            self._write_notifier.setEnabled(False)

    def event(self, event):
        """
        Callback called when a Qt event is fired.

        :param event: the event
        :return: was the event handled?
        """
        if isinstance(event, PacketEvent):
            self._dispatch()
            event.accept()
            return True
        else:
            event.ignore()
            return False

    def _dispatch(self):
        """
        Callback called when a packet event is fired.
        """
        while self._incoming:
            packet = self._incoming.popleft()
            self._logger.debug("Received packet: %s" % packet)

            # Notify for replies
            if isinstance(packet, Reply):
                packet.trigger_callback()

            # Otherwise forward to the subclass
            elif not self.recv_packet(packet):
                self._logger.warning("Unhandled packet received: %s" % packet)

    def send_packet(self, packet):
        """
        Sends a packet the other party.

        :param packet: the packet
        :return: a packet deferred if a reply is expected
        """
        if not self._connected:
            self._logger.warning("Sending packet while disconnected")
            return None

        self._logger.debug("Sending packet: %s" % packet)

        # Enqueue the packet
        self._outgoing.append(packet)
        if not self._write_notifier.isEnabled():
            self._write_notifier.setEnabled(True)

        # Queries return a packet deferred
        if isinstance(packet, Query):
            d = PacketDeferred()
            packet.register_callback(d)
            return d
        return None

    def recv_packet(self, packet):
        """
        Receives a packet from the other party.

        :param packet: the packet
        :return: has the packet been handled?
        """
        raise NotImplementedError("recv_packet() not implemented")


class ServerSocket(QObject):
    """
    A class wrapping a server socket and integrated into the Qt event loop.
    """

    def __init__(self, logger, parent=None):
        """
        Initialize the server socket.

        :param logger: the logger to use
        """
        QObject.__init__(self, parent)
        self._logger = logger
        self._socket = None
        self._connected = False
        self._accept_notifier = None

    @property
    def connected(self):
        """
        Returns if the socket is connected.

        :return: is connected?
        """
        return self._connected

    def connect(self, sock):
        """
        Wraps the socket with the current object.

        :param sock: the socket
        """
        self._accept_notifier = QSocketNotifier(sock.fileno(),
                                                QSocketNotifier.Read, self)
        self._accept_notifier.activated.connect(self._notify_accept)
        self._accept_notifier.setEnabled(True)

        self._socket = sock
        self._connected = True

    def disconnect(self, err=None):
        """
        Terminates the current connection.

        :param err: the reason or None
        """
        if not self._socket:
            return
        if err:
            self._logger.warning("Connection lost")
            self._logger.exception(err)
        self._accept_notifier.setEnabled(False)
        try:
            self._socket.close()
        except socket.error:
            pass
        self._socket = None
        self._connected = False

    def _notify_accept(self):
        """
        Callback called when a client is connecting.
        """
        while True:
            try:
                sock, address = self._socket.accept()
            except socket.error as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                self.disconnect(e)
                break
            self._accept(sock)

    def _accept(self, socket):
        """
        Handles the client who newly connected.

        :param socket: the socket
        """
        raise NotImplementedError('accept() is not implemented')
