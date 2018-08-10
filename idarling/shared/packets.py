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
import sys
import collections
import itertools

# Allow testing for unicode strings
if sys.version_info.major == 3:
    unicode = str


def with_metaclass(meta, *bases):
    """
    Python 2 and 3 compatible way to add a meta-class.

    :param meta: the meta class
    :param bases: the base classes
    :return: the new type
    """
    class metaclass(type):
        def __new__(cls, name, this_bases, d):
            return meta(name, bases, d)

        @classmethod
        def __prepare__(cls, name, _):
            return meta.__prepare__(name, bases)
    return type.__new__(metaclass, 'temporary_class', (), {})


class Serializable(object):
    """
    A base class for an object than can be serialized. More specifically,
    such objects can be read from and written into a Python dictionary.
    """

    @classmethod
    def new(cls, dct):
        """
        Create a new instance of an object.

        :param dct: the dictionary
        :return: the object
        """
        obj = cls.__new__(cls)
        object.__init__(obj)
        obj.parse(dct)
        return obj

    def build(self, dct):
        """
        Write the object into the dictionary.

        :param dct: the dictionary
        :return: the dictionary
        """
        pass

    def parse(self, dct):
        """
        Read the object from the dictionary.

        :param dct: the dictionary
        :return: the object
        """
        pass


class Default(Serializable):
    """
    An object that is automatically serialized using its attributes dictionary.
    """

    @staticmethod
    def attrs(dct):
        """
        Get a filtered version of an attributes dictionary. This method
        currently simply removes the private attributes of the object.

        :param dct: the dictionary
        :return: the filtered dictionary
        """
        def try_decode(s):
            # Force attribute keys to be unicode on the wire.
            if not isinstance(s, unicode):
                return s.decode('utf-8')
            return s

        return {try_decode(key): val for key, val in dct.items()
                if not key.startswith('_')}

    def build_default(self, dct):
        """
        Write the object to the dictionary using its attributes dictionary.

        :param dct: the dictionary
        """
        dct.update(Default.attrs(self.__dict__))

    def parse_default(self, dct):
        """
        Read the object from the dictionary using its attributes dictionary.

        :param dct: the dictionary
        """
        self.__dict__.update(Default.attrs(dct))


class PacketFactory(type):
    """
    A factory class used to instantiate packets as they come from the network.
    """
    _PACKETS = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        """
        Register a new packet class in the factory.

        :param name: the name of the new class
        :param bases: the base classes of the new class
        :param attrs: the attributes of the new class
        :return: the newly created class
        """
        cls = super(PacketFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__type__ is not None \
                and cls.__type__ not in PacketFactory._PACKETS:
            PacketFactory._PACKETS[cls.__type__] = cls
        return cls

    @classmethod
    def get_class(mcs, dct, server=False):
        """
        Get the class corresponding to the given dictionary.

        :param dct: the dictionary
        :param server: server client?
        :return: the packet class
        """
        cls = PacketFactory._PACKETS[dct[u'type']]
        if type(cls) != mcs:
            cls = type(cls).get_class(dct, server)
        return cls


class Packet(with_metaclass(PacketFactory, Serializable)):
    """
    The base class for every packet received. Currently, the packet can
    only be of two kinds: either it is an event or a command.
    """
    __type__ = None

    def __init__(self):
        """
        Initialize a packet.
        """
        super(Packet, self).__init__()
        assert self.__type__ is not None, "__type__ not implemented"

    @staticmethod
    def parse_packet(dct, server=False):
        """
        Parse a packet from a dictionary.

        :param dct: the dictionary
        :param server: server client?
        :return: the packet
        """
        cls = PacketFactory.get_class(dct, server)
        packet = cls.new(dct)
        if isinstance(packet, Reply):
            packet.trigger_initback()
        return packet

    def build_packet(self):
        """
        Build a packet into a dictionary.

        :return: the dictionary
        """
        dct = collections.defaultdict(collections.defaultdict)
        self.build(dct)
        return dct

    def __repr__(self):
        """
        Return a textual representation of a packet. Currently, it is only
        used to pretty-print the packet's contents into the console.

        :return: the representation
        """
        name = self.__class__.__name__
        if isinstance(self, Query) or isinstance(self, Reply):
            name = self.__parent__.__name__ + '.' + name
        attrs = [u'{}={}'.format(k, v) for k, v
                 in Default.attrs(self.__dict__).items()]
        return u'{}({})'.format(name, u', '.join(attrs))


class PacketDeferred(object):
    """
    An Twisted-like deferred object that supports a standard callback, as well
    as a new callback triggered when the expected packet is being instantiated.
    """

    def __init__(self):
        """
        Initialize the packet deferred.
        """
        super(PacketDeferred, self).__init__()
        self._errback = None

        self._callback = None
        self._callresult = None
        self._called = False

        self._initback = None
        self._initresult = None
        self._inited = False

    def add_callback(self, callback):
        """
        Register a callback for this deferred.

        :param callback: the callback function
        :return: the self instance
        """
        self._callback = callback
        if self._called:
            self._run_callback()
        return self

    def add_errback(self, errback):
        """
        Register an errback for this deferred.

        :param errback: the errback function
        :return: the self instance
        """
        self._errback = errback
        return self

    def add_initback(self, initback):
        """
        Register an initback for this deferred.

        :param initback: the initback function
        :return: the self instance
        """
        self._initback = initback
        if self._inited:
            self._run_initback()
        return self

    def callback(self, result):
        """
        Triggers the callback function.

        :param result: the result
        """
        if self._called:
            raise RuntimeError("Callback already triggered")
        self._called = True
        self._callresult = result
        self._run_callback()

    def initback(self, result):
        """
        Trigger the initback function.

        :param result: the result
        """
        if self._inited:
            raise RuntimeError("Initback already triggered")
        self._inited = True
        self._initresult = result
        self._run_initback()

    def _run_callback(self):
        """
        Internal method that calls the callback/errback function.
        """
        if self._callback:
            try:
                self._callback(self._callresult)
            except Exception as e:
                self._errback(e)

    def _run_initback(self):
        """
        Internal method that call the initback/errback function.
        """
        if self._initback:
            try:
                self._initback(self._initresult)
            except Exception as e:
                self._errback(e)


class EventFactory(PacketFactory):
    """
    A factory class used to instantiate the packets of type event.
    """
    _EVENTS = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        cls = super(EventFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__event__ is not None \
                and cls.__event__ not in EventFactory._EVENTS:
            EventFactory._EVENTS[cls.__event__] = cls
        return cls

    @classmethod
    def get_class(mcs, dct, server=False):
        if server:  # Server only knows about DefaultEvent
            return DefaultEvent

        cls = EventFactory._EVENTS[dct[u'event_type']]
        if type(cls) != mcs:
            cls = type(cls).get_class(dct, server)
        return cls


class Event(with_metaclass(EventFactory, Packet)):
    """
    The base class of every packet of type event received.
    """
    __type__ = u'event'
    __event__ = None

    def __init__(self):
        super(Event, self).__init__()
        assert self.__event__ is not None, "__event__ not implemented"
        self._tick = 0

    def build(self, dct):
        dct[u'type'] = self.__type__
        dct[u'event_type'] = self.__event__
        dct[u'tick'] = self._tick
        self.build_event(dct)
        return dct

    def parse(self, dct):
        self._tick = dct.pop('tick')
        self.parse_event(dct)
        return self

    def build_event(self, dct):
        """
        Event subclasses should implement this method.

        :param dct: the dictionary
        """
        pass

    def parse_event(self, dct):
        """
        Event subclasses should implement this method.

        :param dct: the dictionary
        """
        pass

    @property
    def tick(self):
        """
        Get the tick of the event.

        :return: the tick
        """
        return self._tick

    @tick.setter
    def tick(self, tick):
        """
        Set the tick of the event.

        :param tick: the tick
        """
        self._tick = tick


class DefaultEvent(Default, Event):
    """
    A mix-in class for events that can be serialized from their attributes.
    """

    def build_event(self, dct):
        self.build_default(dct)

    def parse_event(self, dct):
        self.parse_default(dct)


class CommandFactory(PacketFactory):
    """
    A factory class used to instantiate the packets of type command.
    """
    _COMMANDS = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        cls = super(CommandFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__command__ is not None \
                and cls.__command__ not in CommandFactory._COMMANDS:
            if issubclass(cls, ParentCommand):
                cls.Query.__parent__ = cls
                cls.Query.__command__ = cls.__command__ + '_query'
                CommandFactory._COMMANDS[cls.Query.__command__] = cls.Query

                cls.Reply.__parent__ = cls
                cls.Reply.__command__ = cls.__command__ + '_reply'
                CommandFactory._COMMANDS[cls.Reply.__command__] = cls.Reply
            else:
                CommandFactory._COMMANDS[cls.__command__] = cls
        return cls

    @classmethod
    def get_class(mcs, dct, server=False):
        cls = CommandFactory._COMMANDS[dct[u'command_type']]
        if type(cls) != mcs:
            cls = type(cls).get_class(dct, server)
        return cls


class Command(with_metaclass(CommandFactory, Packet)):
    """
    The base class of every packet of type command received.
    """
    __type__ = u'command'
    __command__ = None

    def __init__(self):
        super(Command, self).__init__()
        assert self.__command__ is not None, "__command__ not implemented"

    def build(self, dct):
        dct[u'type'] = self.__type__
        dct[u'command_type'] = self.__command__
        self.build_command(dct)
        return dct

    def parse(self, dct):
        self.parse_command(dct)
        return self

    def build_command(self, dct):
        """
        Command subclasses should implement this method.

        :param dct: the dictionary
        """
        pass

    def parse_command(self, dct):
        """
        Command subclasses should implement this method.

        :param dct: the dictionary
        """
        pass


class DefaultCommand(Default, Command):
    """
    A mix-in class for commands that can be serialized from their attributes.
    """

    def build_command(self, dct):
        self.build_default(dct)

    def parse_command(self, dct):
        self.parse_default(dct)


class ParentCommand(Command):
    """
    An inner class that must used in order to link queries with replies.
    """
    __callbacks__ = {}
    Query, Reply = None, None


class Query(Packet):
    """
    A class that must be inherited by commands expecting a reply.
    """
    __parent__ = None

    _NEXT_ID = itertools.count()

    def __init__(self):
        """
        Initialize a query command.
        """
        super(Query, self).__init__()
        self._id = Query._NEXT_ID.next()

    def build(self, dct):
        super(Query, self).build(dct)
        dct[u'__id__'] = self._id
        return dct

    def parse(self, dct):
        super(Query, self).parse(dct)
        self._id = dct[u'__id__']
        return self

    @property
    def id(self):
        """
        Get the identifier of the query packet.

        :return: the id
        """
        return self._id

    def register_callback(self, d):
        """
        Register a callback for when the corresponding reply will be received.

        :param: the deferred to use
        """
        self.__parent__.__callbacks__[self._id] = d


class Reply(Packet):
    """
    A class that must be inherited by commands sent in response to a query.
    """
    __parent__ = None

    def __init__(self, query):
        """
        Initialize a reply command.

        :param query: the query we're replying to
        """
        super(Reply, self).__init__()
        self._id = query.id

    def build(self, dct):
        super(Reply, self).build(dct)
        dct[u'__id__'] = self._id
        return dct

    def parse(self, dct):
        super(Reply, self).parse(dct)
        self._id = dct[u'__id__']
        return self

    @property
    def id(self):
        """
        Get the identifier of the reply packet.

        :return: the id
        """
        return self._id

    def trigger_callback(self):
        """
        Trigger the finalization callback of the corresponding query.
        """
        d = self.__parent__.__callbacks__[self._id]
        d.callback(self)
        del self.__parent__.__callbacks__[self._id]

    def trigger_initback(self):
        """
        Trigger the initialization callback of the corresponding query.
        """
        d = self.__parent__.__callbacks__[self._id]
        d.initback(self)


class Container(Command):
    """
    A class that must be implemented by commands that will contain a raw
    stream of bytes (payload). In reality, the payload will follow the command.
    """

    @staticmethod
    def __new__(cls, *args, **kwargs):
        """
        Create a new instance of a container.

        :return: the instance
        """
        self = super(Container, cls).__new__(cls)
        self._upback = None
        self._downback = None
        return self

    def __init__(self):
        """
        Initialize a container.
        """
        super(Container, self).__init__()
        self._size = 0
        self._content = None
        self._upback = None
        self._downback = None

    def build(self, dct):
        super(Container, self).build(dct)
        dct[u'__size__'] = len(self._content)
        return dct

    def parse(self, dct):
        self._size = dct[u'__size__']
        super(Container, self).parse(dct)
        return self

    @property
    def content(self):
        """
        Get the content of the packet.

        :return: the content
        """
        return self._content

    @content.setter
    def content(self, content):
        """
        Set the content of the packet.

        :param content: the content
        """
        self._content = content
        self._size = len(content)

    @property
    def size(self):
        """
        Get the size of the content.

        :return: the size
        """
        return self._size

    @size.setter
    def size(self, size):
        """
        Set the size of the content.

        :param size: the size
        """
        self._size = size

    @property
    def upback(self):
        """
        Get the callback that will be called every time some data is sent.

        :return: the callback
        """
        return self._upback

    @upback.setter
    def upback(self, upback):
        """
        Set the callback that will be called every time some data is sent.

        :param upback: the callback
        """
        self._upback = upback

    @property
    def downback(self):
        """
        Get the callback that will be called every time some data is received.

        :return: the callback
        """
        return self._downback

    @downback.setter
    def downback(self, downback):
        """
        Set the callback that will be called every time some data is received.

        :param downback: the callback
        """
        self._downback = downback
