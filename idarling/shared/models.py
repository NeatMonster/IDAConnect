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
from __future__ import unicode_literals

from .packets import Default


class Model(Default):
    """
    An object that can be serialized before being sent over the network,
    but that can also be saved into the server SQL database.
    """

    def build(self, dct):
        self.build_default(dct)
        return dct

    def parse(self, dct):
        self.parse_default(dct)
        return self

    def __repr__(self):
        """
        Return a textual representation of the object. It will mainly be used
        for pretty-printing into the console.

        :return: the representation
        """
        attrs = ', '.join(['{}={}'.format(key, val) for key, val in
                           Default.attrs(self.__dict__).items()])
        return '{}({})'.format(self.__class__.__name__, attrs)


class Repository(Model):
    """
    The class representing a repository.
    """

    def __init__(self, name, hash, file, type, date):
        """
        Initialize a repository.

        :param name: the repository name
        :param hash: the hash of the input file
        :param file: the name of the input file
        :param type: the type of the input file
        :param date: the date of creation
        """
        super(Repository, self).__init__()
        self.name = name
        self.hash = hash
        self.file = file
        self.type = type
        self.date = date


class Branch(Model):
    """
    The class representing a branch.
    """

    def __init__(self, repo, name, date, tick=0):
        """
        Initialize a branch.

        :param repo: the name of the repo
        :param name: the name of the branch
        :param date: the date of creation
        :param tick: the last tick received
        """
        super(Branch, self).__init__()
        self.repo = repo
        self.name = name
        self.date = date
        self.tick = tick
