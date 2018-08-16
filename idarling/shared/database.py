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
import msgpack
import sqlite3

from .models import Repository, Branch
from .packets import Default, DefaultEvent


class Database(object):
    """
    An utility object used by the server, that be used to query
    asynchronously the underling SQL database.
    """

    def __init__(self, dbpath):
        """
        Initialize the database wrapper.

        :param dbpath: the database path
        """
        self._conn = sqlite3.connect(dbpath, check_same_thread=False)
        self._conn.isolation_level = None
        self._conn.row_factory = sqlite3.Row

    def initialize(self):
        """
        Creates all the tables used by the wrapper.
        """
        self._create('repos', [
            'name text not null',
            'hash text not null',
            'file text not null',
            'type text not null',
            'date text not null',
            'primary key (name)',
        ])
        self._create('branches', [
            'repo text not null',
            'name text not null',
            'date text not null',
            'foreign key(repo) references repos(name)',
            'primary key(repo, name)',
        ])
        self._create('events', [
            'repo text not null',
            'branch text not null',
            'tick integer not null',
            'dict blob not null',
            'foreign key(repo) references repos(name)',
            'foreign key(repo, branch) references branches(repo, name)',
            'primary key(repo, branch, tick)',
        ])

    def insert_repo(self, repo):
        """
        Inserts a new repository into the database.

        :param repo: the repository
        """
        self._insert('repos', Default.attrs(repo.__dict__))

    def select_repo(self, name):
        """
        Selects the repository with the given name.

        :param name: the name
        :return: the repository or None
        """
        objects = self.select_repos(name, 1)
        return objects[0] if objects else None

    def select_repos(self, name=None, limit=None):
        """
        Selects the repositories with the given name.

        :param name: the name, or None if all
        :param limit: the number of results
        :return: a list of the repositories
        """
        results = self._select('repos', {'name': name}, limit)
        return [Repository(**result) for result in results]

    def insert_branch(self, branch):
        """
        Inserts a new branch into the database.

        :param branch: the branch
        """
        attrs = Default.attrs(branch.__dict__)
        attrs.pop('tick')
        self._insert('branches', attrs)

    def select_branch(self, repo, name):
        """
        Selects the branch with the given name and repo.

        :param repo: the repository name
        :param name: the branch name
        :return: the branch or None
        """
        objects = self.select_branches(repo, name, 1)
        return objects[0] if objects else None

    def select_branches(self, repo=None, name=None, limit=None):
        """
        Selects the branches with the given repo and name.

        :param repo: the repository name, or None if all
        :param name: the branch name, or None if all
        :param limit: the number of results to return
        :return: a list of branches
        """
        results = self._select('branches', {'repo': repo, 'name': name}, limit)
        return [Branch(**result) for result in results]

    def insert_event(self, client, event):
        """
        Inserts a new event into the database.

        :param client: the client
        :param event: the event
        """
        dct = DefaultEvent.attrs(event.__dict__)
        self._insert('events', {
            'repo': client.repo,
            'branch': client.branch,
            'tick': event.tick,
            'dict': msgpack.packb(dct, use_bin_type=True)
        })

    def select_events(self, repo, branch, tick):
        """
        Get all events sent after the given ticks count.

        :param repo: the repository name
        :param branch: the branch name
        :param tick: the ticks count
        :return: a list of events
        """
        c = self._conn.cursor()
        sql = 'select * from events where repo = ? and branch = ? ' \
              'and tick > ? order by tick asc;'
        c.execute(sql, [repo, branch, tick])
        events = []
        for result in c.fetchall():
            dct = msgpack.unpackb(result['dict'], raw=False)
            dct['tick'] = result['tick']
            events.append(DefaultEvent.new(dct))
        return events

    def last_tick(self, repo, branch):
        """
        Get the last tick for the specified repo and branch.

        :param repo: the repo name
        :param branch: the branch name
        :return: the last tick
        """
        c = self._conn.cursor()
        sql = 'select tick from events where repo = ? and branch = ? ' \
              'order by tick desc limit 1;'
        c.execute(sql, [repo, branch])
        result = c.fetchone()
        return result['tick'] if result else 0

    def _create(self, table, cols):
        """
        Creates a table with the given name and columns.

        :param table: the table name
        :param cols: the columns
        """
        c = self._conn.cursor()
        sql = 'create table if not exists {} ({});'
        c.execute(sql.format(table, ', '.join(cols)))

    def _select(self, table, fields, limit=None):
        """
        Selects the rows of a table matching the given values.

        :param table: the table name
        :param fields: the fields and values to match
        :param limit: the number of results to return
        :return: the selected rows
        """
        c = self._conn.cursor()
        sql = 'select * from {}'.format(table)
        fields = {key: val for key, val in fields.items() if val}
        if len(fields):
            cols = ['{} = ?'.format(col) for col in fields.keys()]
            sql = (sql + ' where {}').format(' and '.join(cols))
        sql += ' limit {};'.format(limit) if limit else ';'
        c.execute(sql, list(fields.values()))
        return c.fetchall()

    def _insert(self, table, fields):
        """
        Inserts a row into a table with the given values.

        :param table: the table name
        :param fields: the field and values
        """
        c = self._conn.cursor()
        sql = 'insert into {} ({}) values ({});'
        keys = ', '.join(fields.keys())
        vals = ', '.join(['?'] * len(fields))
        c.execute(sql.format(table, keys, vals), list(fields.values()))
