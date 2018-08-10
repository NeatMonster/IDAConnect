# quick and dirty database migration for msgpack

from __future__ import print_function

import os
import json
import msgpack
import re


import idarling
from idarling.shared.database import Database


def is_printable(s):
    try:
        ascii = s.encode('ascii')
    except UnicodeEncodeError:
        return False

    rx = (rb'^[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!'
          rb'"#$%&\'()*+,./:;<=>?@\[\]^_`{|}~\s-]*$')
    if re.match(rx, ascii):
        return True
    return False


def json_loads_byteified(json_text):
    def _byteify(data, ignore_dicts=False):
        if isinstance(data, str):
            # Total hack to determine if something is really unicode
            if is_printable(data):
                return data
            else:
                return data.encode('raw_unicode_escape')

        if isinstance(data, list):
            return [_byteify(item, ignore_dicts=True) for item in data]

        if isinstance(data, dict) and not ignore_dicts:
            return {_byteify(key, ignore_dicts=True):
                    _byteify(value, ignore_dicts=True)
                    for key, value in data.items()}

        return data

    return _byteify(
        json.loads(json_text, object_hook=_byteify),
        ignore_dicts=True)


def find_database():
    db_path = os.path.join(
        os.path.dirname(idarling.__file__),
        'files',
        'database.db')
    if os.path.exists(db_path):
        return os.path.abspath(db_path)


def migrate_branches(c):
    # Fix the foreign key on branches
    c.execute("CREATE TABLE branches_new (%s)" % ",".join([
        'repo text not null',
        'name text not null',
        'date text not null',
        'foreign key(repo) references repos(name)',
        'primary key(repo, name)',
    ]))
    c.execute("INSERT INTO branches_new SELECT * FROM branches")
    c.execute("DROP TABLE branches")
    c.execute("ALTER TABLE branches_new RENAME TO branches")


def migrate_events(c):
    # Migrate JSON to msgpack
    c.execute("CREATE TABLE events_new (%s)" % ", ".join([
        'repo text not null',
        'branch text not null',
        'tick integer not null',
        'dict blob not null',
        'foreign key(repo) references repos(name)',
        'foreign key(repo, branch) references branches(repo, name)',
        'primary key(repo, branch, tick)',
    ]))

    c.execute("SELECT * from events")
    events = c.fetchall()
    insert_sql = "insert into events_new values (?, ?, ?, ?)"
    for row in events:
        loaded = json_loads_byteified(row['dict'])
        packed = msgpack.packb(loaded, use_bin_type=True)
        c.execute(insert_sql, (row['repo'], row['branch'],
                               row['tick'], packed))

    c.execute("DROP TABLE events")
    c.execute("ALTER TABLE events_new RENAME TO events")
    c.execute("PRAGMA foreign_key_check")


def migrate(path):
    db = Database(path)
    cnx = db._conn

    c = cnx.cursor()
    c.execute("PRAGMA foreign_keys=OFF")
    c.execute("BEGIN")

    migrate_branches(c)
    migrate_events(c)

    c.execute("COMMIT")
    c.execute("PRAGMA foreign_keys=ON")


def main():
    path = find_database()
    if path is None:
        print("Database not found")
        return

    print("Starting migration...")
    migrate(path)


if __name__ == "__main__":
    main()
