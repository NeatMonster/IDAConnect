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
from .models import Repository, Branch
from .packets import (Command, DefaultCommand, ParentCommand,
                      Query as IQuery, Reply as IReply, Container)


class GetRepositories(ParentCommand):
    __command__ = u'get_repos'

    class Query(IQuery, DefaultCommand):
        pass

    class Reply(IReply, Command):

        def __init__(self, query, repos):
            super(GetRepositories.Reply, self).__init__(query)
            self.repos = repos

        def build_command(self, dct):
            dct[u'repos'] = [repo.build(dict()) for repo in self.repos]

        def parse_command(self, dct):
            self.repos = [Repository.new(repo) for repo in dct[u'repos']]


class GetBranches(ParentCommand):
    __command__ = u'get_branches'

    class Query(IQuery, DefaultCommand):

        def __init__(self, repo):
            super(GetBranches.Query, self).__init__()
            self.repo = repo

    class Reply(IReply, Command):

        def __init__(self, query, branches):
            super(GetBranches.Reply, self).__init__(query)
            self.branches = branches

        def build_command(self, dct):
            dct[u'branches'] = [br.build(dict()) for br in self.branches]

        def parse_command(self, dct):
            self.branches = [Branch.new(br) for br in dct[u'branches']]


class NewRepository(ParentCommand):
    __command__ = u'new_repo'

    class Query(IQuery, Command):

        def __init__(self, repo):
            super(NewRepository.Query, self).__init__()
            self.repo = repo

        def build_command(self, dct):
            self.repo.build(dct[u'repo'])

        def parse_command(self, dct):
            self.repo = Repository.new(dct[u'repo'])

    class Reply(IReply, Command):
        pass


class NewBranch(ParentCommand):
    __command__ = u'new_branch'

    class Query(IQuery, Command):

        def __init__(self, branch):
            super(NewBranch.Query, self).__init__()
            self.branch = branch

        def build_command(self, dct):
            self.branch.build(dct[u'branch'])

        def parse_command(self, dct):
            self.branch = Branch.new(dct[u'branch'])

    class Reply(IReply, Command):
        pass


class UploadDatabase(ParentCommand):
    __command__ = u'upload_d'

    class Query(IQuery, Container, DefaultCommand):

        def __init__(self, repo, branch):
            super(UploadDatabase.Query, self).__init__()
            self.repo = repo
            self.branch = branch

    class Reply(IReply, Command):
        pass


class DownloadDatabase(ParentCommand):
    __command__ = u'download_d'

    class Query(IQuery, DefaultCommand):

        def __init__(self, repo, branch):
            super(DownloadDatabase.Query, self).__init__()
            self.repo = repo
            self.branch = branch

    class Reply(IReply, Container, Command):
        pass


class Subscribe(DefaultCommand):
    __command__ = u'subscribe'

    def __init__(self, repo, branch, tick):
        super(Subscribe, self).__init__()
        self.repo = repo
        self.branch = branch
        self.tick = tick


class Unsubscribe(DefaultCommand):
    __command__ = u'unsubscribe'
