## How to contribute to IDArling

*This contributing file is modified from [Ruby on Rails](https://github.com/rails/rails/blob/master/CONTRIBUTING.md)*

### Quick guidelines for commits

* Write cross-platform code. IDArling is working for both macOS, Linux and Windows. Make sure you are not using things like `os.system("ls")` directly.
* Split your large commit into several parts. As we have [discussed](https://github.com/IDArlingTeam/IDArling/issues/46#issuecomment-418980108), using several small commits is easier to see the history through `git log`. If you do not know how to selectively `git add` your file, go stackoverflow or see [this](https://mirrors.edge.kernel.org/pub/software/scm/git/docs/git-add.html#_interactive_mode).
* Test before your PR. Make sure your commit does not break anything, and can pass code style check. We use `black` and `flake8`. See [travis config file](https://github.com/IDArlingTeam/IDArling/blob/master/.travis.yml) for more.

### Did you find a bug?

* **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/IDArlingTeam/IDArling/issues).

* If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/IDArlingTeam/IDArling/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

### Did you write a patch that fixes a bug?

* Open a new GitHub pull request with the patch.

* Ensure the PR description clearly describes the problem and solution. Include the relevant issue number if applicable.

* Before submitting, please read the **Quick guidelines for commits** above for coding guidelines.

### Do you intend to add a new feature or change an existing one?

* Suggest your change by opening a new issue, and start writing code in your own fork.

* New features or improvements will be discussed in the issue, and be sure you get enough favors before you open a new Pull Request.

#### **Do you want to contribute to the IDArling documentation?**

* Yes, we do need you to write it. You can be the first one to write it!

Thanks! :heart: :heart: :heart:

IDArling Team
