<p align="center">
    <img src="https://i.imgur.com/9Vxm0Fn.png" />
</p>


# Warning

This project is no longer under active development and the more featured and up-to-date [fork](https://github.com/fidgetingbits/IDArling) is probably something more interesting for new comers. Also, IDA has announced an official support for collaborative reverse engineering session and one could also wait for this.

## Overview

IDArling is a collaborative reverse engineering plugin for [IDA Pro](https://www.hex-rays.com/products/ida/)
and [Hex-Rays](https://www.hex-rays.com/products/decompiler/index.shtml). It
allows to synchronize in real-time the changes made to a database by multiple
users, by connecting together different instances of IDA Pro.

The main features of IDArling are:
* hooking general user events
* structure and enumeration support
* Hex-Rays decompiler syncing
* replay engine and auto-saving
* database loading and saving
* interactive status bar widget
* user cursors (instructions, functions, navbar)
* invite and following an user moves
* dedicated server using Qt5
* integrated server within IDA
* LAN servers discovery
* following an user moves in real time

If you have any questions not worthy of a bug report, feel free to ping us at
[#idarling on freenode](https://kiwiirc.com/client/irc.freenode.net/idarling)
and ask away.

## Releases

This project is under active development. Feel free to send a PR if you would
like to help! :-)

**It is not really stable in its current state, please stayed tuned for a first
release of the project!**

## Installation

Install the IDArling client into the IDA plugins folder.

- Copy `idarling_plugin.py` and the `idarling` folder to the IDA plugins folder.
    - On Windows, the folder is at `C:\Program Files\IDA 7.x\plugins`
    - On macOS, the folder is at `/Applications/IDA\ Pro\ 7.x/idabin/plugins`
    - On Linux, the folder may be at `~/ida-7.x/plugins/`
- Alternatively, you can use the "easy install" method by copying the following
line into the console:
```
import urllib2; exec(urllib2.urlopen('https://raw.githubusercontent.com/IDArlingTeam/IDArling/master/easy_install.py')).read()
```

**Warning:** The plugin is only compatible with IDA Pro 7.x on Windows, macOS,
and Linux.

The dedicated server requires PyQt5, which is integrated into IDA. If you're
using an external Python installation, we recommand using Python 3, which offers
a pre-built package that can be installed with a simple `pip install PyQt5`.

## Usage

Open the *Settings* dialog accessible from the right-clicking the widget located
in the status bar. Show the servers list by clicking on the *Network Settings*
tabs and add your server to it. Connect to the server by clicking on it after 
right-clicking the widget again. Finally, you should be able to access the
following menus to upload or download a database:

```
- File --> Open from server
- File --> Save to server
```

# Thanks

This project is inspired by [Sol[IDA]rity](https://solidarity.re/). It started
after contacting its authors and asking if it was ever going to be released to
the public. [Lighthouse](https://github.com/gaasedelen/lighthouse) source code
was also carefully studied to understand how to write better IDA plugins.

* Previous plugins, namely [CollabREate](https://github.com/cseagle/collabREate),
[IDASynergy](https://github.com/CubicaLabs/IDASynergy),
[YaCo](https://github.com/DGA-MI-SSI/YaCo), were studied during the development
process;
* The icons are edited and combined versions from the sites [freeiconshop.com](http://freeiconshop.com/)
and [www.iconsplace.com](http://www.iconsplace.com).

Thanks to Quarkslab for allowing this release.

# Authors

* Alexandre Adamski <<neat@idarling.re>>
* Joffrey Guilbon <<patate@idarling.re>>
