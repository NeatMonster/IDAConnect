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
import os
import shutil
from urllib.request import urlopen
import zipfile

import ida_diskio
import ida_loader

# Allow the user to override the download URL
if "URL" not in locals():
    #URL = "https://github.com/IDArlingTeam/IDArling/archive/master.zip"
    URL = "https://github.com/assafnativ/IDArling/archive/master.zip"

print("[*] Installing IDArling...")
# Install into the user directory on all platforms
user_dir = ida_diskio.get_user_idadir()
plug_dir = os.path.join(user_dir, "plugins")
if not os.path.exists(plug_dir):
    os.makedirs(plug_dir, 493)  # 0755

print("[*] Downloading master.zip archive...")
archive_path = os.path.join(plug_dir, "master.zip")
if os.path.exists(archive_path):
    os.remove(archive_path)
with open(archive_path, "wb") as f:
    f.write(urlopen(URL).read())

print("[*] Unzipping master.zip archive...")
archive_dir = os.path.join(plug_dir, "IDArling-master")
if os.path.exists(archive_dir):
    shutil.rmtree(archive_dir)
with zipfile.ZipFile(archive_path, "r") as zip:
    for zip_file in zip.namelist():
        if zip_file.startswith(os.path.basename(archive_dir)):
            zip.extract(zip_file, plug_dir)

print("[*] Moving the IDArling files...")
src_path = os.path.join(archive_dir, "idarling_plugin.py")
dst_path = os.path.join(plug_dir, os.path.basename(src_path))
if os.path.exists(dst_path):
    os.remove(dst_path)
shutil.move(src_path, dst_path)
src_dir = os.path.join(archive_dir, "idarling")
dst_dir = os.path.join(plug_dir, os.path.basename(src_dir))
if os.path.exists(dst_dir):
    shutil.rmtree(dst_dir)
shutil.move(src_dir, dst_dir)

print("[*] Removing master.zip archive...")
if os.path.exists(archive_path):
    os.remove(archive_path)
if os.path.exists(archive_dir):
    shutil.rmtree(archive_dir)

print("[*] Loading IDArling into IDA Pro...")
plugin_path = os.path.join(plug_dir, "idarling_plugin.py")
ida_loader.load_plugin(plugin_path)

print("[*] IDArling installed successfully!")
