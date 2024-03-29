import cProfile
import glob
import locale
import sys
import time
from os import environ
from os import path

_profiler = cProfile.Profile()

_start_time = None
if environ.get("PWNDBG_PROFILE") == "1":
    _start_time = time.time()
    _profiler.enable()

# Allow users to use packages from a virtualenv
# That's not 100% supported, but they do it on their own,
# so we will warn them if the GDB's Python is not virtualenv's Python
virtual_env = environ.get("VIRTUAL_ENV")

if virtual_env:
    py_exe_matches = sys.executable.startswith(virtual_env)

    if not py_exe_matches:
        venv_warning = int(environ.get("PWNDBG_VENV_WARNING", 1))
        if venv_warning:
            print(
                f"""WARNING: Pwndbg/GDB run in virtualenv with which it may not work correctly ***
  Detected Python virtual environment: VIRTUAL_ENV='{virtual_env}'
  while GDB is built with different Python binary: {sys.executable}
  Assuming that you installed Pwndbg dependencies into the virtual environment
  If this is not true, this may cause import errors or other issues in Pwndbg
  If all works for you, you can suppress this warning and all further prints
  by setting `export PWNDBG_VENV_WARNING=0` (e.g. in ~/.bashrc or ~/.zshrc etc.)"""
            )
            venv_warn = print
        else:
            venv_warn = lambda *a, **kw: None

        possible_site_packages = glob.glob(
            path.join(virtual_env, "lib", "python*", "site-packages")
        )

        if len(possible_site_packages) > 1:
            venv_warn("*** Found multiple site packages in virtualenv:")
            for site_pkg in possible_site_packages:
                venv_warn("    - %s" % site_pkg)

            virtualenv_site_packages = possible_site_packages[-1]
            venv_warn("*** Using the last one: %s" % virtualenv_site_packages)

        elif len(possible_site_packages) == 1:
            virtualenv_site_packages = possible_site_packages[-1]
            venv_warn("*** Using the only site packages dir found: %s" % virtualenv_site_packages)

        else:
            guessed_python_directory = "python%s.%s" % (
                sys.version_info.major,
                sys.version_info.minor,
            )
            virtualenv_site_packages = path.join(
                virtual_env, "lib", guessed_python_directory, "site-packages"
            )
            venv_warn(
                "***  Not found site-packages in virtualenv, using guessed site packages Python dir: %s"
                % virtualenv_site_packages
            )

        venv_warn("  Added detected virtualenv's Python site packages to sys.path")
        venv_warn("")
        sys.path.append(virtualenv_site_packages)


directory, file = path.split(__file__)
directory = path.expanduser(directory)
directory = path.abspath(directory)


gdbpt = path.join(directory, "gdb-pt-dump")
sys.path.append(directory)
sys.path.append(gdbpt)

# warn if the user has different encoding than utf-8
encoding = locale.getpreferredencoding()

if encoding != "UTF-8":
    print("******")
    print(
        "Your encoding ({}) is different than UTF-8. pwndbg might not work properly.".format(
            encoding
        )
    )
    print("You might try launching gdb with:")
    print("    LC_ALL=en_US.UTF-8 PYTHONIOENCODING=UTF-8 gdb")
    print("Make sure that en_US.UTF-8 is activated in /etc/locale.gen and you called locale-gen")
    print("******")

environ["PWNLIB_NOTERM"] = "1"

import pwndbg  # noqa: F401
import pwndbg.profiling

pwndbg.profiling.init(_profiler, _start_time)
if environ.get("PWNDBG_PROFILE") == "1":
    pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
    pwndbg.profiling.profiler.start()
