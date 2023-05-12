from __future__ import absolute_import, division, print_function
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

from time import time
from multiprocessing import Pool, cpu_count

try:
    import lzma
except ImportError:
    lzma = None

def platform_is_win32():
    return sys.platform == 'win32'

EXE_SUFFIX = ".exe" if platform_is_win32() else ""

def get_cpus():
    if hasattr(os, "sched_getaffinity"):
        return len(os.sched_getaffinity(0))
    if hasattr(os, "cpu_count"):
        cpus = os.cpu_count()
        if cpus is not None:
            return cpus
    try:
        return cpu_count()
    except NotImplementedError:
        return 1



def get(base, url, path, checksums, verbose=False):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name

    try:
        if url not in checksums:
            raise RuntimeError(
                f"src/stage0.json doesn't contain a checksum for {url}. Pre-built artifacts might not be available for this target at this time, see https://doc.rust-lang.org/nightly/rustc/platform-support.html for more information."
            )
        sha256 = checksums[url]
        if os.path.exists(path):
            if verify(path, sha256, False):
                if verbose:
                    print("using already-download file", path, file=sys.stderr)
                return
            else:
                if verbose:
                    print("ignoring already-download file",
                        path, "due to failed verification", file=sys.stderr)
                os.unlink(path)
        download(temp_path, f"{base}/{url}", True, verbose)
        if not verify(temp_path, sha256, verbose):
            raise RuntimeError("failed verification")
        if verbose:
            print(f"moving {temp_path} to {path}", file=sys.stderr)
        shutil.move(temp_path, path)
    finally:
        if os.path.isfile(temp_path):
            if verbose:
                print("removing", temp_path, file=sys.stderr)
            os.unlink(temp_path)


def download(path, url, probably_big, verbose):
    for _ in range(4):
        try:
            _download(path, url, probably_big, verbose, True)
            return
        except RuntimeError:
            print("\nspurious failure, trying again", file=sys.stderr)
    _download(path, url, probably_big, verbose, False)


def _download(path, url, probably_big, verbose, exception):
    # Try to use curl (potentially available on win32
    #    https://devblogs.microsoft.com/commandline/tar-and-curl-come-to-windows/)
    # If an error occurs:
    #  - If we are on win32 fallback to powershell
    #  - Otherwise raise the error if appropriate
    if probably_big or verbose:
        print(f"downloading {url}", file=sys.stderr)

    try:
        option = "-#" if probably_big or verbose else "-s"
        # If curl is not present on Win32, we should not sys.exit
        #   but raise `CalledProcessError` or `OSError` instead
        require(["curl", "--version"], exception=platform_is_win32())
        with open(path, "wb") as outfile:
            run(["curl", option,
                "-L", # Follow redirect.
                "-y", "30", "-Y", "10",    # timeout if speed is < 10 bytes/sec for > 30 seconds
                "--connect-timeout", "30",  # timeout if cannot connect within 30 seconds
                "--retry", "3", "-Sf", url],
                stdout=outfile,    #Implements cli redirect operator '>'
                verbose=verbose,
                exception=True, # Will raise RuntimeError on failure
            )
    except (subprocess.CalledProcessError, OSError, RuntimeError):
        # see http://serverfault.com/questions/301128/how-to-download
        if platform_is_win32():
            run_powershell(
                [
                    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;",
                    f"(New-Object System.Net.WebClient).DownloadFile('{url}', '{path}')",
                ],
                verbose=verbose,
                exception=exception,
            )
        elif verbose or exception:
            raise


def verify(path, expected, verbose):
    """Check if the sha256 sum of the given path is valid"""
    if verbose:
        print("verifying", path, file=sys.stderr)
    with open(path, "rb") as source:
        found = hashlib.sha256(source.read()).hexdigest()
    verified = found == expected
    if not verified:
        print(
            f"invalid checksum:\n    found:    {found}\n    expected: {expected}",
            file=sys.stderr,
        )
    return verified


def unpack(tarball, tarball_suffix, dst, verbose=False, match=None):
    """Unpack the given tarball file"""
    print("extracting", tarball, file=sys.stderr)
    fname = os.path.basename(tarball).replace(tarball_suffix, "")
    with contextlib.closing(tarfile.open(tarball)) as tar:
        for member in tar.getnames():
            if "/" not in member:
                continue
            name = member.replace(f"{fname}/", "", 1)
            if match is not None and not name.startswith(match):
                continue
            name = name[len(match) + 1:]

            dst_path = os.path.join(dst, name)
            if verbose:
                print("  extracting", member, file=sys.stderr)
            tar.extract(member, dst)
            src_path = os.path.join(dst, member)
            if os.path.isdir(src_path) and os.path.exists(dst_path):
                continue
            shutil.move(src_path, dst_path)
    shutil.rmtree(os.path.join(dst, fname))


def run(args, verbose=False, exception=False, is_bootstrap=False, **kwargs):
    """Run a child program in a new process"""
    if verbose:
        print("running: " + ' '.join(args), file=sys.stderr)
    sys.stdout.flush()
    # Ensure that the .exe is used on Windows just in case a Linux ELF has been
    # compiled in the same directory.
    if os.name == 'nt' and not args[0].endswith('.exe'):
        args[0] += '.exe'
    # Use Popen here instead of call() as it apparently allows powershell on
    # Windows to not lock up waiting for input presumably.
    ret = subprocess.Popen(args, **kwargs)
    code = ret.wait()
    if code != 0:
        err = "failed to run: " + ' '.join(args)
        if verbose or exception:
            raise RuntimeError(err)
        # For most failures, we definitely do want to print this error, or the user will have no
        # idea what went wrong. But when we've successfully built bootstrap and it failed, it will
        # have already printed an error above, so there's no need to print the exact command we're
        # running.
        if is_bootstrap:
            sys.exit(1)
        else:
            sys.exit(err)

def run_powershell(script, *args, **kwargs):
    """Run a powershell script"""
    run(["PowerShell.exe", "/nologo", "-Command"] + script, *args, **kwargs)


def require(cmd, exit=True, exception=False):
    '''Run a command, returning its output.
    On error,
        If `exception` is `True`, raise the error
        Otherwise If `exit` is `True`, exit the process
        Else return None.'''
    try:
        return subprocess.check_output(cmd).strip()
    except (subprocess.CalledProcessError, OSError) as exc:
        if exception:
            raise
        elif exit:
            print(f"error: unable to run `{' '.join(cmd)}`: {exc}", file=sys.stderr)
            print("Please make sure it's installed and in the path.", file=sys.stderr)
            sys.exit(1)
        return None



def format_build_time(duration):
    """Return a nicer format for build time

    >>> format_build_time('300')
    '0:05:00'
    """
    return str(datetime.timedelta(seconds=int(duration)))


def default_build_triple(verbose):
    """Build triple as in LLVM"""
    # If the user already has a host build triple with an existing `rustc`
    # install, use their preference. This fixes most issues with Windows builds
    # being detected as GNU instead of MSVC.
    default_encoding = sys.getdefaultencoding()

    if sys.platform == 'darwin':
        if verbose:
            print("not using rustc detection as it is unreliable on macOS", file=sys.stderr)
            print("falling back to auto-detect", file=sys.stderr)
    else:
        try:
            version = subprocess.check_output(["rustc", "--version", "--verbose"],
                    stderr=subprocess.DEVNULL)
            version = version.decode(default_encoding)
            host = next(x for x in version.split('\n') if x.startswith("host: "))
            triple = host.split("host: ")[1]
            if verbose:
                print(
                    f"detected default triple {triple} from pre-installed rustc",
                    file=sys.stderr,
                )
            return triple
        except Exception as e:
            if verbose:
                print(f"pre-installed rustc not detected: {e}", file=sys.stderr)
                print("falling back to auto-detect", file=sys.stderr)

    required = not platform_is_win32()
    ostype = require(["uname", "-s"], exit=required)
    cputype = require(['uname', '-m'], exit=required)

    # If we do not have `uname`, assume Windows.
    if ostype is None or cputype is None:
        return 'x86_64-pc-windows-msvc'

    ostype = ostype.decode(default_encoding)
    cputype = cputype.decode(default_encoding)

    # The goal here is to come up with the same triple as LLVM would,
    # at least for the subset of platforms we're willing to target.
    ostype_mapper = {
        'Darwin': 'apple-darwin',
        'DragonFly': 'unknown-dragonfly',
        'FreeBSD': 'unknown-freebsd',
        'Haiku': 'unknown-haiku',
        'NetBSD': 'unknown-netbsd',
        'OpenBSD': 'unknown-openbsd'
    }

    # Consider the direct transformation first and then the special cases
    if ostype in ostype_mapper:
        ostype = ostype_mapper[ostype]
    elif ostype == 'Linux':
        os_from_sp = subprocess.check_output(
            ['uname', '-o']).strip().decode(default_encoding)
        ostype = 'linux-android' if os_from_sp == 'Android' else 'unknown-linux-gnu'
    elif ostype == 'SunOS':
        # On Solaris, uname -m will return a machine classification instead
        # of a cpu type, so uname -p is recommended instead.  However, the
        # output from that option is too generic for our purposes (it will
        # always emit 'i386' on x86/amd64 systems).  As such, isainfo -k
        # must be used instead.
        cputype = require(['isainfo', '-k']).decode(default_encoding)
        ostype = 'sun-solaris' if 'sparc' in cputype else 'pc-solaris'
    elif ostype.startswith('MINGW'):
        # msys' `uname` does not print gcc configuration, but prints msys
        # configuration. so we cannot believe `uname -m`:
        # msys1 is always i686 and msys2 is always x86_64.
        # instead, msys defines $MSYSTEM which is MINGW32 on i686 and
        # MINGW64 on x86_64.
        ostype = 'pc-windows-gnu'
        cputype = 'x86_64' if os.environ.get('MSYSTEM') == 'MINGW64' else 'i686'
    elif ostype.startswith('MSYS'):
        ostype = 'pc-windows-gnu'
    elif ostype.startswith('CYGWIN_NT'):
        cputype = 'x86_64' if ostype.endswith('WOW64') else 'i686'
        ostype = 'pc-windows-gnu'
    elif sys.platform == 'win32':
        # Some Windows platforms might have a `uname` command that returns a
        # non-standard string (e.g. gnuwin32 tools returns `windows32`). In
        # these cases, fall back to using sys.platform.
        return 'x86_64-pc-windows-msvc'
    else:
        err = f"unknown OS type: {ostype}"
        sys.exit(err)

    if cputype in ['powerpc', 'riscv'] and ostype == 'unknown-freebsd':
        cputype = subprocess.check_output(
              ['uname', '-p']).strip().decode(default_encoding)
    cputype_mapper = {
        'BePC': 'i686',
        'aarch64': 'aarch64',
        'amd64': 'x86_64',
        'arm64': 'aarch64',
        'i386': 'i686',
        'i486': 'i686',
        'i686': 'i686',
        'i786': 'i686',
        'loongarch64': 'loongarch64',
        'm68k': 'm68k',
        'powerpc': 'powerpc',
        'powerpc64': 'powerpc64',
        'powerpc64le': 'powerpc64le',
        'ppc': 'powerpc',
        'ppc64': 'powerpc64',
        'ppc64le': 'powerpc64le',
        'riscv64': 'riscv64gc',
        's390x': 's390x',
        'x64': 'x86_64',
        'x86': 'i686',
        'x86-64': 'x86_64',
        'x86_64': 'x86_64'
    }

    # Consider the direct transformation first and then the special cases
    if cputype in cputype_mapper:
        cputype = cputype_mapper[cputype]
    elif cputype in {'xscale', 'arm'}:
        cputype = 'arm'
        if ostype == 'linux-android':
            ostype = 'linux-androideabi'
        elif ostype == 'unknown-freebsd':
            cputype = subprocess.check_output(
                ['uname', '-p']).strip().decode(default_encoding)
            ostype = 'unknown-freebsd'
    elif cputype == 'armv6l':
        cputype = 'arm'
        if ostype == 'linux-android':
            ostype = 'linux-androideabi'
        else:
            ostype += 'eabihf'
    elif cputype in {'armv7l', 'armv8l'}:
        cputype = 'armv7'
        if ostype == 'linux-android':
            ostype = 'linux-androideabi'
        else:
            ostype += 'eabihf'
    elif cputype == 'mips':
        if sys.byteorder == 'big':
            cputype = 'mips'
        elif sys.byteorder == 'little':
            cputype = 'mipsel'
        else:
            raise ValueError(f"unknown byteorder: {sys.byteorder}")
    elif cputype == 'mips64':
        if sys.byteorder == 'big':
            cputype = 'mips64'
        elif sys.byteorder == 'little':
            cputype = 'mips64el'
        else:
            raise ValueError(f'unknown byteorder: {sys.byteorder}')
        # only the n64 ABI is supported, indicate it
        ostype += 'abi64'
    elif cputype not in ['sparc', 'sparcv9', 'sparc64']:
        err = f"unknown cpu type: {cputype}"
        sys.exit(err)

    return f"{cputype}-{ostype}"


@contextlib.contextmanager
def output(filepath):
    tmp = f'{filepath}.tmp'
    with open(tmp, 'w') as f:
        yield f
    try:
        if os.path.exists(filepath):
            os.remove(filepath)  # PermissionError/OSError on Win32 if in use
    except OSError:
        shutil.copy2(tmp, filepath)
        os.remove(tmp)
        return
    os.rename(tmp, filepath)


class Stage0Toolchain:
    def __init__(self, stage0_payload):
        self.date = stage0_payload["date"]
        self.version = stage0_payload["version"]

    def channel(self):
        return f"{self.version}-{self.date}"


class DownloadInfo:
    """A helper class that can be pickled into a parallel subprocess"""

    def __init__(
        self,
        base_download_url,
        download_path,
        bin_root,
        tarball_path,
        tarball_suffix,
        checksums_sha256,
        pattern,
        verbose,
    ):
        self.base_download_url = base_download_url
        self.download_path = download_path
        self.bin_root = bin_root
        self.tarball_path = tarball_path
        self.tarball_suffix = tarball_suffix
        self.checksums_sha256 = checksums_sha256
        self.pattern = pattern
        self.verbose = verbose

def download_component(download_info):
    if not os.path.exists(download_info.tarball_path):
        get(
            download_info.base_download_url,
            download_info.download_path,
            download_info.tarball_path,
            download_info.checksums_sha256,
            verbose=download_info.verbose,
        )

def unpack_component(download_info):
    unpack(
        download_info.tarball_path,
        download_info.tarball_suffix,
        download_info.bin_root,
        match=download_info.pattern,
        verbose=download_info.verbose,
    )

class RustBuild(object):
    """Provide all the methods required to build Rust"""
    def __init__(self):
        self.checksums_sha256 = {}
        self.stage0_compiler = None
        self.download_url = ''
        self.build = ''
        self.build_dir = ''
        self.clean = False
        self.config_toml = ''
        self.rust_root = ''
        self.use_locked_deps = False
        self.use_vendored_sources = False
        self.verbose = False
        self.git_version = None
        self.nix_deps_dir = None
        self._should_fix_bins_and_dylibs = None

    def download_toolchain(self):
        """Fetch the build system for Rust, written in Rust

        This method will build a cache directory, then it will fetch the
        tarball which has the stage0 compiler used to then bootstrap the Rust
        compiler itself.

        Each downloaded tarball is extracted, after that, the script
        will move all the content to the right place.
        """
        rustc_channel = self.stage0_compiler.version
        bin_root = self.bin_root()

        key = self.stage0_compiler.date
        if self.rustc().startswith(bin_root) and \
                    (not os.path.exists(self.rustc()) or
                 self.program_out_of_date(self.rustc_stamp(), key)):
            if os.path.exists(bin_root):
                # HACK: On Windows, we can't delete rust-analyzer-proc-macro-server while it's
                # running. Kill it.
                if platform_is_win32():
                    print("Killing rust-analyzer-proc-macro-srv before deleting stage0 toolchain")
                    regex = f'{os.path.basename(self.build_dir)}\\\\(host|{self.build})\\\\stage0\\\\libexec'
                    script = (
                        # NOTE: can't use `taskkill` or `Get-Process -Name` because they error if
                        # the server isn't running.
                        'Get-Process | ' +
                        'Where-Object {$_.Name -eq "rust-analyzer-proc-macro-srv"} |' +
                        'Where-Object {{$_.Path -match "{}"}} |'.format(regex) +
                        'Stop-Process'
                    )
                    run_powershell([script])
                shutil.rmtree(bin_root)

            key = self.stage0_compiler.date
            cache_dst = os.path.join(self.build_dir, "cache")
            rustc_cache = os.path.join(cache_dst, key)
            if not os.path.exists(rustc_cache):
                os.makedirs(rustc_cache)

            tarball_suffix = '.tar.gz' if lzma is None else '.tar.xz'

            toolchain_suffix = f"{rustc_channel}-{self.build}{tarball_suffix}"

            tarballs_to_download = [
                (f"rust-std-{toolchain_suffix}", f"rust-std-{self.build}"),
                (f"rustc-{toolchain_suffix}", "rustc"),
                (f"cargo-{toolchain_suffix}", "cargo"),
            ]

            tarballs_download_info = [
                DownloadInfo(
                    base_download_url=self.download_url,
                    download_path=f"dist/{self.stage0_compiler.date}/{filename}",
                    bin_root=self.bin_root(),
                    tarball_path=os.path.join(rustc_cache, filename),
                    tarball_suffix=tarball_suffix,
                    checksums_sha256=self.checksums_sha256,
                    pattern=pattern,
                    verbose=self.verbose,
                )
                for filename, pattern in tarballs_to_download
            ]

            # Download the components serially to show the progress bars properly.
            for download_info in tarballs_download_info:
                download_component(download_info)

            # Unpack the tarballs in parallle.
            # In Python 2.7, Pool cannot be used as a context manager.
            pool_size = min(len(tarballs_download_info), get_cpus())
            if self.verbose:
                print('Choosing a pool size of', pool_size, 'for the unpacking of the tarballs')
            p = Pool(pool_size)
            try:
                p.map(unpack_component, tarballs_download_info)
            finally:
                p.close()
            p.join()

            if self.should_fix_bins_and_dylibs():
                self.fix_bin_or_dylib(f"{bin_root}/bin/cargo")

                self.fix_bin_or_dylib(f"{bin_root}/bin/rustc")
                self.fix_bin_or_dylib(f"{bin_root}/bin/rustdoc")
                self.fix_bin_or_dylib(f"{bin_root}/libexec/rust-analyzer-proc-macro-srv")
                lib_dir = f"{bin_root}/lib"
                for lib in os.listdir(lib_dir):
                    if lib.endswith(".so"):
                        self.fix_bin_or_dylib(os.path.join(lib_dir, lib))

            with output(self.rustc_stamp()) as rust_stamp:
                rust_stamp.write(key)

    def _download_component_helper(
        self, filename, pattern, tarball_suffix, rustc_cache,
    ):
        key = self.stage0_compiler.date

        tarball = os.path.join(rustc_cache, filename)
        if not os.path.exists(tarball):
            get(
                self.download_url,
                f"dist/{key}/{filename}",
                tarball,
                self.checksums_sha256,
                verbose=self.verbose,
            )
        unpack(tarball, tarball_suffix, self.bin_root(), match=pattern, verbose=self.verbose)

    def should_fix_bins_and_dylibs(self):
        """Whether or not `fix_bin_or_dylib` needs to be run; can only be True
        on NixOS.
        """
        if self._should_fix_bins_and_dylibs is not None:
            return self._should_fix_bins_and_dylibs

        def get_answer():
            default_encoding = sys.getdefaultencoding()
            try:
                ostype = subprocess.check_output(
                    ['uname', '-s']).strip().decode(default_encoding)
            except subprocess.CalledProcessError:
                return False
            except OSError as reason:
                if getattr(reason, 'winerror', None) is not None:
                    return False
                raise reason

            if ostype != "Linux":
                return False

            # If the user has asked binaries to be patched for Nix, then
            # don't check for NixOS or `/lib`.
            if self.get_toml("patch-binaries-for-nix", "build") == "true":
                return True

            # Use `/etc/os-release` instead of `/etc/NIXOS`.
            # The latter one does not exist on NixOS when using tmpfs as root.
            try:
                with open("/etc/os-release", "r") as f:
                    if all(
                        l.strip() not in ("ID=nixos", "ID='nixos'", 'ID="nixos"')
                        for l in f
                    ):
                        return False
            except FileNotFoundError:
                return False
            return not os.path.exists("/lib")

        answer = self._should_fix_bins_and_dylibs = get_answer()
        if answer:
            print("info: You seem to be using Nix.", file=sys.stderr)
        return answer

    def fix_bin_or_dylib(self, fname):
        """Modifies the interpreter section of 'fname' to fix the dynamic linker,
        or the RPATH section, to fix the dynamic library search path

        This method is only required on NixOS and uses the PatchELF utility to
        change the interpreter/RPATH of ELF executables.

        Please see https://nixos.org/patchelf.html for more information
        """
        assert self._should_fix_bins_and_dylibs is True
        print("attempting to patch", fname, file=sys.stderr)

        # Only build `.nix-deps` once.
        nix_deps_dir = self.nix_deps_dir
        if not nix_deps_dir:
            # Run `nix-build` to "build" each dependency (which will likely reuse
            # the existing `/nix/store` copy, or at most download a pre-built copy).
            #
            # Importantly, we create a gc-root called `.nix-deps` in the `build/`
            # directory, but still reference the actual `/nix/store` path in the rpath
            # as it makes it significantly more robust against changes to the location of
            # the `.nix-deps` location.
            #
            # bintools: Needed for the path of `ld-linux.so` (via `nix-support/dynamic-linker`).
            # zlib: Needed as a system dependency of `libLLVM-*.so`.
            # patchelf: Needed for patching ELF binaries (see doc comment above).
            nix_deps_dir = f"{self.build_dir}/.nix-deps"
            nix_expr = '''
            with (import <nixpkgs> {});
            symlinkJoin {
              name = "rust-stage0-dependencies";
              paths = [
                zlib
                patchelf
                stdenv.cc.bintools
              ];
            }
            '''
            try:
                subprocess.check_output([
                    "nix-build", "-E", nix_expr, "-o", nix_deps_dir,
                ])
            except subprocess.CalledProcessError as reason:
                print("warning: failed to call nix-build:", reason, file=sys.stderr)
                return
            self.nix_deps_dir = nix_deps_dir

        patchelf = f"{nix_deps_dir}/bin/patchelf"
        rpath_entries = [
            # Relative default, all binary and dynamic libraries we ship
            # appear to have this (even when `../lib` is redundant).
            "$ORIGIN/../lib",
            os.path.join(os.path.realpath(nix_deps_dir), "lib")
        ]
        patchelf_args = ["--set-rpath", ":".join(rpath_entries)]
        if not fname.endswith(".so"):
            # Finally, set the correct .interp for binaries
            with open(f"{nix_deps_dir}/nix-support/dynamic-linker") as dynamic_linker:
                patchelf_args += ["--set-interpreter", dynamic_linker.read().rstrip()]

        try:
            subprocess.check_output([patchelf] + patchelf_args + [fname])
        except subprocess.CalledProcessError as reason:
            print("warning: failed to call patchelf:", reason, file=sys.stderr)
            return

    def rustc_stamp(self):
        """Return the path for .rustc-stamp at the given stage

        >>> rb = RustBuild()
        >>> rb.build_dir = "build"
        >>> rb.rustc_stamp() == os.path.join("build", "stage0", ".rustc-stamp")
        True
        """
        return os.path.join(self.bin_root(), '.rustc-stamp')

    def program_out_of_date(self, stamp_path, key):
        """Check if the given program stamp is out of date"""
        if not os.path.exists(stamp_path) or self.clean:
            return True
        with open(stamp_path, 'r') as stamp:
            return key != stamp.read()

    def bin_root(self):
        """Return the binary root directory for the given stage

        >>> rb = RustBuild()
        >>> rb.build_dir = "build"
        >>> rb.bin_root() == os.path.join("build", "stage0")
        True

        When the 'build' property is given should be a nested directory:

        >>> rb.build = "devel"
        >>> rb.bin_root() == os.path.join("build", "devel", "stage0")
        True
        """
        subdir = "stage0"
        return os.path.join(self.build_dir, self.build, subdir)

    def get_toml(self, key, section=None):
        """Returns the value of the given key in config.toml, otherwise returns None

        >>> rb = RustBuild()
        >>> rb.config_toml = 'key1 = "value1"\\nkey2 = "value2"'
        >>> rb.get_toml("key2")
        'value2'

        If the key does not exist, the result is None:

        >>> rb.get_toml("key3") is None
        True

        Optionally also matches the section the key appears in

        >>> rb.config_toml = '[a]\\nkey = "value1"\\n[b]\\nkey = "value2"'
        >>> rb.get_toml('key', 'a')
        'value1'
        >>> rb.get_toml('key', 'b')
        'value2'
        >>> rb.get_toml('key', 'c') is None
        True

        >>> rb.config_toml = 'key1 = true'
        >>> rb.get_toml("key1")
        'true'
        """

        cur_section = None
        for line in self.config_toml.splitlines():
            section_match = re.match(r'^\s*\[(.*)\]\s*$', line)
            if section_match is not None:
                cur_section = section_match[1]

            match = re.match(f'^{key}\s*=(.*)$', line)
            if match is not None and (section is None or section == cur_section):
                value = match[1]
                return self.get_string(value) or value.strip()
        return None

    def cargo(self):
        """Return config path for cargo"""
        return self.program_config('cargo')

    def rustc(self):
        """Return config path for rustc"""
        return self.program_config('rustc')

    def program_config(self, program):
        """Return config path for the given program at the given stage

        >>> rb = RustBuild()
        >>> rb.config_toml = 'rustc = "rustc"\\n'
        >>> rb.program_config('rustc')
        'rustc'
        >>> rb.config_toml = ''
        >>> cargo_path = rb.program_config('cargo')
        >>> cargo_path.rstrip(".exe") == os.path.join(rb.bin_root(),
        ... "bin", "cargo")
        True
        """
        if config := self.get_toml(program):
            return os.path.expanduser(config)
        return os.path.join(self.bin_root(), "bin", f"{program}{EXE_SUFFIX}")

    @staticmethod
    def get_string(line):
        """Return the value between double quotes

        >>> RustBuild.get_string('    "devel"   ')
        'devel'
        >>> RustBuild.get_string("    'devel'   ")
        'devel'
        >>> RustBuild.get_string('devel') is None
        True
        >>> RustBuild.get_string('    "devel   ')
        ''
        """
        start = line.find('"')
        if start != -1:
            end = start + 1 + line[start + 1:].find('"')
            return line[start + 1:end]
        start = line.find('\'')
        if start != -1:
            end = start + 1 + line[start + 1:].find('\'')
            return line[start + 1:end]
        return None

    def bootstrap_binary(self):
        """Return the path of the bootstrap binary

        >>> rb = RustBuild()
        >>> rb.build_dir = "build"
        >>> rb.bootstrap_binary() == os.path.join("build", "bootstrap",
        ... "debug", "bootstrap")
        True
        """
        return os.path.join(self.build_dir, "bootstrap", "debug", "bootstrap")

    def build_bootstrap(self, color, verbose_count):
        """Build bootstrap"""
        env = os.environ.copy()
        if "GITHUB_ACTIONS" in env:
            print("::group::Building bootstrap")
        else:
            print("Building bootstrap", file=sys.stderr)
        build_dir = os.path.join(self.build_dir, "bootstrap")
        if self.clean and os.path.exists(build_dir):
            shutil.rmtree(build_dir)
        # `CARGO_BUILD_TARGET` breaks bootstrap build.
        # See also: <https://github.com/rust-lang/rust/issues/70208>.
        if "CARGO_BUILD_TARGET" in env:
            del env["CARGO_BUILD_TARGET"]
        env["CARGO_TARGET_DIR"] = build_dir
        env["RUSTC"] = self.rustc()
        env["LD_LIBRARY_PATH"] = os.path.join(self.bin_root(), "lib") + \
                (os.pathsep + env["LD_LIBRARY_PATH"]) \
                if "LD_LIBRARY_PATH" in env else ""
        env["DYLD_LIBRARY_PATH"] = os.path.join(self.bin_root(), "lib") + \
                (os.pathsep + env["DYLD_LIBRARY_PATH"]) \
                if "DYLD_LIBRARY_PATH" in env else ""
        env["LIBRARY_PATH"] = os.path.join(self.bin_root(), "lib") + \
                (os.pathsep + env["LIBRARY_PATH"]) \
                if "LIBRARY_PATH" in env else ""
        env["LIBPATH"] = os.path.join(self.bin_root(), "lib") + \
                (os.pathsep + env["LIBPATH"]) \
                if "LIBPATH" in env else ""

        # Export Stage0 snapshot compiler related env variables
        build_section = f"target.{self.build}"
        host_triple_sanitized = self.build.replace("-", "_")
        var_data = {
            "CC": "cc", "CXX": "cxx", "LD": "linker", "AR": "ar", "RANLIB": "ranlib"
        }
        for var_name, toml_key in var_data.items():
            toml_val = self.get_toml(toml_key, build_section)
            if toml_val != None:
                env[f"{var_name}_{host_triple_sanitized}"] = toml_val

        # preserve existing RUSTFLAGS
        env.setdefault("RUSTFLAGS", "")
        target_features = []
        if self.get_toml("crt-static", build_section) == "true":
            target_features += ["+crt-static"]
        elif self.get_toml("crt-static", build_section) == "false":
            target_features += ["-crt-static"]
        if target_features:
            env["RUSTFLAGS"] += " -C target-feature=" + (",".join(target_features))
        target_linker = self.get_toml("linker", build_section)
        if target_linker is not None:
            env["RUSTFLAGS"] += f" -C linker={target_linker}"
        env["RUSTFLAGS"] += " -Wrust_2018_idioms -Wunused_lifetimes"
        if self.get_toml("deny-warnings", "rust") != "false":
            env["RUSTFLAGS"] += " -Dwarnings"

        env["PATH"] = os.path.join(self.bin_root(), "bin") + \
                os.pathsep + env["PATH"]
        if not os.path.isfile(self.cargo()):
            raise Exception(f"no cargo executable found at `{self.cargo()}`")
        args = [self.cargo(), "build", "--manifest-path",
                os.path.join(self.rust_root, "src/bootstrap/Cargo.toml")]
        args.extend("--verbose" for _ in range(verbose_count))
        if self.use_locked_deps:
            args.append("--locked")
        if self.use_vendored_sources:
            args.append("--frozen")
        if self.get_toml("metrics", "build"):
            args.extend(("--features", "build-metrics"))
        if self.json_output:
            args.append("--message-format=json")
        if color == "always":
            args.append("--color=always")
        elif color == "never":
            args.append("--color=never")

        # Run this from the source directory so cargo finds .cargo/config
        run(args, env=env, verbose=self.verbose, cwd=self.rust_root)

        if "GITHUB_ACTIONS" in env:
            print("::endgroup::")

    def build_triple(self):
        """Build triple as in LLVM

        Note that `default_build_triple` is moderately expensive,
        so use `self.build` where possible.
        """
        config = self.get_toml('build')
        return config or default_build_triple(self.verbose)

    def check_vendored_status(self):
        """Check that vendoring is configured properly"""
        # keep this consistent with the equivalent check in rustbuild:
        # https://github.com/rust-lang/rust/blob/a8a33cf27166d3eabaffc58ed3799e054af3b0c6/src/bootstrap/lib.rs#L399-L405
        if (
            'SUDO_USER' in os.environ
            and not self.use_vendored_sources
            and os.getuid() == 0
        ):
            self.use_vendored_sources = True
            print('info: looks like you\'re trying to run this command as root',
                file=sys.stderr)
            print('      and so in order to preserve your $HOME this will now',
                file=sys.stderr)
            print('      use vendored sources by default.',
                file=sys.stderr)

        cargo_dir = os.path.join(self.rust_root, '.cargo')
        if self.use_vendored_sources:
            vendor_dir = os.path.join(self.rust_root, 'vendor')
            if not os.path.exists(vendor_dir):
                print('error: vendoring required, but vendor directory does not exist.',
                    file=sys.stderr)
                sync_dirs = (
                    "--sync ./src/tools/cargo/Cargo.toml "
                    "--sync ./src/tools/rust-analyzer/Cargo.toml "
                    "--sync ./compiler/rustc_codegen_cranelift/Cargo.toml "
                    "--sync ./src/bootstrap/Cargo.toml "
                )
                print(
                    f'       Run `cargo vendor {sync_dirs}` to initialize the vendor directory.',
                    file=sys.stderr,
                )
                print('Alternatively, use the pre-vendored `rustc-src` dist component.',
                    file=sys.stderr)
                raise Exception(f"{vendor_dir} not found")

            if not os.path.exists(cargo_dir):
                print('error: vendoring required, but .cargo/config does not exist.',
                    file=sys.stderr)
                raise Exception(f"{cargo_dir} not found")
        elif os.path.exists(cargo_dir):
            shutil.rmtree(cargo_dir)

def parse_args():
    """Parse the command line arguments that the python script needs."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true')
    parser.add_argument('--config')
    parser.add_argument('--build-dir')
    parser.add_argument('--build')
    parser.add_argument('--color', choices=['always', 'never', 'auto'])
    parser.add_argument('--clean', action='store_true')
    parser.add_argument('--json-output', action='store_true')
    parser.add_argument('-v', '--verbose', action='count', default=0)

    return parser.parse_known_args(sys.argv)[0]

def bootstrap(args):
    """Configure, fetch, build and run the initial bootstrap"""
    # Configure initial bootstrap
    build = RustBuild()
    build.rust_root = os.path.abspath(os.path.join(__file__, '../../..'))
    build.verbose = args.verbose != 0
    build.clean = args.clean
    build.json_output = args.json_output

    # Read from `--config`, then `RUST_BOOTSTRAP_CONFIG`, then `./config.toml`,
    # then `config.toml` in the root directory.
    toml_path = args.config or os.getenv('RUST_BOOTSTRAP_CONFIG')
    using_default_path = toml_path is None
    if using_default_path:
        toml_path = 'config.toml'
        if not os.path.exists(toml_path):
            toml_path = os.path.join(build.rust_root, toml_path)

    # Give a hard error if `--config` or `RUST_BOOTSTRAP_CONFIG` are set to a missing path,
    # but not if `config.toml` hasn't been created.
    if not using_default_path or os.path.exists(toml_path):
        with open(toml_path) as config:
            build.config_toml = config.read()

    profile = build.get_toml('profile')
    if profile is not None:
        include_file = f'config.{profile}.toml'
        include_dir = os.path.join(build.rust_root, 'src', 'bootstrap', 'defaults')
        include_path = os.path.join(include_dir, include_file)
        # HACK: This works because `build.get_toml()` returns the first match it finds for a
        # specific key, so appending our defaults at the end allows the user to override them
        with open(include_path) as included_toml:
            build.config_toml += os.linesep + included_toml.read()

    verbose_count = args.verbose
    config_verbose_count = build.get_toml('verbose', 'build')
    if config_verbose_count is not None:
        verbose_count = max(args.verbose, int(config_verbose_count))

    build.use_vendored_sources = build.get_toml('vendor', 'build') == 'true'
    build.use_locked_deps = build.get_toml('locked-deps', 'build') == 'true'

    build.check_vendored_status()

    build_dir = args.build_dir or build.get_toml('build-dir', 'build') or 'build'
    build.build_dir = os.path.abspath(build_dir)

    with open(os.path.join(build.rust_root, "src", "stage0.json")) as f:
        data = json.load(f)
    build.checksums_sha256 = data["checksums_sha256"]
    build.stage0_compiler = Stage0Toolchain(data["compiler"])
    build.download_url = os.getenv("RUSTUP_DIST_SERVER") or data["config"]["dist_server"]

    build.build = args.build or build.build_triple()

    if not os.path.exists(build.build_dir):
        os.makedirs(build.build_dir)

    # Fetch/build the bootstrap
    build.download_toolchain()
    sys.stdout.flush()
    build.build_bootstrap(args.color, verbose_count)
    sys.stdout.flush()

    # Run the bootstrap
    args = [build.bootstrap_binary()]
    args.extend(sys.argv[1:])
    env = os.environ.copy()
    env["BOOTSTRAP_PARENT_ID"] = str(os.getpid())
    env["BOOTSTRAP_PYTHON"] = sys.executable
    run(args, env=env, verbose=build.verbose, is_bootstrap=True)


def main():
    """Entry point for the bootstrap process"""
    start_time = time()

    # x.py help <cmd> ...
    if len(sys.argv) > 1 and sys.argv[1] == 'help':
        sys.argv[1] = '-h'

    args = parse_args()
    help_triggered = args.help or len(sys.argv) == 1

    # If the user is asking for help, let them know that the whole download-and-build
    # process has to happen before anything is printed out.
    if help_triggered:
        print(
            "info: Downloading and building bootstrap before processing --help command.\n"
            "      See src/bootstrap/README.md for help with common commands."
        , file=sys.stderr)

    exit_code = 0
    success_word = "successfully"
    try:
        bootstrap(args)
    except (SystemExit, KeyboardInterrupt) as error:
        if hasattr(error, 'code') and isinstance(error.code, int):
            exit_code = error.code
        else:
            exit_code = 1
            print(error, file=sys.stderr)
        success_word = "unsuccessfully"

    if not help_triggered:
        print("Build completed", success_word, "in", format_build_time(time() - start_time),
            file=sys.stderr)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
