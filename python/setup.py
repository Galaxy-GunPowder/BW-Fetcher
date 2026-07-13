"""Imperative build shim. All package metadata lives in pyproject.toml.

This exists only to force a *platform-specific* wheel. The package ships a
prebuilt native binary (BW_Fetcher.exe + DLLs on Windows, an ELF binary + .so
files on Linux), so a wheel built for one OS must NOT be installable on another.
Without this, setuptools would tag the wheel `py3-none-any` (pure Python) and pip
would happily install a Windows binary on a Linux box, then fail at runtime.

We mark the wheel impure and tag it `py3-none-<platform>` — valid for any
Python 3 interpreter (we only subprocess the binary; there is no CPython ABI
dependency) but pinned to the OS/arch of the bundled binary.
"""
from setuptools import setup
from setuptools.dist import Distribution

try:  # setuptools >= 70.1 vendors bdist_wheel
    from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:  # older toolchains still have the `wheel` package
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel


class BinaryDistribution(Distribution):
    """Mark the distribution as containing platform-specific binaries so the
    wheel is tagged for this OS/arch (and laid out as a normal platlib package),
    even though there is no compiled CPython extension."""

    def has_ext_modules(self):
        return True


class bdist_wheel(_bdist_wheel):
    def get_tag(self):
        # Keep the auto-detected platform tag, but make the wheel work on any
        # Python 3 (the binary is launched via subprocess, not imported).
        _python, _abi, plat = super().get_tag()
        return "py3", "none", plat


setup(distclass=BinaryDistribution, cmdclass={"bdist_wheel": bdist_wheel})
