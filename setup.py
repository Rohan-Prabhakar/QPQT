"""
setup.py for QPQT Python bindings.

Install:
    pip install .

Or for development:
    pip install -e .

Requires:
    - liboqs installed to /usr/local (run scripts/install_deps.sh first)
    - OpenSSL 3.x
    - pybind11
    - C++17 compiler with OpenMP support
"""

import os
import sys
import subprocess
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


class QpqtBuildExt(build_ext):
    def build_extension(self, ext):
        # Get pybind11 includes
        import pybind11
        ext.include_dirs += [
            pybind11.get_include(),
            "/usr/local/include",
            os.path.join(os.path.dirname(__file__), "include"),
        ]

        # OpenMP flag
        if sys.platform == "darwin":
            ext.extra_compile_args += ["-Xpreprocessor", "-fopenmp"]
            ext.extra_link_args    += ["-lomp"]
        else:
            ext.extra_compile_args += ["-fopenmp"]
            ext.extra_link_args    += ["-fopenmp"]

        ext.extra_compile_args += ["-O3", "-std=c++17"]
        ext.library_dirs       += ["/usr/local/lib"]
        ext.libraries          += ["oqs", "ssl", "crypto"]
        ext.runtime_library_dirs += ["/usr/local/lib"]

        super().build_extension(ext)


qpqt_ext = Extension(
    "qpqt",
    sources=["python/qpqt_python.cpp"],
    language="c++",
    extra_compile_args=[],
    extra_link_args=[],
)

setup(
    name="qpqt",
    version="0.1.0",
    author="Rohan Prabhakar",
    description="Quantum-Safe Columnar Storage Format — Python bindings",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Rohan1103/qpqt",
    ext_modules=[qpqt_ext],
    cmdclass={"build_ext": QpqtBuildExt},
    install_requires=["pybind11>=2.10"],
    extras_require={
        "pandas": ["pandas>=1.5"],
        "arrow":  ["pyarrow>=12.0"],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: Database",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: C++",
    ],
)
