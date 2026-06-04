"""
setup.py for QPQT Python bindings.

For end users:
    pip install qpqt          # uses a prebuilt wheel, no compilation

Building from source (requires liboqs + OpenSSL + a C++17 compiler):
    bash scripts/install_deps.sh
    pip install .

The prebuilt wheels published to PyPI bundle liboqs and OpenSSL, so end
users do not need either installed. Source builds expect liboqs in
/usr/local (lib or lib64) and OpenSSL development headers present.
"""

import os
import sys
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


class QpqtBuildExt(build_ext):
    def build_extension(self, ext):
        import pybind11
        here = os.path.dirname(os.path.abspath(__file__))

        ext.include_dirs += [
            pybind11.get_include(),
            "/usr/local/include",
            os.path.join(here, "include"),
        ]

        # OpenMP
        if sys.platform == "darwin":
            ext.extra_compile_args += ["-Xpreprocessor", "-fopenmp"]
            ext.extra_link_args    += ["-lomp"]
        else:
            ext.extra_compile_args += ["-fopenmp"]
            ext.extra_link_args    += ["-fopenmp"]

        ext.extra_compile_args += ["-O3", "-std=c++17"]

        # liboqs is built statically so no runtime_library_dirs needed.
        ext.library_dirs += ["/usr/local/lib64", "/usr/local/lib"]
        ext.libraries += ["oqs", "ssl", "crypto"]

        super().build_extension(ext)


qpqt_ext = Extension(
    "qpqt",
    sources=["python/qpqt_python.cpp"],
    language="c++",
)

setup(
    name="qpqt",
    version="0.3.0",
    author="Rohan Prabhakar",
    description="Quantum-Safe Columnar Storage Format with row-granular lazy decryption (Python bindings)",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Rohan-Prabhakar/QPQT",
    ext_modules=[qpqt_ext],
    cmdclass={"build_ext": QpqtBuildExt},
    setup_requires=["pybind11>=2.10"],
    install_requires=[],
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
        "Operating System :: POSIX :: Linux",
    ],
)
