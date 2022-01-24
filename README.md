# axc 0.3.7
Client lib for [libsignal-protocol-c](https://github.com/WhisperSystems/libsignal-protocol-c), implementing the needed database and crypto interfaces using SQLite and gcrypt.
Initially, the libsignal-protocol-c project was named _libaxolotl_, hence the name `axc`.

Additionally it provides utility functions for common use cases like encrypting and decrypting, ultimately making direct use of libsignal-protocol-c unnecessary.

## Dependencies
* CMake (`cmake`)
* pkg-config (`pkg-config`) or pkgconf (`pkgconf`)
* glib2 (`libglib2.0-dev`)
* libsignal-protocol-c (`libsignal-protocol-c-dev`)
* gcrypt for the crypto (`libgcrypt20-dev`)
* SQLite for the stores (`libsqlite3-dev`)
* GNU make (`make`) or Ninja (`ninja-build`)

Optional:
* [cmocka](https://cmocka.org/) (`libcmocka-dev`) for testing (`make test`)
* [gcovr](http://gcovr.com/) (`gcovr`) for a coverage report (`make coverage`)

## Installation
axc uses CMake as a build system.  It can be used with either GNU make or Ninja.  For example:

```
mkdir build
cd build

cmake -G Ninja ..  # for options see below

ninja -v all
ninja -v test  # potentially with CTEST_OUTPUT_ON_FAILURE=1 in the environment
ninja -v install
```

The following configuration options are supported:

```console
# rm -f CMakeCache.txt ; cmake -D_AXC_HELP=ON -LH . | grep -B1 ':.*=' | sed 's,^--$,,'
// Install build artifacts
AXC_INSTALL:BOOL=ON

// Build with pthreads support
AXC_WITH_PTHREADS:BOOL=ON

// Build test suite (depends on cmocka)
AXC_WITH_TESTS:BOOL=ON

// Build shared libraries (rather than static ones)
BUILD_SHARED_LIBS:BOOL=ON

// Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel ...
CMAKE_BUILD_TYPE:STRING=

// Install path prefix, prepended onto install directories.
CMAKE_INSTALL_PREFIX:PATH=/usr/local
```

They can be passed to CMake as `-D<key>=<value>`, e.g. `-DBUILD_SHARED_LIBS=OFF`.

## Usage
The basic idea is to create the `axc_context`, set what is needed (e.g. path to the database or logging function), init it, and then pass it to every function as it contains all necessary data.
As said before, In theory you should not have to directly communicate with _libsignal-protocol-c_.
