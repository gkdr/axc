# axc 0.3.4
Client lib for [libsignal-c](https://github.com/WhisperSystems/libsignal-protocol-c), implementing the needed database and crypto interfaces using SQLite and gcrypt.
Initially, the library's name was _libaxolotl_, hence the name.

Additionally it provides utility functions for common use cases like encrypting and decrypting, ultimately making direct use of libsignal unnecessary.

## Dependencies
* gcrypt for the crypto (`libgcrypt20-dev`)
* SQLite for the stores (`libsqlite3-dev`)

Optional:
* [cmocka](https://cmocka.org/) for testing (`make test`)
* [gcovr](http://gcovr.com/) for a coverage report (`make coverage`)

## Installation
First, you should pull the _libsignal_ submodule using `git submodule update --init`.
If you are using this as a submodule in another project, you should  lso append `--recursive` so it gets pulled as well.


Since you will need to link _libsignal_ also anyway, it is included here instead of just the headers, and the makefile provides an example of how to compile it as a static library with position independent code.
In theory there is also the possibility to install it as a shared lib by typing `cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=ON ..` instead and then type `sudo make install` after the `make`.


The standard makefile target creates a static library with position independent code.
There is also a target for creating a static library without the code for threading support, as it is implemented using `pthread` and will not work on Windows, and is not necessary for the functioning.


The `client` make target is a little demo that should explain the usage a bit, and if that is not enough there is also the testcases and the documentation.
Unfortunately it is currently broken as the synchronous code was removed.

## Usage
The basic idea is to create the `axc_context`, set what is needed (e.g. path to the database or logging function), init it, and then pass it to every function as it contains all necessary data.
As said before, In theory you should not have to directly communicate with _libsignal_.
