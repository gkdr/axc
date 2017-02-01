# axc
Client lib for axolotl.

## What does it do?
As [libsignal-c](https://github.com/WhisperSystems/libsignal-protocol-c)'s README states, several interfaces have to be implemented before you can use it. This is what this library does, using OpenSSL and SQLite.
In addition, it provides some utility functions that seemed useful when I was working with it.

## Axolotl?
When I started working on this, both the "double ratchet" and the Signal protocol were called "Axolotl".
I did not update the dependency because at first I was too lazy to rename everything in my code, but then the synchronous session establishment was removed from the official implementation and I was not sure if I would need it in the future so I just left it.
Right now I have different priorities, but I will probably do it later. If there is any interest, tell me and I will (probably) hurry up a bit.

## Dependencies
* OpenSSL for the crypto
* SQLite for the stores
* libaxolotl, see below

Optional:
* [cmocka](https://cmocka.org/) for testing (`make test`)
* [gcovr](http://gcovr.com/) for a coverage report (`make coverage`)

## Installation and Usage
An old version of [libsignal-c](https://github.com/WhisperSystems/libsignal-protocol-c) can be found in the `lib` directory, which I hope will not get me into trouble. I manually patched it for easier installation as a shared lib though, so when you follow the installation instructions in the subdir's README, instead of using the cmake command it tells you, use `cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=ON ..`, and after the `make` you need to call `make install` (as superuser).

After you have done that, it should work just fine.
The `client` make target is a little demo that should explain the usage a bit, and if that is not enough there is also the testcases and the documentation.
The basic idea is to create the `axc_context`, set what is needed (e.g. path to the database or logging function), init it, and then pass it to every function as it contains all necessary data. In theory you should not have to directly communicate with libaxolotl.
