# Changelog

## [x.x.x] - xxxx-xx-xx
### Fixed
- Compiler warnings ([#21](https://github.com/gkdr/axc/issues/21), [#29](https://github.com/gkdr/axc/pull/29)) (thanks, [@hartwork](https://github.com/hartwork)!)
- `gcc` can now be set from env like the rest of the tools. ([#30](https://github.com/gkdr/axc/pull/30))) (thanks, [@henry-nicolas](https://github.com/henry-nicolas) and Helmut Grohne!)
- Fix the build for users without libsignal-protocol-c installed system-wide ([#31](https://github.com/gkdr/axc/pull/31)) (thanks, [@hartwork](https://github.com/hartwork)!)

## [0.3.6] - 2021-09-06
### Fixed
- `pkg_config` can now be set from env like the rest of the tools. ([#28](https://github.com/gkdr/axc/pull/28)) (thanks, [@henry-nicolas](https://github.com/henry-nicolas) and Helmut Grohne!)

## [0.3.5] - 2021-08-21
### Fixed
- Added missing symlinks `libaxc.so.$(VER_MAJ)` and `libaxc.so`. ([#24](https://github.com/gkdr/axc/pull/24)) (thanks, [@hartwork](https://github.com/hartwork)!)
- `session_cipher` is now `free()`d using the correct function. ([#25](https://github.com/gkdr/axc/pull/25)) (thanks, [@root-hardenedvault](https://github.com/root-hardenedvault)!)
- Already removed files now don't cause an error during cleanup. ([#27](https://github.com/gkdr/axc/pull/27)) (thanks, [@henry-nicolas](https://github.com/henry-nicolas)!)

## [0.3.4] - 2021-02-10
### Added
- Makefile target to build a shared library, optionally depending on a shared libsignal-protocol-c. ([#17](https://github.com/gkdr/axc/pull/17)) (thanks, [@henry-nicolas](https://github.com/henry-nicolas)!)

### Changed
- Updated libsignal-protocol-c to v2.3.3.

### Fixed
- Added date to 0.3.3 release in changelog.
- Delete an unused variable. ([#22](https://github.com/gkdr/axc/pull/22)) (thanks, [@henry-nicolas](https://github.com/henry-nicolas)!)
- `axc_context_destroy_all()` now also frees itself. ([#23](https://github.com/gkdr/axc/pull/23)) (thanks, [@henry-nicolas](https://github.com/henry-nicolas)!)

## [0.3.3] - 2020-07-23
### Added
- Correct license headers. (thanks [@henry-nicolas](https://github.com/henry-nicolas))
- This file.

### Fixed
- Removed dead code using internal libsignal-protocol-c functionality.

## 0.3.2 and before
Lost to commit logs. Might hunt the changed down later.
