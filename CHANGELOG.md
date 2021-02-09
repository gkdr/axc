# Changelog

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
- Correct license headers. (thanks @henry-nicolas)
- This file.

### Fixed
- Removed dead code using internal libsignal-protocol-c functionality.

## 0.3.2 and before
Lost to commit logs. Might hunt the changed down later.
