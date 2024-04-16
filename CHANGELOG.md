<a name="0.0.3"></a>
# 0.0.3 (2022-04-30)

### Feature Added
- None

### Bug Fixes
- None

<a name="0.0.2"></a>
# 0.0.2 (2024-04-14)

### Feature Added
- Added monkey-patching for `window.fetch(...)`

### Bug Fixes
- Fixed issue with monkey-patching for `XMLHttpRequest.prototypr.open(...)`. Moved `beforerequest` event firing to `XMLHttpRequest.prototype.send(...)` from `XMLHttpRequest.prototypr.open(...)`.

<a name="0.0.1"></a>
# 0.0.1 (2024-04-05)

### Feature Added
- Added function API `initializeBotDetector(...)`
- Added function API `initializeXSSDetector(...)`
- Added function API `initializeNavigatorMetricsTracker(...)`

### Bug Fixes
- None