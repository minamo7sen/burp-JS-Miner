# Burp JS-Miner Changelog
Notable changes in JS-Miner releases. Other code improvements that usually happen with every release are not mentioned.

## [1.12] - 2021-09-26
- Added logging to the extension console.
  - Only enabled for invoked tasks through the context menu items. (Not enabled for Burp's passive scan)
- Added a new approach to identify internally disclosed NPM package names.
  - For this approach, "css" files are also scanned as they are a potential location for this type of disclosure.

## [1.11] - 2021-09-19
- Improving the Subdomains scanner.

## [1.1] - 2021-09-08
- Added Dependency Confusion (passive scan)
- Added Inline Base64 Source Mapper (passive scan)

## [1.0] - 2021-08-22
- Initial release