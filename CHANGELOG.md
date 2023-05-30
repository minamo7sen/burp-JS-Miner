# Burp JS-Miner Changelog
Notable changes in JS-Miner releases. Other code improvements that usually happen with every release are not mentioned.

## [1.16] - 2023-05-30
- Added http-basic auth scan to "Secrets" scanner.

## [1.15] - 2022-04-23
- Added new passive scan "API Endpoints Finder".

## [1.14] - 2021-10-20
- Replaced `Java Regex` with `Google/RE2J`, which is much faster, and it does not need timeout tuning. 
- Based on that, all timeout functionalities have been removed.
- Other improvements to make sure the extension runs faster and smoother (against huge websites) without having deadlocks.

## [1.13] - 2021-10-14
- Code Re-Structure
- Similar issues affecting the same URL are now combined into one issue.
  - For example, instead of getting like 100 dependencies (in the same URL), you only get one Burp issue for all of them (with highlights).
  - Same idea for secrets and other scanners.
- New context menu items for all scan types.
- New context menu items for extensions configuration.
  - Enable/disable verbose tasks logging.
  - Enable/disable Burp's passive scanning.
- Tasks management
  - Better visibility over scanning tasks (New context menu item to see tasks summary and uncompleted tasks).
  - Duplicate unwanted scans are now skipped (if 3 factors are matched: Request URL, HTTP Response body hash and scan type).
- Small improvement to the "Secrets" scanner to eliminate some false positives. (Planning to improve it further in the future)
- New scan features: Static Files Dumper
  - It dumps static files from a website to the local disk (namely: JS, JSON, CSS and MAP files).
  - The purpose is to provide an easy way to check those static files locally (using other custom tools or to search for specific patterns based on your target).


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