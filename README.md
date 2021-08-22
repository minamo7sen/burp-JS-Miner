# Burp JS Miner
This tool tries to find interesting stuff inside static files; mainly JavaScript and JSON files.

## Background
While assessing a web application, it is expected to enumerate information residing inside static ".js" and ".json" files. 

This tool tries to help with this "initial" phase, which should be followed by manual review/analysis of the reported issues.

**Note:** Like many other tools of the same nature, this tool is expected to produce false positives. Also, as it is meant to be used as a helper tool, but it does not replace manual review/analysis (nothing really can). 

## Features
- Scans for secrets / credentials
- Scans for subdomains
- Scans for cloud URLs 
- Tries to construct source code from JavaScript Source Map Files (if found).

### What are JavaScript source maps?
**TL;DR: If the ".map" files were found, this tool can construct the front-end source code and store it under your home directory.**
- JavaScript source map files are mainly meant for debugging purposes. To map the minified JavaScript files to the original source code. 
- The constructed source code might include comments, configurations and other internal information.
- While most of this data might be included in the minified JavaScript files, the original source code and its comments can be easier to review/analyze.
- References:
  - https://www.html5rocks.com/en/tutorials/developertools/sourcemaps/
  - https://www.rapid7.com/de/blog/post/2017/05/24/what-are-javascript-source-maps/

## How to use this tool
The tool contains two main scans:
- **Passive** scans, which are enabled by default (to search for secrets, subdomains and cloud URLs).
- **Actively** try to guess JavaScript source map files. (During the process, HTTP requests will be sent)

For the best results, ensure to navigate your target first in order for all the static files to be loaded then right-click on the target domain 
(example.com) from Burp Suite's site map tree, then select one of "JS Miner" scan options.

Note: JS Source mapper scan is not included in Burp's "Active scan".

## Motivation and contribution
As I'm using Burp Suite almost every day, my goal was to have a burp extension that searches for information inside static files. (Many good command-line tools are out there that are doing what this extension is doing)

I'm open for ideas/suggestions to help improve or optimize this tool.

## Disclaimer
It is the user's responsibility to obey all applicable local, state and federal laws. The author assumes no liability and is not responsible for any misuse or damage caused by this tool.

## License
This project is licensed under the terms of the Apache 2.0 open source license. Please refer to LICENSE for the full terms.
