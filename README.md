# Burp JS Miner
This tool tries to find interesting stuff inside static files; mainly JavaScript and JSON files.

## Background
While assessing a web application, it is expected to enumerate information residing inside static files such as JavaScript or JSON resources. 

This tool tries to help with this "initial" recon phase, which should be followed by manual review/analysis of the reported issues.

**Note:** Like many other tools of the same nature, this tool is expected to produce false positives. Also, as it is meant to be used as a helper tool, but it does not replace manual review/analysis (nothing really can). 

## Features
### Secrets / credentials (passive)
- Uses Shannon entropy to improve the confidence level.
- A good resource to verify found API keys:
  - https://github.com/streaak/keyhacks

### Subdomains (passive)
- Nothing special here.

### Cloud URLs (passive)
- Support for (AWS, Azure, Google, CloudFront, Digital Ocean, Oracle, Alibaba, Firebase, Rackspace, Dream Host)

### Dependency Confusion (passive but connects to NPM JS registry to verify the issue)
- Reports a critical issue when a dependency or an organization is missing from the NPM registry.
- Reports informational issues for identified dependencies.

### JS Source Mapper (active and passive)
- Tries to construct source code from JavaScript Source Map Files (if found).
- Actively tries to guess the common location of the ".map" files;
- It can also (passively) parse inline base64 JS map files.

### Static files dumper (passive but requires manual invocation)
- A **one-click** option to dump static files from one or multiple websites.
- Think `ctrl+A` in your Burp's `sitemap`, then dump all static files.
- You can use this feature to run your custom tools to find specific patterns for example.

### API Endpoints Finder (passive)
- Tries to find `GET`/`POST`/`PUT`/`DELETE`/`PATCH` API endpoints.

## How to use this tool
- Download from BApp Store, or download the pre-built "jar" file from "Releases" then load it normally to your Burp Suite.
- Passive scans are invoked automatically, while active scans require manual invocation ( by right-clicking your targets) from the site map or other Burp windows.
- No configuration needed, no extra Burp Suite tab.
  - Just install and maybe enjoy.

### More information
The tool contains two main scans:
- **Passive** scans, which are enabled by default (to search for inline JS map files, secrets, subdomains and cloud URLs).
- **Actively** try to guess JavaScript source map files. (During the process, HTTP requests will be sent)

#### For the best results:
- Ensure to **navigate** your target first in order for all the static files to be loaded;
- Passive scans will trigger automatically. Ensure Burp's Sitemap is **displaying** your target's static files. 
- Then right-click on the target domain (example.com) from Burp Suite's site map tree, then select one of "JS Miner" scan options.
- Sometimes you may need to allow cookies to be sent by the extension. Check the wiki for how to do that.

## Motivation and contribution
As I'm using Burp Suite almost every day, my goal was to have a burp extension that searches for information inside static files. (Many good command-line tools are out there that are doing what this extension is doing)

I'm open for ideas/suggestions to help improve or optimize this tool.

### Contributors; thanks to
-  [Stanislav Kravchenko](https://linkedin.com/in/staskravchenko/): For suggesting the dependency confusion feature, besides helping with testing and improving the functionality. 

### Build from source
```
git clone https://github.com/minamo7sen/burp-JS-Miner.git
cd burp-JS-Miner
gradle fatJar
```
Then, the jar file can be found at `build/libs/burp-JS-Miner-all.jar`.


## Disclaimer
It is the user's responsibility to obey all applicable local, state and federal laws. The author assumes no liability and is not responsible for any misuse or damage caused by this tool.

## License
This project is licensed under the terms of the Apache 2.0 open source license. Please refer to LICENSE for the full terms.
