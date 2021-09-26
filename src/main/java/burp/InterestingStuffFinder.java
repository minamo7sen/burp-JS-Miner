package burp;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.BurpExtender.mStdErr;
import static burp.Utilities.sendNewIssue;
import static burp.Constants.*;

/**
 * Class to find interesting stuff in JavaScript & JSON files
 */

public class InterestingStuffFinder implements Runnable {
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = callbacks.getHelpers();
    private final IHttpRequestResponse[] baseRequestResponseArray;
    private final long timeStamp;
    private final int taskId;


    InterestingStuffFinder(IHttpRequestResponse[] baseRequestResponseArray, long timeStamp, int taskId) {
        this.baseRequestResponseArray = baseRequestResponseArray;
        this.timeStamp = timeStamp;
        this.taskId = taskId;
    }

    public void run() {
        try {
            for (IHttpRequestResponse baseRequestResponse : baseRequestResponseArray) {
                if (baseRequestResponse.getResponse() != null && BurpExtender.isLoaded()) {
                    // Pass ".js" and ".json" files to mainHandler to run all scans
                    if (
                            (helpers.analyzeRequest(baseRequestResponse).getUrl().getPath().endsWith(".js"))
                                    || (helpers.analyzeRequest(baseRequestResponse).getUrl().getPath().endsWith(".json"))
                    ) {
                        String responseString = new String(baseRequestResponse.getResponse());
                        String responseBodyString = responseString.substring(helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset());
                        mainHandler(baseRequestResponse, responseBodyString, timeStamp);
                    } else if (
                            // pass css files to dependency confusion as they might leak internal package names
                            helpers.analyzeRequest(baseRequestResponse).getUrl().getPath().endsWith(".css")
                    ) {
                        String responseString = new String(baseRequestResponse.getResponse());
                        String responseBodyString = responseString.substring(helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset());
                        findDependencyConfusion(baseRequestResponse, responseBodyString, false);
                    }
                }
            }
        } catch (Exception e) {
            try {
                throw e;
            } catch (Exception ex) {
                Utilities.logScanInfo(SCAN_STATUS_FAILED, taskId, SCANNER_NAME_INTERESTING_STUFF, "");
                StackTraceElement[] traces = ex.getStackTrace();
                for (StackTraceElement trace : traces) {
                    mStdErr.println(trace);
                }
            }
        }
    }

    private void mainHandler(IHttpRequestResponse baseRequestResponse, String responseBodyString, long timeStamp) throws InterruptedException, IOException {
        findDependencyConfusion(baseRequestResponse, responseBodyString, true);
        handleInlineMapFiles(baseRequestResponse, responseBodyString, timeStamp);
        findSecrets(baseRequestResponse, responseBodyString);
        findSubDomains(baseRequestResponse, responseBodyString);
        findCloudURLs(baseRequestResponse, responseBodyString);
    }

    /**
     * Scan function 1 - Check all strings for potential secrets (uses Shannon Entropy to increase confidence)
     */
    private void findSecrets(IHttpRequestResponse baseRequestResponse, String responseBodyString) throws InterruptedException {
        Utilities.logScanInfo(SCAN_STATUS_RUNNING, taskId, SCANNER_NAME_SECRETS, Utilities.getURLPrefix(baseRequestResponse));

        Matcher matcherSecrets = SECRETS_REGEX.matcher(new InterruptibleCharSequence(responseBodyString));
        Runnable runnable = () -> {
            while (matcherSecrets.find() && BurpExtender.isLoaded()) {
                List<int[]> secretsMatches = Utilities.getMatches(baseRequestResponse.getResponse(), helpers.stringToBytes(matcherSecrets.group()));
                double entropy = Utilities.getShannonEntropy(matcherSecrets.group(20)); // group(2) matches our secret
                String confidence;
                String description;
                if (entropy >= 3.5) {
                    // if high entropy, confidence is "Firm"
                    confidence = CONFIDENCE_FIRM;
                    description = "The following secret has high entropy and it was found in a static file.";
                } else {
                    // if low entropy, confidence is "Tentative"
                    confidence = CONFIDENCE_TENTATIVE;
                    description = "The following secret has low entropy and it was found in a static file.";
                }
                sendNewIssue(baseRequestResponse,
                        "[JS Miner] Secrets / Credentials",
                        description,
                        matcherSecrets.group(),
                        secretsMatches,
                        SEVERITY_MEDIUM,
                        confidence
                );
            }
            Utilities.logScanInfo(SCAN_STATUS_COMPLETED, taskId, SCANNER_NAME_SECRETS, Utilities.getURLPrefix(baseRequestResponse));
        };
        Utilities.regexRunnerWithTimeOut(runnable);
    }

    /**
     * Scan function 2 - Get all subdomains
     */
    private void findSubDomains(IHttpRequestResponse baseRequestResponse, String responseBodyString) throws InterruptedException {
        Utilities.logScanInfo(SCAN_STATUS_RUNNING, taskId, SCANNER_NAME_SUBDOMAINS, Utilities.getURLPrefix(baseRequestResponse));
        String domainFromReferer = Utilities.getDomainFromReferer(baseRequestResponse);
        String requestDomain = helpers.analyzeRequest(baseRequestResponse).getUrl().getHost();
        String rootDomain;
        // Try to get caller domain from Referer header (to avoid matching cdn subdomains, ..etc.)
        if (domainFromReferer != null) {
            rootDomain = domainFromReferer;
        } else {
            // If the above failed, then use the domain from the HTTP request
            rootDomain = Utilities.getRootDomain(requestDomain);
        }

        Runnable runnable = () -> {
            if (rootDomain != null) {
                // Simple SubDomains Regex
                Pattern subDomainsRegex = Pattern.compile("([a-z0-9]+[.])+" + rootDomain, Pattern.CASE_INSENSITIVE);
                Matcher matcherSubDomains = subDomainsRegex.matcher(new InterruptibleCharSequence(responseBodyString));
                while (matcherSubDomains.find() && BurpExtender.isLoaded()) {
                    if (
                            Utilities.isMatchedDomainValid(matcherSubDomains.group(), rootDomain, requestDomain)
                    ) {
                        // Get markers of found subdomains
                        List<int[]> subDomainsMatches = Utilities.getMatches(baseRequestResponse.getResponse(), matcherSubDomains.group().getBytes());
                        // report the issue
                        sendNewIssue(baseRequestResponse,
                                "[JS Miner] Subdomains",
                                "The following subdomain was found in a static file.",
                                helpers.urlDecode(matcherSubDomains.group()),
                                subDomainsMatches,
                                SEVERITY_INFORMATION,
                                CONFIDENCE_CERTAIN
                        );
                    }
                }
            }
            Utilities.logScanInfo(SCAN_STATUS_COMPLETED, taskId, SCANNER_NAME_SUBDOMAINS, Utilities.getURLPrefix(baseRequestResponse));
        };
        Utilities.regexRunnerWithTimeOut(runnable);
    }


    /**
     * Scan function 3 - Get Cloud URLs
     */
    private void findCloudURLs(IHttpRequestResponse baseRequestResponse, String responseBodyString) throws InterruptedException {

        Utilities.logScanInfo(SCAN_STATUS_RUNNING, taskId, SCANNER_NAME_CLOUD_URLS, Utilities.getURLPrefix(baseRequestResponse));

        Matcher cloudURLsMatcher = CLOUD_URLS_REGEX.matcher(new InterruptibleCharSequence(responseBodyString));

        Runnable runnable = () -> {
            while (cloudURLsMatcher.find() && BurpExtender.isLoaded()) {
                // Get markers of found Cloud URL Matches
                List<int[]> cloudHostsMatches = Utilities.getMatches(baseRequestResponse.getResponse(), cloudURLsMatcher.group().getBytes());
                // report the issue
                sendNewIssue(baseRequestResponse,
                        "[JS Miner] Cloud Resources",
                        "The following  cloud URL was found in a static file.",
                        cloudURLsMatcher.group(),
                        cloudHostsMatches,
                        SEVERITY_INFORMATION,
                        CONFIDENCE_CERTAIN
                );
            }
            Utilities.logScanInfo(SCAN_STATUS_COMPLETED, taskId, SCANNER_NAME_CLOUD_URLS, Utilities.getURLPrefix(baseRequestResponse));
        };
        Utilities.regexRunnerWithTimeOut(runnable);
    }

    /**
     * Scan function 4 - Parse inline JS map files
     */
    private void handleInlineMapFiles(IHttpRequestResponse baseRequestResponse, String responseBodyString, long timeStamp) {

        Utilities.logScanInfo(SCAN_STATUS_RUNNING, taskId, SCANNER_NAME_INLINE_SOURCE_MAPS, Utilities.getURLPrefix(baseRequestResponse));

        Path outputDirPath = Paths.get(System.getProperty("user.home"))
                .resolve(".BurpSuite")
                .resolve("JS-Miner")
                .resolve(helpers.analyzeRequest(baseRequestResponse).getUrl().getHost() + "-" + timeStamp);

        Matcher b64SourceMapperMatcher = b64SourceMapRegex.matcher(responseBodyString);

        while (b64SourceMapperMatcher.find()) {
            new SourceMapper(
                    baseRequestResponse,
                    Utilities.b64Decode(b64SourceMapperMatcher.group(3)), // Base64 Decoded map File Data
                    outputDirPath
            );
        }
        Utilities.logScanInfo(SCAN_STATUS_COMPLETED, taskId, SCANNER_NAME_INLINE_SOURCE_MAPS, Utilities.getURLPrefix(baseRequestResponse));
    }

    /**
     * Scan function 5 - Find Dependency Confusion
     */
    private void findDependencyConfusion(IHttpRequestResponse baseRequestResponse, String responseBodyString, boolean findDependenciesWithRegex) throws IOException {
        Utilities.logScanInfo(SCAN_STATUS_RUNNING, taskId, SCANNER_NAME_DEPENDENCY_CONFUSION, Utilities.getURLPrefix(baseRequestResponse));

        // Removing unwanted spaces, new lines and so on, which might mislead matching our Regex
        Matcher dependenciesListMatcher = EXTRACT_DEPENDENCIES_REGEX.matcher(responseBodyString
                .replaceAll("\\s", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("\n", ""));

        HashSet<NPMPackage> uniquePackageNames = new HashSet<>();

        // Approach 1 to identify internal NPM packages based on the "EXTRACT_DEPENDENCIES_REGEX"
        if (findDependenciesWithRegex) {
            while (dependenciesListMatcher.find()) {
                String dependencyList = dependenciesListMatcher.group(2);
                String[] dependencyListArray = dependencyList.split(",");
                for (String dependency : dependencyListArray) {
                    // A new npm package that holds and validates name and version for later use
                    NPMPackage npmPackage = new NPMPackage(dependency);

                    // package name must be valid
                    if (npmPackage.isNameValid()) {
                        uniquePackageNames.add(npmPackage);
                    }
                }
            }
        }

        // Approach 2 to identify internal NPM packages that were part of common node_modules URL path (e.g.: /node_modules/<pkg> )
        Matcher fromNodeModulesPathMatcher = extractFromNodeModules.matcher(responseBodyString);
        while (fromNodeModulesPathMatcher.find()) {
            // The new npm package won't have a version, so passing "disclosedNameOnly" flag to handle it properly
            NPMPackage npmPackage = new NPMPackage(fromNodeModulesPathMatcher.group(1), true);
            // package name must be valid
            if (npmPackage.isNameValid()) {
                uniquePackageNames.add(npmPackage);
            }
        }

        for (NPMPackage npmPackage: uniquePackageNames) {
            // Get markers of each single dependency with its version
            List<int[]> depMatches = Utilities.getMatches(baseRequestResponse.getResponse(), npmPackage.toString().getBytes());
            verifyDependencyConfusion(baseRequestResponse, npmPackage, depMatches);
        }
        Utilities.logScanInfo(SCAN_STATUS_COMPLETED, taskId, SCANNER_NAME_DEPENDENCY_CONFUSION, Utilities.getURLPrefix(baseRequestResponse));
    }


    // Verify if dependency is exploitable by querying npm js registry service
    private static void verifyDependencyConfusion(IHttpRequestResponse baseRequestResponse, NPMPackage npmPackage, List<int[]> depMatches) throws IOException {
        String findingTitle;
        String findingDetail;
        String severity;

        // 1. if package version does not comply with NPM Semantic versioning, then report it as info for manual analysis
        if (!npmPackage.isVersionValidNPM()) {
            findingTitle = "[JS Miner] Dependency (Non-NPM registry package)";
            findingDetail = "The following non-NPM dependency was found in a static file. The version might contain a public repository URL, a private repository URL or a file path. Manual review is advised.";
            severity = SEVERITY_INFORMATION;
        }
        // 2. if package name starts with "@", then it's a scoped package.
        else if (npmPackage.getName().startsWith("@")) {

            String organizationName = npmPackage.getOrgNameFromScopedDependency();

            URL url = new URL("https://www.npmjs.com/org/" + organizationName);
            IHttpRequestResponse httpRequestResponse = callbacks.makeHttpRequest(Utilities.url2HttpService(url), helpers.buildHttpRequest(url));

            // 2.1 scoped package with non-existing organization -> Most likely a valid issue
            if (httpRequestResponse.getResponse() != null
            && helpers.analyzeResponse(httpRequestResponse.getResponse()).getStatusCode() == 404) {
                // valid critical issue
                findingTitle = "[JS Miner] Dependency (organization not found)";
                findingDetail = "The following potentially exploitable dependency was found in a static file. The organization does not seem to be available, which indicates that it can be registered: " + url;
                severity = SEVERITY_HIGH;
            }
            // 2.2 scoped package with an existing organization -> Info issue
            else {
                // most likely not an issue but still reported as an informational
                findingTitle = "[JS Miner] Dependency (scoped package)";
                findingDetail = "The following dependency (a.k.a: scoped package) was found in a static file.";
                severity = SEVERITY_INFORMATION;
            }
        } else {
            // 3. Public NPM package
            URL url = new URL("https://registry.npmjs.org/" + npmPackage.getName());
            IHttpRequestResponse httpRequestResponse = callbacks.makeHttpRequest(Utilities.url2HttpService(url), helpers.buildHttpRequest(url));

            // 3.1 If package name does not exist -> Most likely a valid issue
            if (httpRequestResponse.getResponse() != null
            && helpers.analyzeResponse(httpRequestResponse.getResponse()).getStatusCode() == 404) {
                // valid critical issue
                findingTitle = "[JS Miner] Dependency Confusion";
                findingDetail = "The following potentially exploitable dependency was found in a static file. There was no entry for this package on the 'npm js' registry: " + url;
                severity = SEVERITY_HIGH;
            }
            // 3.2 If package name does exist -> Info issue
            else {
                // most likely not an issue but still reported as an informational
                findingTitle = "[JS Miner] Dependency";
                findingDetail = "The following dependency was found in a static file. Most likely, this package is either publicly available or it is private.";
                severity = SEVERITY_INFORMATION;
            }
        }

        sendNewIssue(baseRequestResponse,
                findingTitle,
                findingDetail,
                npmPackage.getNameWithVersion(),
                depMatches,
                severity,
                CONFIDENCE_CERTAIN
        );
    }
}
