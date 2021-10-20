package burp.core.scanners;

import burp.*;
import burp.utils.NPMPackage;
import burp.utils.Utilities;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import com.google.re2j.Matcher;

import static burp.utils.Constants.*;
import static burp.utils.Utilities.*;

public class DependencyConfusion implements Runnable {
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = callbacks.getHelpers();
    private final IHttpRequestResponse baseRequestResponse;
    private final UUID taskUUID;
    private final boolean findDependenciesWithRegex;

    public DependencyConfusion(IHttpRequestResponse baseRequestResponse, UUID taskUUID, boolean findDependenciesWithRegex) {
        this.baseRequestResponse = baseRequestResponse;
        this.taskUUID = taskUUID;
        this.findDependenciesWithRegex = findDependenciesWithRegex;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);

        // For reporting unique matches with markers
        List<byte[]> uniqueMatches = new ArrayList<>();
        StringBuilder uniqueMatchesSB = new StringBuilder();

        String responseString = new String(baseRequestResponse.getResponse());
        String responseBodyString = responseString.substring(helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset());

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
                        uniqueMatches.add(npmPackage.getNameWithVersion().getBytes());
                        appendFoundMatches(npmPackage.getNameWithVersion(), uniqueMatchesSB);
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
                uniqueMatches.add(npmPackage.getNameWithVersion().getBytes());
                appendFoundMatches(npmPackage.getNameWithVersion(), uniqueMatchesSB);
            }
        }

        // Get matches & report all dependencies as info
        if (uniqueMatchesSB.length() > 0) {
            List<int[]> allDependenciesMatches = getMatches(baseRequestResponse.getResponse(), uniqueMatches);
            reportDependencies(baseRequestResponse, uniqueMatchesSB.toString(), allDependenciesMatches);

            // Loop each identified package and check for Dependency Confusion
            for (NPMPackage npmPackage : uniquePackageNames) {
                // Get markers of each single dependency with its version
                List<int[]> depMatches = getMatches(baseRequestResponse.getResponse(), npmPackage.toString().getBytes());
                try {
                    if (isConnectionOK()) {
                        verifyDependencyConfusion(baseRequestResponse, npmPackage, depMatches);
                        BurpExtender.getTaskRepository().completeTask(taskUUID);
                    } else {
                        // If connection failed, fail the task to allow re-scanning
                        BurpExtender.getTaskRepository().failTask(taskUUID);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } else {
            // if no NPM package names were found, then task is completed
            BurpExtender.getTaskRepository().completeTask(taskUUID);
        }
    }

    private static boolean isConnectionOK(){
        try {
            URL npmURL = new URL("https://www.npmjs.com/robots.txt");
            IHttpRequestResponse npmJSReqRes = callbacks.makeHttpRequest(Utilities.url2HttpService(npmURL), helpers.buildHttpRequest(npmURL));
            URL npmRegistryURL = new URL("https://registry.npmjs.org/");
            IHttpRequestResponse npmRegistryReqRes = callbacks.makeHttpRequest(Utilities.url2HttpService(npmRegistryURL), helpers.buildHttpRequest(npmRegistryURL));

            return npmJSReqRes.getResponse() != null && npmRegistryReqRes.getResponse() != null;
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return false;
    }

    private static void reportDependencies(IHttpRequestResponse baseRequestResponse, String dependenciesList, List<int[]> depMatches) {
        String findingTitle;
        String findingDetail;
        String severity;

        findingTitle = "[JS Miner] Dependencies";
        findingDetail = "The following dependencies were found in a static file.";
        severity = SEVERITY_INFORMATION;

        sendNewIssue(baseRequestResponse,
                findingTitle,
                findingDetail,
                dependenciesList,
                depMatches,
                severity,
                CONFIDENCE_CERTAIN
        );
    }

    // Verify if dependency is exploitable by querying npm js registry service
    private static void verifyDependencyConfusion(IHttpRequestResponse baseRequestResponse, NPMPackage npmPackage, List<int[]> depMatches) throws IOException {
        String findingTitle = null;
        String findingDetail = null;
        String severity = null;

        // 1. if package version does not comply with NPM Semantic versioning, then report it as info for manual analysis
        if (!npmPackage.isVersionValidNPM()) {
            findingTitle = "[JS Miner] Dependency (Non-NPM registry package)";
            findingDetail = "The following non-NPM dependency was found in a static file. The version might contain a public repository URL, a private repository URL or a file path. Manual review is advised.";
            severity = SEVERITY_INFORMATION;
        } else if (npmPackage.getName().startsWith("@")) {
            // 2. if package name starts with "@", then it's a scoped package.
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
        }

        if (findingTitle != null) {
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
}
