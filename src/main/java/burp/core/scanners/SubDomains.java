package burp.core.scanners;

import burp.*;
import burp.utils.Utilities;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import static burp.utils.Constants.*;
import static burp.utils.Utilities.appendFoundMatches;
import static burp.utils.Utilities.sendNewIssue;

public class SubDomains implements Runnable {
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = callbacks.getHelpers();
    private final IHttpRequestResponse baseRequestResponse;
    private final UUID taskUUID;

    public SubDomains(IHttpRequestResponse baseRequestResponse, UUID taskUUID) {
        this.baseRequestResponse = baseRequestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);

        String responseString = new String(baseRequestResponse.getResponse());
        String responseBodyString = responseString.substring(helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset());
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

        if (rootDomain != null) {
            // For reporting unique matches with markers
            List<byte[]> uniqueMatches = new ArrayList<>();
            StringBuilder uniqueMatchesSB = new StringBuilder();

            // Simple SubDomains Regex
            Pattern subDomainsRegex = Pattern.compile("([a-z-0-9]+[.])+" + rootDomain, Pattern.CASE_INSENSITIVE);
            Matcher matcherSubDomains = subDomainsRegex.matcher(responseBodyString);
            while (matcherSubDomains.find() && BurpExtender.isLoaded()) {
                if (
                        Utilities.isMatchedDomainValid(matcherSubDomains.group(), rootDomain, requestDomain)
                ) {
                    uniqueMatches.add(helpers.urlDecode(matcherSubDomains.group()).getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(helpers.urlDecode(matcherSubDomains.group()), uniqueMatchesSB);
                }
            }
            reportFinding(baseRequestResponse, uniqueMatchesSB, uniqueMatches);
        }
        BurpExtender.getTaskRepository().completeTask(taskUUID);
    }

    private static void reportFinding(IHttpRequestResponse baseRequestResponse, StringBuilder allMatchesSB, List<byte[]> uniqueMatches) {
        if (allMatchesSB.length() > 0) {
            // Get markers of found Cloud URL Matches
            List<int[]> allMatchesMarkers = Utilities.getMatches(baseRequestResponse.getResponse(), uniqueMatches);

            // report the issue
            sendNewIssue(baseRequestResponse,
                    "[JS Miner] Subdomains",
                    "The following subdomains were found in a static file.",
                    allMatchesSB.toString(),
                    allMatchesMarkers,
                    SEVERITY_INFORMATION,
                    CONFIDENCE_CERTAIN
            );
        }
    }
}
