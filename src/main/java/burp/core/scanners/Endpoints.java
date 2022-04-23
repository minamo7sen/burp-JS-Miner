package burp.core.scanners;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.utils.Utilities;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static burp.utils.Constants.*;
import static burp.utils.Utilities.appendFoundMatches;
import static burp.utils.Utilities.sendNewIssue;

public class Endpoints implements Runnable {
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = callbacks.getHelpers();
    private final IHttpRequestResponse baseRequestResponse;
    private final UUID taskUUID;

    public Endpoints(IHttpRequestResponse baseRequestResponse, UUID taskUUID) {
        this.baseRequestResponse = baseRequestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);
        // For readability, reporting each method separately, maybe I'll combine them in the future into one burp issue.
        endpointsFinder(ENDPOINTS_GET_REGEX, "get");
        endpointsFinder(ENDPOINTS_POST_REGEX, "post");
        endpointsFinder(ENDPOINTS_PUT_REGEX, "put");
        endpointsFinder(ENDPOINTS_DELETE_REGEX, "delete");
        endpointsFinder(ENDPOINTS_PATCH_REGEX, "patch");
        BurpExtender.getTaskRepository().completeTask(taskUUID);
    }

    private void endpointsFinder(Pattern endpointsPattern, String method) {
        // For reporting unique matches with markers
        List<byte[]> uniqueMatches = new ArrayList<>();
        StringBuilder uniqueMatchesSB = new StringBuilder();

        String responseString = new String(baseRequestResponse.getResponse());
        String responseBodyString = responseString.substring(helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset());
        Matcher endpointsMatcher = endpointsPattern.matcher(responseBodyString);

        while (BurpExtender.isLoaded() && endpointsMatcher.find() && endpointsMatcher.group(1).contains("/")
        && !endpointsMatcher.group(1).contains("<") && !endpointsMatcher.group(1).contains(">") ) {
            uniqueMatches.add(endpointsMatcher.group(1).getBytes(StandardCharsets.UTF_8));
            appendFoundMatches(endpointsMatcher.group(1), uniqueMatchesSB);
        }

        reportFinding(baseRequestResponse, uniqueMatchesSB, uniqueMatches, method.toUpperCase(Locale.ENGLISH));
    }

    private static void reportFinding(IHttpRequestResponse baseRequestResponse, StringBuilder allMatchesSB, List<byte[]> uniqueMatches, String method) {
        if (allMatchesSB.length() > 0) {
            // Get markers of found Cloud URL Matches
            List<int[]> allMatchesMarkers = Utilities.getMatches(baseRequestResponse.getResponse(), uniqueMatches);

            // report the issue
            sendNewIssue(baseRequestResponse,
                    "[JS Miner] API Endpoints (" + method + ")",
                    "The following API endpoints were found in a static file.",
                    allMatchesSB.toString(),
                    allMatchesMarkers,
                    SEVERITY_INFORMATION,
                    CONFIDENCE_CERTAIN
            );
        }
    }
}
