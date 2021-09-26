package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.HashSet;

import static burp.BurpExtender.mStdErr;
import static burp.Constants.*;
import static burp.Utilities.getURLPrefix;
import static burp.Utilities.logScanInfo;

/**
 * JS Miner Scans manager that invokes all the available scans (based on the passed flags)
 */

public class JSMinerScan {

    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();

    final URL targetURL;
    final IHttpRequestResponse baseHTTPReqRes;
    final boolean sourceMapScan;
    final boolean findInterestingStuffScan;
    final int taskId;

    public URL getTargetURL() {
        return targetURL;
    }

    public boolean isSourceMapScan() {
        return sourceMapScan;
    }

    public boolean isFindInterestingStuffScan() {
        return findInterestingStuffScan;
    }

    JSMinerScan(IHttpRequestResponse baseHTTPReqRes, int taskId, boolean sourceMapScan, boolean findInterestingStuffScan) {
        this.baseHTTPReqRes = baseHTTPReqRes;
        this.targetURL = helpers.analyzeRequest(this.baseHTTPReqRes).getUrl();

        // Task ID
        this.taskId = taskId;

        // Scan flags
        this.sourceMapScan = sourceMapScan;
        this.findInterestingStuffScan = findInterestingStuffScan;

        // Kick off the scans
        invokeScans();
    }

    // All scans should be invoked from here
    private void invokeScans() {
        long currentTimestamp = Instant.now().toEpochMilli();

        // Fetch the target's HTTP requests / responses from site map
        IHttpRequestResponse[] siteMapReqResArray = callbacks.getSiteMap(
                Utilities.getURL(getTargetURL())
        );

        if (isSourceMapScan()) {
            HashSet<URL> sourceMapURLs = guessSourceMapFiles(siteMapReqResArray);
            invokeJavaScriptSourceMapper(sourceMapURLs, currentTimestamp, taskId);
        }

        if (isFindInterestingStuffScan()) {
            logScanInfo(SCAN_STATUS_ADDED, taskId, "Target host: " + helpers.analyzeRequest(baseHTTPReqRes).getUrl().getHost(),"SourceMapScan: " + isSourceMapScan() + " | findInterestingStuffScan: " + isFindInterestingStuffScan());
            BurpExtender.getExecutorServiceManager().getExecutorService().submit(new InterestingStuffFinder(siteMapReqResArray, currentTimestamp, taskId));
        }
    }

    // Function to handle Source Mapper scan
    private void invokeJavaScriptSourceMapper(HashSet<URL> sourceMapURLs, long timeStamp, int taskId) {
        // Crawl URLs & construct sources from .map files
        if (sourceMapURLs.size() > 1) {
            // Try to Fetch Map Files
            for (URL url : sourceMapURLs) {
                logScanInfo(SCAN_STATUS_ADDED, taskId, SCANNER_NAME_SOURCE_MAPPER, getURLPrefix(url));
                BurpExtender.getExecutorServiceManager().getExecutorService().submit(
                        new JSMapFileFetcher(url, timeStamp, taskId)
                );
            }
        }
    }

    // Function to guess source map URLs ( it fetches all ".js" files from siteMapReqResArray then append ".map" to them)
    private HashSet<URL> guessSourceMapFiles(IHttpRequestResponse[] iHttpRequestResponses) {
        HashSet<URL> urls = new HashSet<>();
        for (IHttpRequestResponse message : iHttpRequestResponses) {
            URL url = helpers.analyzeRequest(message).getUrl();
            if (url.getPath().endsWith(".js")) {
                try {
                    // Appending ".map" to the list of ".js" files
                    urls.add(new URL(Utilities.appendURLPath(url, ".map")));
                } catch (MalformedURLException malformedURLException) {
                    mStdErr.println("guessSourceMapFiles MalformedURLException.");
                }
            }
        }
        return urls;
    }
}
