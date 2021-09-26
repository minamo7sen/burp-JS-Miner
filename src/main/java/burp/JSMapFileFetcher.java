package burp;

import java.net.URL;
import java.nio.file.*;

import static burp.BurpExtender.mStdErr;
import static burp.BurpExtender.mStdOut;
import static burp.Constants.*;
import static burp.Utilities.getURLPrefix;
import static burp.Utilities.logScanInfo;

public class JSMapFileFetcher implements Runnable {
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();
    private final URL myURL;
    private final Path outputDirectory;
    private final long timeStamp;
    private final int taskId;

    public JSMapFileFetcher(URL myURL, long currentTimestamp, int taskId) {
        this.myURL = myURL;
        this.timeStamp = currentTimestamp;
        this.outputDirectory = Paths.get(System.getProperty("user.home"))
                .resolve(".BurpSuite")
                .resolve("JS-Miner")
                .resolve(myURL.getHost() + "-" + timeStamp);
        this.taskId = taskId;
    }

    public void run() {
        try {
            logScanInfo(SCAN_STATUS_RUNNING, taskId, SCANNER_NAME_SOURCE_MAPPER, getURLPrefix(myURL));
            IHttpRequestResponse newHTTPReqRes = callbacks.makeHttpRequest(Utilities.url2HttpService(myURL), helpers.buildHttpRequest(myURL));
            // if 200 OK, add to sitemap & pass content to parse map files
            if (helpers.analyzeResponse(newHTTPReqRes.getResponse()).getStatusCode() == 200
                    && BurpExtender.isLoaded()
            ) {
                callbacks.addToSiteMap(newHTTPReqRes);
                String response = new String(newHTTPReqRes.getResponse());
                String responseBody = response.substring(helpers.analyzeRequest(newHTTPReqRes.getResponse()).getBodyOffset());
                new SourceMapper(
                        newHTTPReqRes,
                        responseBody,
                        outputDirectory
                );
            }

            logScanInfo(SCAN_STATUS_COMPLETED, taskId, SCANNER_NAME_SOURCE_MAPPER, getURLPrefix(myURL));

        } catch (Exception e) {
            mStdOut.printf(LOG_FORMAT, SCAN_STATUS_FAILED, LOG_TIME_STAMP_STRING + timeStamp + LOG_TASK_ID_PREFIX + taskId, SCANNER_NAME_SOURCE_MAPPER, getURLPrefix(myURL));
            StackTraceElement[] traces = e.getStackTrace();
            for (StackTraceElement trace : traces) {
                mStdErr.println(trace);
            }
        }
    }
}