package burp.core.scanners;

import burp.*;
import burp.utils.SourceMapper;
import burp.utils.Utilities;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import static burp.BurpExtender.mStdErr;

public class ActiveSourceMapper implements Runnable {
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();
    private URL jsMapURL;
    private Path outputDirectory;
    private final UUID taskUUID;

    public ActiveSourceMapper(IHttpRequestResponse requestResponse, long currentTimestamp, UUID taskUUID) {
        URL jsURL = helpers.analyzeRequest(requestResponse).getUrl();
        this.taskUUID = taskUUID;

        try {
            this.jsMapURL = new URL(Utilities.appendURLPath(jsURL, ".map"));
            this.outputDirectory = Paths.get(System.getProperty("user.home"))
                    .resolve(".BurpSuite")
                    .resolve("JS-Miner")
                    .resolve(jsMapURL.getHost() + "-" + currentTimestamp);
        } catch (MalformedURLException e) {
            mStdErr.println("[-] MalformedURLException");
        }
    }

    public void run() {
        try {
            BurpExtender.getTaskRepository().startTask(taskUUID);
            IHttpRequestResponse newHTTPReqRes = callbacks.makeHttpRequest(Utilities.url2HttpService(jsMapURL), helpers.buildHttpRequest(jsMapURL));
            // if 200 OK, add to sitemap & pass content to parse map files
            if (helpers.analyzeResponse(newHTTPReqRes.getResponse()).getStatusCode() == 200
                    && BurpExtender.isLoaded()
            ) {
                callbacks.addToSiteMap(newHTTPReqRes);
                String response = new String(newHTTPReqRes.getResponse());
                String responseBody = response.substring(helpers.analyzeRequest(newHTTPReqRes.getResponse()).getBodyOffset());
                // Quick check to see if Response contains what we are looking for
                if (responseBody.contains("sources") && responseBody.contains("sourcesContent")) {
                    new SourceMapper(
                            newHTTPReqRes,
                            responseBody,
                            outputDirectory
                    );
                }
            }
            BurpExtender.getTaskRepository().completeTask(taskUUID);
        } catch (Exception e) {
            BurpExtender.getTaskRepository().failTask(taskUUID);
            StackTraceElement[] traces = e.getStackTrace();
            for (StackTraceElement trace : traces) {
                mStdErr.println(trace);
            }
        }
    }
}