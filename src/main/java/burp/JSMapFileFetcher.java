package burp;

import java.net.URL;
import java.nio.file.*;

import static burp.BurpExtender.mStdErr;

public class JSMapFileFetcher implements Runnable {
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();
    private final URL myURL;
    private final Path outputDirectory;

    public JSMapFileFetcher(URL myURL, long currentTimestamp) {
        this.myURL = myURL;
        this.outputDirectory = Paths.get(System.getProperty("user.home"))
                .resolve(".BurpSuite")
                .resolve("JS-Miner")
                .resolve(myURL.getHost() + "-" + currentTimestamp);
    }

    public void run() {
        try {
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
        } catch (Exception e) {
            mStdErr.println("JSMapFileFetcher run Exception");
        }
    }
}