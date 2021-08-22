package burp;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
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

    private URL getMyURL() {
        return myURL;
    }

    private Path getOutputDirectory() {
        return outputDirectory;
    }

    public Path getTempDirectory() {
        return getOutputDirectory().resolve("tmp");
    }

    public void run() {
        try {
            IHttpRequestResponse newHTTPReqRes = callbacks.makeHttpRequest(Utilities.url2HttpService(getMyURL()), helpers.buildHttpRequest(getMyURL()));
            // if 200 OK, add to sitemap & pass content to parse map files
            if (helpers.analyzeResponse(newHTTPReqRes.getResponse()).getStatusCode() == 200
                    && BurpExtender.isLoaded()
            ) {
                callbacks.addToSiteMap(newHTTPReqRes);
                String response = new String(newHTTPReqRes.getResponse());
                String responseBody = response.substring(helpers.analyzeRequest(newHTTPReqRes.getResponse()).getBodyOffset());
                parseMapFile(newHTTPReqRes, responseBody);
            }
        } catch (Exception e) {
            mStdErr.println("JSMapFileFetcher run Exception");
        }
    }

    // Function 1 - parse Map Files
    private void parseMapFile(IHttpRequestResponse httpReqRes, String json) {
        ObjectMapper objectMapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try {
            JSMapFile mapFile = objectMapper.readValue(json, JSMapFile.class);
            for (int i = 0; i <= mapFile.getSources().length - 1; i++) {
                saveFile(
                        httpReqRes,
                        mapFile.getSources()[i].replaceAll("[?%*|:\"<>~]", ""),
                        helpers.stringToBytes(mapFile.getSourcesContent()[i])
                );
            }
        } catch (Exception e) {
            mStdErr.println("[-] Error processing the file - parseMapFile Exception.");
        }
    }

    // Function 2 - After parsing map files, save resulting data to mapped destinations
    private void saveFile(IHttpRequestResponse httpReqRes, String sourceFilePath, byte[] data) {
        Path filePath = Paths.get(sourceFilePath);
        String fileName = filePath.getFileName().toString();
        Utilities.createDirectoriesIfNotExist(getTempDirectory());
        try {
            Path tempFile = Files.createTempFile(getTempDirectory(), fileName, ".js");
            Files.write(tempFile, data);
            String trustedFileName = secureFile(sourceFilePath);
            Path trustedPath = Paths.get(trustedFileName);
            // check & rename to "e.g.: existingFile_n.js" if duplicate
            trustedPath = Utilities.handleDuplicateFile(trustedPath);
            Files.move(tempFile, trustedPath);
            if (!Utilities.isDirEmpty(getOutputDirectory())) {
                sendJSMapperIssue(httpReqRes);
            }
        } catch (IOException e) {
            mStdErr.println("[-] Error saving the file - saveFile IOException.");
        }
    }


    // Function 3 - Security check for File name to prevent potential path traversal attacks
    private String secureFile(String fileName) {
        File destinationDir = new File(getOutputDirectory().toString());

        String fakeRootPath;
        if (System.getenv("SystemDrive") != null) {
            fakeRootPath = System.getenv("SystemDrive");
        } else {
            fakeRootPath = FileSystems.getDefault().getSeparator();
        }
        File untrustedFile = new File(fakeRootPath + fileName); // Fake root path

        File trustedFile;
        try {
            trustedFile = new File(destinationDir.getCanonicalPath() +
                    untrustedFile.toPath().normalize().toString().replace(fakeRootPath, FileSystems.getDefault().getSeparator())); // Replace fakeRootPath with system separator

            if (trustedFile.getCanonicalPath().startsWith(destinationDir.getCanonicalPath())) {
                Utilities.createDirectoriesIfNotExist(trustedFile.getParentFile().toPath());
                return trustedFile.toString();
            } else {
                mStdErr.println("[-] Unexpected OS file write was prevented.");
            }
        } catch (IOException ioException) {
            mStdErr.println("[-] secureFile failed - IOException.");
        }
        // If structuring the file path failed, keep the file in the temp directory instead of not saving it
        return getTempDirectory().toString();
    }

    private void sendJSMapperIssue(IHttpRequestResponse httpReqRes) {
        IScanIssue scanIssue = null;
        try {
            scanIssue = new CustomScanIssue(
                    httpReqRes.getHttpService(),
                    getMyURL(),
                    new IHttpRequestResponse[]{httpReqRes},
                    "[JS Miner] JavaScript Source Mapper",
                    "This issue was generated by \"" + BurpExtender.EXTENSION_NAME + "\" Burp extension.<br><br>" +
                            "It was possible to retrieve JavaScript source map files of the target host." +
                            "The retrieved (front-end) source code is available (for manual review) in the following location:<br><br>"
                            + "<b>" + getOutputDirectory() + "</b>",
                    null,
                    "Information",
                    "Certain");
        } catch (Exception e) {
            mStdErr.println("[-] createDirectoriesIfNotExist Exception.");
        }
        Utilities.reportIssueIfNotDuplicate(scanIssue, httpReqRes);
    }
}