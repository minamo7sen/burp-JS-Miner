package burp;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.BurpExtender.*;
import static burp.Constants.*;

public final class Utilities {
    private static final Pattern FILE_NAME_REGEX = Pattern.compile("(.*)\\.(.*)");
    private static final long REGEX_TIME_OUT = 60000; // 1 minute (x3)

    private Utilities() {
    }

    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();

    // template issue for interesting stuff
    public static void sendNewIssue(
            IHttpRequestResponse baseRequestResponse,
            String issueName,
            String description,
            String issueHighlight,
            List<int[]> responseMarkers,
            String severity,
            String confidence
    ) {
        IScanIssue newCustomIssue = new CustomScanIssue(
                baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, responseMarkers)},
                issueName,
                SCAN_ISSUE_HEADER +
                        description +
                        HTML_LIST_OPEN +
                        HTML_LIST_BULLET_OPEN + issueHighlight + HTML_LIST_BULLET_CLOSED +
                        HTML_LIST_CLOSED +
                        "The identified matches should be highlighted in the HTTP response.<br><br>" +
                        "<br>",
                null,
                severity,
                confidence);

        Utilities.reportIssueIfNotDuplicate(newCustomIssue, baseRequestResponse);

    }

    public static void reportIssueIfNotDuplicate(IScanIssue iScanIssue, IHttpRequestResponse baseRequestResponse) {
        synchronized (Utilities.class) {
            if (isNewIssue(iScanIssue, helpers.analyzeRequest(baseRequestResponse).getUrl())) {
                callbacks.addScanIssue(iScanIssue);
            }
        }
    }

    private static boolean isNewIssue(IScanIssue scanIssueCheck, URL targetURL) {
        String urlPrefix = Utilities.getURLPrefix(targetURL);
        IScanIssue[] allIssues = getCallbacks().getScanIssues(urlPrefix);
        for (IScanIssue scanIssue : allIssues) {
            if (scanIssue.getIssueName().equals(scanIssueCheck.getIssueName())
                    && scanIssue.getIssueDetail().equals(scanIssueCheck.getIssueDetail())
            ) {
                return false;
            }
        }
        return true;
    }

    public static void logScanInfo(String status, int taskId, String scannerName, String url) {
        if (taskId != -1) {
            mStdOut.printf(LOG_FORMAT, "[" + status + "]", LOG_TASK_ID_PREFIX + taskId, scannerName, url);
        }
    }

    public static String getRootDomain(String requestDomain) {
        // Get root Domain (e.g.: example.com instead of sub.example.com)
        Pattern rootDomainRegex = Pattern.compile("[a-z0-9]+.[a-z0-9]+$", Pattern.CASE_INSENSITIVE);
        Matcher matcherRootDomain = rootDomainRegex.matcher(requestDomain);
        if (matcherRootDomain.find() && BurpExtender.isLoaded()) {
            return matcherRootDomain.group();
        }
        return null;
    }

    /**
     * Get domain from "Referer" header to search the caller domain instead of a cdn for example
     */
    public static String getDomainFromReferer(IHttpRequestResponse baseRequestResponse) {
        List<String> requestHeadersList = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String domain;
        for (String header : requestHeadersList) {
            if (header.startsWith("Referer:")) {
                domain = header.replaceAll("^Referer: ", "");
                try {
                    URI domainURI = new URI(domain);
                    return getRootDomain(domainURI.getHost());
                } catch (URISyntaxException e) {
                    mStdErr.println("[-] URI syntax error.");
                }
            }
        }
        return null;
    }

    /**
     * Make sure the found subdomain does not match (www.'request domain') or request domain or root domain
     */
    public static boolean isMatchedDomainValid(String matchedDomain, String rootDomain, String requestDomain) {
        return !matchedDomain.equals("www." + requestDomain)
                && !matchedDomain.equals(requestDomain)
                && !matchedDomain.equals("www." + rootDomain);
    }

    // Source: https://rosettacode.org/wiki/Entropy#Java
    @SuppressWarnings("boxing")
    public static double getShannonEntropy(String s) {
        int n = 0;
        Map<Character, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < s.length(); ++c_) {
            char cx = s.charAt(c_);
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }
        double e = 0.0;
        for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
            if (n != 0) {
                double p = (double) entry.getValue() / n;
                e += p * log2(p);
            }
        }
        return -e;
    }

    private static double log2(double a) {
        return Math.log(a) / Math.log(2);
    }

    /**
     * Source: https://github.com/PortSwigger/example-scanner-checks/blob/master/java/BurpExtender.java
     * helper method to search a response for occurrences of a literal match string
     * and return a list of start/end offsets
     */
    public static List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    public static Path handleDuplicateFile(Path originalFilePath) {
        if (Files.exists(originalFilePath)) {
            Matcher matcherFileName = FILE_NAME_REGEX.matcher(originalFilePath.toString());
            if (
                    matcherFileName.find()
                            && !matcherFileName.group(1).isEmpty()
                            && !matcherFileName.group(2).isEmpty()
            ) {
                String fileName = matcherFileName.group(1);
                String fileExtension = matcherFileName.group(2);
                return findValidName(originalFilePath, fileName, fileExtension);
            } else {
                return Paths.get(originalFilePath.getParent().toString())
                        .resolve(originalFilePath + "_copy");
            }
        }
        return originalFilePath;
    }

    private static Path findValidName(Path originalFilePath, String fileName, String fileExtension) {
        // To maintain performance, we will only handle 20 duplicate file names
        for (int i = 1; i < 20; i++) {
            if (!Files.exists(
                    Paths.get(originalFilePath.getParent().toString()) // get parent directory
                            .resolve(fileName + "_" + i + "." + fileExtension) // append suffix
            )) {
                return Paths.get(originalFilePath.getParent().toString()) // get parent directory
                        .resolve(fileName + "_" + i + "." + fileExtension); // append suffix
            }
        }
        return null;
    }

    public static void createDirectoriesIfNotExist(Path directoryPath) {
        if (!Files.exists(directoryPath)) {
            try {
                Files.createDirectories(directoryPath);
            } catch (IOException ioException) {
                mStdErr.println("[-] createDirectoriesIfNotExist IOException.");
            }
        }
    }

    public static boolean isDirEmpty(Path directory) throws IOException {
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(directory)) {
            return !dirStream.iterator().hasNext();
        }
    }

    // Build IHttpService object from a URL (to use it for "makeHttpRequest")
    static IHttpService url2HttpService(URL url) {
        return new IHttpService() {
            @Override
            // This is the actual host
            public String getHost() {
                return url.getHost();
            }

            @Override
            public int getPort() {
                if ((url.getPort() == -1) && (url.getProtocol().equals("https"))) {
                    return 443;
                } else if ((url.getPort() == -1) && (url.getProtocol().equals("http"))) {
                    return 80;
                } else {
                    return url.getPort();
                }
            }

            @Override
            public String getProtocol() {
                return url.getProtocol();
            }
        };
    }

    public static String getURL(URL url) {
        String urlString = url.toString();
        if (url.getDefaultPort() == url.getPort()) { // https://example.com:443/index -> https://example.com/index
            urlString = urlString.replaceFirst(":" + url.getPort(), "");
        }
        return urlString;
    }

    // get URL Prefix without query strings (to use with "getScanIssues")
    public static String getURLPrefix(URL url) {
        if (url.getDefaultPort() == url.getPort()) {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    url.getPath();
        } else {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    ":" +
                    url.getPort() +
                    url.getPath();
        }
    }

    public static String getURLPrefix(IHttpRequestResponse httpRequestResponse) {
        URL url = helpers.analyzeRequest(httpRequestResponse).getUrl();
        if (url.getDefaultPort() == url.getPort()) {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    url.getPath();
        } else {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    ":" +
                    url.getPort() +
                    url.getPath();
        }
    }

    public static String appendURLPath(URL url, String appendedPath) {
        if ((url.getProtocol().equalsIgnoreCase("https") && url.getPort() == 443)
                || (url.getProtocol().equalsIgnoreCase("http") && url.getPort() == 80)
        ) {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    url.getPath() + appendedPath;
        } else {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    ":" +
                    url.getPort() +
                    url.getPath() + appendedPath;
        }
    }

    public static String b64Decode(String encodedString) {
        byte[] decodedBytes = Base64.getDecoder().decode(encodedString.trim());
        return new String(decodedBytes);
    }

    /**
     * A dirty method to timeout Regexes that takes so long
     * <p>
     * Due to the fact we are using big complex Regexes,
     * sometimes with big files, this can take a long time.
     * This method mitigates this problem by killing the thread before it "kills" your CPU =)
     * Thanks to: https://www.ocpsoft.org/regex/how-to-interrupt-a-long-running-infinite-java-regular-expression/
     */
    public static void regexRunnerWithTimeOut(Runnable runnable) throws InterruptedException {
        Thread thread = new Thread(runnable);
        thread.start();
        Thread.sleep(1000); // wait a bit then check the thread before forcing thread.interrupt

        // Intentionally making loops to check if thread is alive to help continue the execution cleanly
        if (thread.isAlive()) {
            Thread.sleep(REGEX_TIME_OUT);   // wait a minute then check
            if (thread.isAlive()) {
                Thread.sleep(REGEX_TIME_OUT);   // wait a second minute then check
                if (thread.isAlive()) {
                    Thread.sleep(REGEX_TIME_OUT);   // wait a third minute then give-up and kill force thread.interrupt
                    thread.interrupt();
                }
            }
        }
    }
}
