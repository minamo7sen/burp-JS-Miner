package burp;

import java.io.IOException;
import java.net.URL;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.BurpExtender.*;

public final class Utilities {
    private static final Pattern FILE_NAME_REGEX = Pattern.compile("(.*)\\.(.*)");

    private Utilities() {
    }

    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();

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
}
