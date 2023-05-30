package burp.utils;

import burp.*;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import static burp.BurpExtender.*;
import static burp.utils.Constants.*;

public final class Utilities {
    private static final Pattern FILE_NAME_REGEX = Pattern.compile("(.*)\\.(.*)");

    private Utilities() {
    }

    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();

    /*
     *  This is mainly used by the "querySiteMap" function
     *  Checks if the HTTP Response is not null and that the Requested file is either JS or JSON
     */
    public static boolean isValidScanTarget(IHttpRequestResponse baseRequestResponse, String[] queryFileExtensions) {
        if (baseRequestResponse.getResponse() != null && BurpExtender.isLoaded()) {
            for (String fileExtension: queryFileExtensions) {
                if (helpers.analyzeRequest(baseRequestResponse).getUrl().getPath().endsWith("." + fileExtension)) {
                    return true;
                }
            }
        }
        return false;
    }

    /*
     *  Query Site Map for specific extensions (including children of the passed Request URL)
     */
    public static Set<IHttpRequestResponse> querySiteMap(IHttpRequestResponse[] httpReqResArray, String[] queryFileExtensions) {
        HashSet<IHttpRequestResponse> uniqueRequests = new HashSet<>();
        for (IHttpRequestResponse baseRequestResponse : httpReqResArray) {
            URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
            // Get all child URLs from Site Map
            IHttpRequestResponse[] siteMapReqResArray = callbacks.getSiteMap(Utilities.getURL(url));
            for (IHttpRequestResponse requestResponse : siteMapReqResArray) {
                if (isValidScanTarget(requestResponse, queryFileExtensions)) {
                    uniqueRequests.add(requestResponse);
                }
            }
        }
        return uniqueRequests;
    }

    // Append found matches to be listed in Burp's issues
    public static void appendFoundMatches(String finding, StringBuilder uniqueMatchesSB) {
        // Only report unique instances
        if (uniqueMatchesSB.indexOf(HTML_LIST_BULLET_OPEN + finding + HTML_LIST_BULLET_CLOSED) == -1) {
            uniqueMatchesSB.append(HTML_LIST_BULLET_OPEN);
            uniqueMatchesSB.append(finding);
            uniqueMatchesSB.append(HTML_LIST_BULLET_CLOSED);
        }
    }

    /**
     * An improved version of the getMatches method to search an HTTP response for occurrences of a unique matches
     * and return a sorted list of start/end offsets
     */
    public static List<int[]> getMatches(byte[] response, List<byte[]> uniqueMatches)
    {
        List<int[]> matches = new ArrayList<>();

        for (byte[] match: uniqueMatches) {
            // Limit Response highlighters (matches) only to 500 then break (to maintain performance)
            if (matches.size() < 500) {
                int start = 0;
                while (start < response.length)
                {
                    start = helpers.indexOf(response, match, false, start, response.length);
                    if (start == -1)
                        break;
                    matches.add(new int[] { start, start + match.length });
                    start += match.length;
                }
            } else {
                break;
            }
        }
        // Sort found matches or otherwise Burp will complain (Source: https://stackoverflow.com/questions/19596950/sort-an-arraylist-of-integer-arrays)
        matches.sort(new Comparator<int[]>() {
            private static final int INDEX = 0;

            @Override
            public int compare(int[] o1, int[] o2) {
                return Integer.compare(o1[INDEX], o2[INDEX]);
            }
        });

        // Dirty trick to fix overlapping offsets
        for (int i = 0; i < matches.size(); i++) {
            if (i + 1 != matches.size()
                    && matches.get(i)[1] > matches.get(i + 1)[0]) {
                int[] fixed = {matches.get(i)[0], matches.get(i + 1)[0]};
                matches.set(i, fixed);
            }
        }

        return matches;
    }


    public static byte[] getHTTPResponseBodyHash(IHttpRequestResponse baseRequestResponse) {
        if (baseRequestResponse.getResponse() != null) {
            // Get bytes of Response content
            int bodyOffset = helpers.analyzeRequest(baseRequestResponse.getResponse()).getBodyOffset();
            byte[] responseBytes = baseRequestResponse.getResponse();
            byte[] responseBodyBytes = Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length);
            MessageDigest digest = null;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return digest != null ? digest.digest(responseBodyBytes) : new byte[0];
        } else {
            return new byte[0];
        }
    }


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
                        issueHighlight+
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

    public static URL trimURL(URL url) {
        String host = url.getHost();
        String string = url.toString().replaceAll(host + ".*", host);
        try {
            return new URL(string);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return null;
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
                && !matchedDomain.equals("www." + rootDomain)
                && matchedDomain.endsWith(rootDomain);
    }

    public static boolean isHighEntropy(String s) {
        return Utilities.getShannonEntropy(s) >= 3.5;
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

    public static boolean isDirEmpty(Path directory) {
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(directory)) {
            return !dirStream.iterator().hasNext();
        } catch (IOException e) {
            return false;
        }
    }

    // Build IHttpService object from a URL (to use it for "makeHttpRequest")
    public static IHttpService url2HttpService(URL url) {
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

    public static Path urlToPath(URI uri) {

        Path newPath = Paths.get(FileSystems.getDefault().getSeparator());

        String[] uriPaths = uri.getPath().split("/");
        for (String uriPath: uriPaths) {
            newPath = Paths.get( newPath.toUri() )
                    .resolve(uriPath);
        }

        return newPath;
    }

    public static String b64Decode(String encodedString) {
        byte[] decodedBytes = Base64.getDecoder().decode(encodedString.trim());
        return new String(decodedBytes);
    }

    public static boolean isValidBase64(String base64) {
        try {
            // Decode string
            Base64.getDecoder().decode(base64);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

}
