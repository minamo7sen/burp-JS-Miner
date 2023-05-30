package burp.utils;

import burp.BurpExtender;

import com.google.re2j.Pattern;

public class Constants {

    private Constants() {}

    public static final String SETTING_VERBOSE_LOGGING = "verboseLoggingFlag";
    public static final String SETTING_BURP_PASSIVE = "burpPassiveFlag";

    // Logging constants
    public static final String LOG_FORMAT = "%-15s%-15s%-40s%-40s%n";
    public static final String LOG_TASK_ID_PREFIX = " Task ID: ";

    // Regexes
    public static final String WHITE_SPACES = "(\\s*)";
    public static final String REGEX_QUOTES = "['\"`]";

    public static final Pattern CLOUD_URLS_REGEX = Pattern.compile("([\\w]+[.]){1,10}" + // get up to 10 subdomain levels
                    "(s3.amazonaws.com|rds.amazonaws.com|cache.amazonaws.com|" + // AWS
                    "blob.core.windows.net|onedrive.live.com|1drv.com|" + // Azure
                    "storage.googleapis.com|storage.cloud.google.com|storage-download.googleapis.com|content-storage-upload.googleapis.com|content-storage-download.googleapis.com|" + // Google
                    "cloudfront.net|" +
                    "digitaloceanspaces.com|" +
                    "oraclecloud.com|" +
                    "aliyuncs.com|" + // Ali baba
                    "firebaseio.com|" + // Firebase
                    "rackcdn.com|" +
                    "objects.cdn.dream.io|objects-us-west-1.dream.io)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    // Inspired by: https://github.com/nsonaniya2010/SubDomainizer/blob/master/SubDomainizer.py
    public static final Pattern SECRETS_REGEX = Pattern.compile(("['\"`]?(\\w*)" + // Starts with a quote then a word / white spaces
                    WHITE_SPACES +
                    "(secret|token|password|passwd|authorization|bearer|aws_access_key_id|aws_secret_access_key|irc_pass|SLACK_BOT_TOKEN|id_dsa|" +
                    "secret[_-]?(key|token|secret)|" +
                    "api[_-]?(key|token|secret)|" +
                    "access[_-]?(key|token|secret)|" +
                    "auth[_-]?(key|token|secret)|" +
                    "session[_-]?(key|token|secret)|" +
                    "consumer[_-]?(key|token|secret)|" +
                    "public[_-]?(key|token|secret)|" +
                    "client[_-]?(id|token|key)|" +
                    "ssh[_-]?key|" +
                    "encrypt[_-]?(secret|key)|" +
                    "decrypt[_-]?(secret|key)|" +
                    "github[_-]?(key|token|secret)|" +
                    "slack[_-]?token)" +
                    "(\\w*)" + // in case there are any characters / white spaces
                    WHITE_SPACES +
                    "['\"`]?" + // closing quote for variable name
                    WHITE_SPACES +// white spaces
                    "[:=]+[:=>]?" +// assignments operation
                    WHITE_SPACES +
                    REGEX_QUOTES + // opening quote for secret
                    WHITE_SPACES +
                    "([\\w\\-/~!@#$%^&*+]+)" + // Assuming secrets will be alphanumeric with some special characters
                    WHITE_SPACES +
                    REGEX_QUOTES // closing quote for secrets
            ),
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    public static final Pattern HTTP_BASIC_AUTH_SECRETS = Pattern.compile("Authorization.{0,5}Basic(\\s*)([A-Za-z0-9+/=]+)",
            Pattern.MULTILINE);

    public static final Pattern b64SourceMapRegex = Pattern.compile("sourceMappingURL=data(.*)json(.*)base64,((?:[a-z0-9+/]{4})*(?:[a-z0-9+/]{2}==|[a-z0-9+/]{3}=)?)(\\\\n)?",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    public static final Pattern EXTRACT_DEPENDENCIES_REGEX = Pattern.compile((
                    "dependencies" + // we don't care about prefix. Once we find this, just check what comes next
                            "([a-z-_0-9])*" + // some suffix may be (e.g.: dependenciesDev1_2-3)
                            REGEX_QUOTES + // closing quote
                            ":" + // mandatory colon
                            "\\{" + // mandatory opening curly brackets
                            "(.*?)" +   // our dependencies list -> matcher.group(2)
                            "}"     // mandatory closing curly brackets
            ),
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    public static final Pattern extractFromNodeModules = Pattern.compile(("/node_modules/(@?[a-z-_.0-9]+)/"));

    public static final Pattern ENDPOINTS_GET_REGEX = Pattern.compile("\\.[$]?get\\(['\"`]?(.*?)['\"`]?\\)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    public static final Pattern ENDPOINTS_POST_REGEX = Pattern.compile("\\.[$]?post\\(['\"`]?(.*?)['\"`]?\\)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    public static final Pattern ENDPOINTS_PUT_REGEX = Pattern.compile("\\.[$]?put\\(['\"`]?(.*?)['\"`]?\\)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    public static final Pattern ENDPOINTS_DELETE_REGEX = Pattern.compile("\\.[$]?delete\\(['\"`]?(.*?)['\"`]?\\)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    public static final Pattern ENDPOINTS_PATCH_REGEX = Pattern.compile("\\.[$]?patch\\(['\"`]?(.*?)['\"`]?\\)",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    // Scan issues related constants
    public static final String SCAN_ISSUE_HEADER = "This issue was generated by \"" + BurpExtender.EXTENSION_NAME + "\" Burp extension.<br><br>";
    public static final String CONFIDENCE_CERTAIN = "Certain";
    public static final String CONFIDENCE_TENTATIVE = "Tentative";
    public static final String CONFIDENCE_FIRM = "Firm";
    public static final String SEVERITY_INFORMATION = "Information";
    public static final String SEVERITY_MEDIUM = "Medium";
    public static final String SEVERITY_HIGH = "High";
    public static final String HTML_LIST_OPEN = "<ul>";
    public static final String HTML_LIST_BULLET_OPEN = "<li> ";
    public static final String HTML_LIST_BULLET_CLOSED = "</li>";
    public static final String HTML_LIST_CLOSED = "</ul>";

}
