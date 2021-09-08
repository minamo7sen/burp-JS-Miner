package burp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static burp.InterestingStuffFinder.REGEX_QUOTES;

/**
 * NPM package to hold dependency name and version.
 * It also does some basic validations.
 * Mainly used with the "dependency confusion" scan.
 */
public class NPMPackage {
    private String name;
    private String version;
    private String nameWithVersion;

    private static final Pattern DEPENDENCY_AND_VERSION_REGEX = Pattern.compile(REGEX_QUOTES + "(.*)" + REGEX_QUOTES +
            ":" +
            REGEX_QUOTES + "(.*)" + REGEX_QUOTES);

    private static final String[] blacklistDepName = {"node_modules", "favicon.ico"};

    NPMPackage(String dependencyWithNameAndVersion) {
        final Matcher nameAndVersionMatcher = DEPENDENCY_AND_VERSION_REGEX.matcher(dependencyWithNameAndVersion);

        if (nameAndVersionMatcher.find()
                && nameAndVersionMatcher.groupCount() == 2) {
            this.name = nameAndVersionMatcher.group(1);
            this.version = nameAndVersionMatcher.group(2);
            this.nameWithVersion = nameAndVersionMatcher.group();
        }
    }

    // Basic validation for npm package name
    public boolean isNameValid() {
        if (
                name.startsWith(".")  // // npm package name should not start with a period
                        || name.startsWith("_")  // // npm package name should not start with an underscore
                        || !name.toLowerCase().equals(name) // npm package name should be all lower case
                        || name.contains("~\\'!()*\")")
                        || !name.trim().equals(name) // npm package name should not contain leading or trailing spaces
                        || name.length() == 0 // npm package name should not be empty
                        || name.length() > 214 // npm package name length should not exceed 214
        ) {
            return false;
        }

        // if npm package name is in the blacklist, then it's invalid
        for (String blacklist : blacklistDepName) {
            if (name.equals(blacklist)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Basic blacklist for NPM version number (whitelisting is always better, might need to improve this in the future)
     * Reference https://docs.npmjs.com/cli/v7/configuring-npm/package-json#dependencies
     */
    public boolean isVersionValidNPM() {
        return !version.contains("@")
                && !version.contains("/")
                && !version.contains("git")
                && !version.contains("file")
                && !version.contains("npm")
                && !version.contains("link")
                && !version.contains("bitbucket");
    }

    public String getOrgNameFromScopedDependency() {
        return name.replaceAll("^@", "").replaceAll("/.*", "");
    }

    public String getName() {
        return name;
    }

    public String getNameWithVersion() {
        return nameWithVersion;
    }

}
