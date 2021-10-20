package burp.utils;

import java.util.Objects;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import static burp.utils.Constants.REGEX_QUOTES;

/**
 * NPM package to hold dependency name and version.
 * It also does some basic validations.
 * Mainly used with the "dependency confusion" scan.
 */
public class NPMPackage {
    private String name;
    private String version;
    private String nameWithVersion;
    private boolean disclosedNameOnly;

    private static final Pattern DEPENDENCY_AND_VERSION_REGEX = Pattern.compile(REGEX_QUOTES + "(.*)" + REGEX_QUOTES +
            ":" +
            REGEX_QUOTES + "(.*)" + REGEX_QUOTES);

    private static final String[] blacklistDepName = {"node_modules", "favicon.ico"};

    public NPMPackage(String dependencyWithNameAndVersion) {
        final Matcher nameAndVersionMatcher = DEPENDENCY_AND_VERSION_REGEX.matcher(dependencyWithNameAndVersion);

        if (nameAndVersionMatcher.find()
                && nameAndVersionMatcher.groupCount() == 2) {
            this.name = nameAndVersionMatcher.group(1);
            this.version = nameAndVersionMatcher.group(2);
            this.nameWithVersion = nameAndVersionMatcher.group();
        }
    }

    // Construct an NPMPackage when an internal package name was disclosed (without the version number).
    public NPMPackage(String dependencyName, boolean disclosedNameOnly) {
        this.name = dependencyName;
        this.disclosedNameOnly = disclosedNameOnly;
    }

    // Basic validation for npm package name
    public boolean isNameValid() {

        if (name == null) {
            return false;
        }

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

        // if version was not disclosed (only name as in e.g.: /node_modules/<pkg>), return true because further checks are not required.
        if (disclosedNameOnly) {
            return true;
        }

        if (version == null) {
            return false;
        }

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
        if (disclosedNameOnly) {
            return "/node_modules/" + name;
        } else {
            return nameWithVersion;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NPMPackage that = (NPMPackage) o;
        return name.equals(that.name) && Objects.equals(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, version);
    }

    @Override
    public String toString() {
        return name;
    }

}
