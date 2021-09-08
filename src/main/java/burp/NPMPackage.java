package burp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.InterestingStuffFinder.REGEX_QUOTES;

public class DependencyValidator {
    private String name;
    private String version;
    private String nameWithVersion;

    private static final Pattern DEPENDENCY_AND_VERSION_REGEX = Pattern.compile(REGEX_QUOTES + "(.*)" + REGEX_QUOTES +
            ":" +
            REGEX_QUOTES + "(.*)" + REGEX_QUOTES);

    // Source: https://github.com/sindresorhus/semver-regex/blob/main/index.js
    private static final Pattern NPM_SEMANTIC_VERSION_REGEX = Pattern.compile(("(?<=^v?|\\sv?)(?:(?:0|[1-9]\\d*)\\.){2}(?:0|[1-9]\\d*)(?:-(?:0|[1-9]\\d*|[\\da-z-]*[a-z-][\\da-z-]*)(?:\\.(?:0|[1-9]\\d*|[\\da-z-]*[a-z-][\\da-z-]*))*)?(?:\\+[\\da-z-]+(?:\\.[\\da-z-]+)*)?\\b"),
            Pattern.CASE_INSENSITIVE);

    private static final String[] blacklistDepName = {"node_modules", "favicon.ico"};

    DependencyValidator(String dependencyWithNameAndVersion) {
        final Matcher nameAndVersionMatcher = DEPENDENCY_AND_VERSION_REGEX.matcher(dependencyWithNameAndVersion);

        if (nameAndVersionMatcher.find()
                && nameAndVersionMatcher.groupCount() == 2) {
            this.name = nameAndVersionMatcher.group(1);
            this.version = nameAndVersionMatcher.group(2);
            this.nameWithVersion = nameAndVersionMatcher.group();
        }
    }

    // Basic validations for npm package name
    private boolean isNameValid() {
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

    private boolean isVersionValid() {
        Matcher matcher = NPM_SEMANTIC_VERSION_REGEX.matcher(version);
        return matcher.find();
    }

    public boolean isValid() {
        return isNameValid() && isVersionValid();

    }

    public String getOrgNameFromScopedDependency() {
        return name.replaceAll("^@", "").replaceAll("/.*", "");
    }


    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public String getNameWithVersion() {
        return nameWithVersion;
    }

    private static boolean isVersionNotURLorPath(String dependencyWithVersion) {
        // TODO: https://docs.npmjs.com/cli/v7/configuring-npm/package-json#dependencies

        return true;
    }


}
