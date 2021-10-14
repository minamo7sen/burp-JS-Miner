package burp.config;

public class ExtensionConfig {

    private static ExtensionConfig extensionConfig = null;
    private boolean isVerboseLogging = true;
    private boolean isPassiveEnabled = true;

    public static ExtensionConfig getInstance() {
        if (extensionConfig == null)
            extensionConfig = new ExtensionConfig();
        return extensionConfig;
    }

    private ExtensionConfig() {

    }

    public void toggleLogging() {
        setVerboseLogging(!isVerboseLogging());
    }

    public void togglePassiveScans() {
        setPassiveEnabled(!isPassiveEnabled());
    }

    public String loggingConfigMenuItemText() {
        if (extensionConfig.isVerboseLogging()) {
            return "Disable verbose logging for tasks";
        } else {
            return "Enable verbose logging for tasks";
        }
    }

    public String passiveConfigMenuItemText() {
        if (extensionConfig.isPassiveEnabled()) {
            return "Disable Burp's passive scans";
        } else {
            return "Enable Burp's passive scans";
        }
    }

    public boolean isVerboseLogging() {
        return isVerboseLogging;
    }

    public void setVerboseLogging(boolean verboseLogging) {
        isVerboseLogging = verboseLogging;
    }

    public boolean isPassiveEnabled() {
        return isPassiveEnabled;
    }

    public void setPassiveEnabled(boolean passiveEnabled) {
        isPassiveEnabled = passiveEnabled;
    }

}
