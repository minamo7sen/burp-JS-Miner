package burp.utils;

/*
 * JS Source Maps - mainly used for ObjectMapper
 */

public class JSMapFile {
    private String[] sources;
    private String[] sourcesContent;

    public String[] getSources() {
        return sources;
    }

    public void setSources(String[] sources) {
        this.sources = sources;
    }

    public String[] getSourcesContent() {
        return sourcesContent;
    }

    public void setSourcesContent(String[] sourcesContent) {
        this.sourcesContent = sourcesContent;
    }
}