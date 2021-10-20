package burp.core.scanners;

import burp.*;
import burp.utils.SourceMapper;
import burp.utils.Utilities;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import com.google.re2j.Matcher;

import static burp.utils.Constants.b64SourceMapRegex;

public class InlineSourceMapFiles implements Runnable{
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    private static final IExtensionHelpers helpers = callbacks.getHelpers();
    private final IHttpRequestResponse baseRequestResponse;
    private final Path outputDirectory;
    private final UUID taskUUID;

    public InlineSourceMapFiles(IHttpRequestResponse baseRequestResponse, UUID taskUUID, long timeStamp) {
        this.baseRequestResponse = baseRequestResponse;
        this.outputDirectory = Paths.get(System.getProperty("user.home"))
                .resolve(".BurpSuite")
                .resolve("JS-Miner")
                .resolve(helpers.analyzeRequest(baseRequestResponse).getUrl().getHost() + "-" + timeStamp);
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);

        String responseString = new String(baseRequestResponse.getResponse());
        String responseBodyString = responseString.substring(helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset());

        Matcher b64SourceMapperMatcher = b64SourceMapRegex.matcher(responseBodyString);

        while (b64SourceMapperMatcher.find()) {
            new SourceMapper(
                    baseRequestResponse,
                    Utilities.b64Decode(b64SourceMapperMatcher.group(3)), // Base64 Decoded map File Data
                    outputDirectory
            );
        }
        BurpExtender.getTaskRepository().completeTask(taskUUID);
    }
}
