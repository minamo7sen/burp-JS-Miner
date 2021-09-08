package burp;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static burp.BurpExtender.mStdErr;

/**
 * Class to construct the front-end source code from the passed JS map files
 */

public class SourceMapper {

    private static final IExtensionHelpers helpers = BurpExtender.getHelpers();

    private final IHttpRequestResponse httpRequestResponse;
    private final String jsonMapFile; // json string that potentially contains JS map file
    private final Path outputDirPath; // where we are going to store the source files

    /**
     * @param httpRequestResponse The HTTP request/response that should be included in Burp's scan alert
     * @param jsonMapFile         A json string that potentially contains JS map files
     * @param outputDirPath       The output directory where we store the constructed source code
     */
    SourceMapper(IHttpRequestResponse httpRequestResponse, String jsonMapFile, Path outputDirPath) {
        this.httpRequestResponse = httpRequestResponse;
        this.jsonMapFile = jsonMapFile;
        this.outputDirPath = outputDirPath;
        parseMapFile();
    }

    // Function 1 - parse Map Files
    public void parseMapFile() {
        ObjectMapper objectMapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try {
            JSMapFile mapFile = objectMapper.readValue(jsonMapFile, JSMapFile.class);
            for (int i = 0; i <= mapFile.getSources().length - 1; i++) {
                saveFile(
                        mapFile.getSources()[i]
                                .replaceAll("\\?.*", "") // remove app.vue?d123 .. make it app.vue
                                .replaceAll("[?%*|:\"<>~]", ""),
                        helpers.stringToBytes(mapFile.getSourcesContent()[i])
                );
            }
        } catch (Exception e) {
            mStdErr.println("[-] Error processing the file - parseMapFile Exception.");
        }
    }

    // Function 2 - After parsing map files, save resulting data to mapped destinations
    private void saveFile(String sourceFilePath, byte[] data) {
        Path filePath = Paths.get(sourceFilePath);
        String fileName = filePath.getFileName().toString();
        Utilities.createDirectoriesIfNotExist(getTempDirPath());
        try {
            Path tempFile = Files.createTempFile(getTempDirPath(), fileName, ".js");
            Files.write(tempFile, data);
            String trustedFileName = secureFile(sourceFilePath);
            Path trustedPath = Paths.get(trustedFileName);
            // check & rename to "e.g.: existingFile_n.js" if duplicate
            trustedPath = Utilities.handleDuplicateFile(trustedPath);
            Files.move(tempFile, trustedPath);
            if (!Utilities.isDirEmpty(outputDirPath)) {
                sendJSMapperIssue();
            }
        } catch (IOException e) {
            mStdErr.println("[-] Error saving the file - saveFile IOException.");
        }
    }


    // Function 3 - Security check for File name to prevent potential path traversal attacks
    private String secureFile(String fileName) {
        File destinationDir = new File(outputDirPath.toString());

        String fakeRootPath;
        if (System.getenv("SystemDrive") != null) {
            fakeRootPath = System.getenv("SystemDrive");
        } else {
            fakeRootPath = FileSystems.getDefault().getSeparator();
        }
        File untrustedFile = new File(fakeRootPath + fileName); // Fake root path

        File trustedFile;
        try {
            trustedFile = new File(destinationDir.getCanonicalPath() +
                    untrustedFile.toPath().normalize().toString().replace(fakeRootPath, FileSystems.getDefault().getSeparator())); // Replace fakeRootPath with system separator

            if (trustedFile.getCanonicalPath().startsWith(destinationDir.getCanonicalPath())) {
                Utilities.createDirectoriesIfNotExist(trustedFile.getParentFile().toPath());
                return trustedFile.toString();
            } else {
                mStdErr.println("[-] Unexpected OS file write was prevented.");
            }
        } catch (IOException ioException) {
            mStdErr.println("[-] secureFile failed - IOException.");
        }
        // If structuring the file path failed, keep the file in the temp directory instead of not saving it
        return getTempDirPath().toString();
    }

    private void sendJSMapperIssue() {
        IScanIssue scanIssue = null;
        try {
            scanIssue = new CustomScanIssue(
                    httpRequestResponse.getHttpService(),
                    helpers.analyzeRequest(httpRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{httpRequestResponse},
                    "[JS Miner] JavaScript Source Mapper",
                    "This issue was generated by \"" + BurpExtender.EXTENSION_NAME + "\" Burp extension.<br><br>" +
                            "It was possible to retrieve JavaScript source map files of the target host." +
                            "The retrieved (front-end) source code is available (for manual review) in the following location:<br><br>"
                            + "<b>" + outputDirPath + "</b>",
                    null,
                    "Information",
                    "Certain");
        } catch (Exception e) {
            mStdErr.println("[-] createDirectoriesIfNotExist Exception.");
        }
        Utilities.reportIssueIfNotDuplicate(scanIssue, httpRequestResponse);
    }

    public Path getTempDirPath() {
        return outputDirPath.resolve("tmp");
    }
}
