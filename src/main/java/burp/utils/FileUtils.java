package burp.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static burp.BurpExtender.mStdErr;

/*
 * Class responsible to securely store files
 */

public class FileUtils {

    // Function 2 - After parsing map files, save resulting data to mapped destinations
    public static boolean saveFile(String sourceFilePath, byte[] data, Path outputDirPath) {

        Path filePath = Paths.get(sourceFilePath);
        String fileName = filePath.getFileName().toString();
        Utilities.createDirectoriesIfNotExist(getTempDirPath(outputDirPath));
        try {
            Path tempFile = Files.createTempFile(getTempDirPath(outputDirPath), fileName, ".js");
            Files.write(tempFile, data);
            String trustedFileName = secureFile(sourceFilePath, outputDirPath);
            Path trustedPath = Paths.get(trustedFileName);
            // check & rename to "e.g.: existingFile_n.js" if duplicate
            trustedPath = Utilities.handleDuplicateFile(trustedPath);
            Files.move(tempFile, trustedPath);
            if (!Utilities.isDirEmpty(outputDirPath)) {
                return true;
            }
        } catch (IOException e) {
            mStdErr.println("[-] Error saving the file - saveFile IOException.");
        }
        return false;
    }


    // Function 3 - Security check for File name to prevent potential path traversal attacks
    private static String secureFile(String fileName, Path outputDirPath) {
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
        return getTempDirPath(outputDirPath).toString();
    }

    private static Path getTempDirPath(Path outputDirPath) {
        return outputDirPath.resolve("tmp");
    }
}
