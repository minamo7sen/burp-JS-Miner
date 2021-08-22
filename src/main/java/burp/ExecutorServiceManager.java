package burp;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ExecutorServiceManager {
    private static ExecutorServiceManager executorServiceManager = null;
    private final ExecutorService executorService = Executors.newFixedThreadPool(5);

    public static ExecutorServiceManager getInstance() {
        if (executorServiceManager == null)
            executorServiceManager = new ExecutorServiceManager();
        return executorServiceManager;
    }

    private ExecutorServiceManager() {
    }

    public ExecutorService getExecutorService() {
        return executorService;
    }


}


