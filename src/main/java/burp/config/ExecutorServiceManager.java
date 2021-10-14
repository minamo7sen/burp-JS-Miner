package burp.config;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class ExecutorServiceManager {
    private static ExecutorServiceManager executorServiceManager = null;
    private final ThreadPoolExecutor executorService = (ThreadPoolExecutor) Executors.newFixedThreadPool(5);

    public static ExecutorServiceManager getInstance() {
        if (executorServiceManager == null)
            executorServiceManager = new ExecutorServiceManager();
        return executorServiceManager;
    }

    private ExecutorServiceManager() {
    }

    public ThreadPoolExecutor getExecutorService() {
        return executorService;
    }


}


