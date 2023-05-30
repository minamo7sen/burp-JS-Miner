package burp;

import burp.config.ExecutorServiceManager;
import burp.config.ExtensionConfig;
import burp.core.TaskRepository;
import burp.core.ScannerBuilder;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static burp.utils.Constants.SETTING_BURP_PASSIVE;
import static burp.utils.Constants.SETTING_VERBOSE_LOGGING;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, IExtensionStateListener, IScannerCheck {
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static final ExecutorServiceManager executorServiceManager = ExecutorServiceManager.getInstance();
    private static final TaskRepository taskRepository = TaskRepository.getInstance();
    private static final ExtensionConfig extensionConfig = ExtensionConfig.getInstance();
    private static boolean loaded = true;
    public static PrintWriter mStdOut;
    public static PrintWriter mStdErr;
    public static final String EXTENSION_NAME = "JS Miner";
    private static final String EXTENSION_VERSION = "1.16";
    private int taskCount = 0; // counter for invoked tasks through the menu items context (Not for Burp's passive scan)

    // Exposing callbacks for use in other classes
    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    public static boolean isLoaded() {
        return loaded;
    }

    public static void setLoaded(boolean loaded) {
        BurpExtender.loaded = loaded;
    }

    public static ExecutorServiceManager getExecutorServiceManager() {
        return executorServiceManager;
    }

    public static TaskRepository getTaskRepository() {
        return taskRepository;
    }

    public static ExtensionConfig getExtensionConfig() {
        return extensionConfig;
    }



    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        // Extension initializations
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);

        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);

        // obtain our output and error streams
        mStdOut = new PrintWriter(callbacks.getStdout(), true);
        mStdErr = new PrintWriter(callbacks.getStderr(), true);

        mStdOut.println("[*] Loaded:\t" + EXTENSION_NAME + " v" + EXTENSION_VERSION);
        mStdOut.println("[*] Author:\tMina M. Edwar (minamo7sen@gmail.com)");
        mStdOut.println("=================================================");

        // Load extension configurations
        loadExtensionConfig();

    }

    private void updateExtensionConfig() {
        callbacks.saveExtensionSetting(SETTING_VERBOSE_LOGGING, String.valueOf(extensionConfig.isVerboseLogging()));
        callbacks.saveExtensionSetting(SETTING_BURP_PASSIVE, String.valueOf(extensionConfig.isPassiveEnabled()));
    }

    public void loadExtensionConfig() {
        if (callbacks.loadExtensionSetting(SETTING_VERBOSE_LOGGING) != null) {
            extensionConfig.setVerboseLogging(Boolean.parseBoolean(callbacks.loadExtensionSetting(SETTING_VERBOSE_LOGGING)));
        }

        if (callbacks.loadExtensionSetting(SETTING_BURP_PASSIVE) != null) {
            extensionConfig.setPassiveEnabled(Boolean.parseBoolean(callbacks.loadExtensionSetting(SETTING_BURP_PASSIVE)));
        }

    }


    @Override
    public void extensionUnloaded() {
        setLoaded(false);
        taskRepository.destroy();
        mStdOut.println("[*] Sending shutdown signal to terminate any running threads..");
        executorServiceManager.getExecutorService().shutdownNow();
        mStdOut.println("[*] Extension was unloaded.");
        mStdOut.println("=================================================");
    }

    /*
     *  Context menu items
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();
        JMenu scanItems = new JMenu("Scans");
        JMenu logItems = new JMenu("Log");
        JMenu configItems = new JMenu("Config");

        if (IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_PROXY_HISTORY == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE == invocation.getInvocationContext()
        ) {
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

            // === Main Scans Menu Items ==== //
            JMenuItem autoMineItem = new JMenuItem("Run JS Auto-Mine (check everything)");
            JSAutoMineItemAction autoMineItemActionAction = new JSAutoMineItemAction(selectedMessages);
            autoMineItem.addActionListener(autoMineItemActionAction);
            items.add(autoMineItem);

            JMenuItem findInterestingStuffItem = new JMenuItem("Run all passive scans ");
            AllPassiveScansItemAction findStuffAction = new AllPassiveScansItemAction(selectedMessages);
            findInterestingStuffItem.addActionListener(findStuffAction);
            items.add(findInterestingStuffItem);

            // === Specific Scans Menu Items ==== //
            JMenuItem jsSourceMapItem = new JMenuItem("JS source mapper (active)");
            ActiveSourceMapsItemAction jsMapAction = new ActiveSourceMapsItemAction(selectedMessages);
            jsSourceMapItem.addActionListener(jsMapAction);
            scanItems.add(jsSourceMapItem);

            JMenuItem secretsMenuItem = new JMenuItem("Secrets");
            SecretsItemAction secretsItemAction = new SecretsItemAction(selectedMessages);
            secretsMenuItem.addActionListener(secretsItemAction);
            scanItems.add(secretsMenuItem);

            JMenuItem dependencyConfusionMenuItem = new JMenuItem("Dependency Confusion");
            DependencyConfusionItemAction dependencyConfusionItemAction = new DependencyConfusionItemAction(selectedMessages);
            dependencyConfusionMenuItem.addActionListener(dependencyConfusionItemAction);
            scanItems.add(dependencyConfusionMenuItem);

            JMenuItem subDomainsMenuItem = new JMenuItem("SubDomains");
            SubDomainsItemAction subDomainsItemAction = new SubDomainsItemAction(selectedMessages);
            subDomainsMenuItem.addActionListener(subDomainsItemAction);
            scanItems.add(subDomainsMenuItem);

            JMenuItem cloudURLsMenuItem = new JMenuItem("Cloud URLs");
            CloudURLsItemAction cloudURLsItemAction = new CloudURLsItemAction(selectedMessages);
            cloudURLsMenuItem.addActionListener(cloudURLsItemAction);
            scanItems.add(cloudURLsMenuItem);

            JMenuItem inlineSourceMapsMenuItem = new JMenuItem("Inline B64 JS Source Maps");
            InlineSourceMapsItemAction inlineSourceMapsItemAction = new InlineSourceMapsItemAction(selectedMessages);
            inlineSourceMapsMenuItem.addActionListener(inlineSourceMapsItemAction);
            scanItems.add(inlineSourceMapsMenuItem);

            JMenuItem dumpStaticFilesMenuItem = new JMenuItem("Dump Static Files");
            DumpStaticFilesItemAction dumpStaticFilesItemAction = new DumpStaticFilesItemAction(selectedMessages);
            dumpStaticFilesMenuItem.addActionListener(dumpStaticFilesItemAction);
            scanItems.add(dumpStaticFilesMenuItem);

            JMenuItem endpointsFinderMenuItem = new JMenuItem("API Endpoints Finder");
            EndpointsFinderItemAction endpointsFinderItemAction = new EndpointsFinderItemAction(selectedMessages);
            endpointsFinderMenuItem.addActionListener(endpointsFinderItemAction);
            scanItems.add(endpointsFinderMenuItem);

            // === Logging Menu Items ==== //
            JMenuItem checkTasksMenuItem = new JMenuItem("Tasks Summary");
            CheckTasksMenuItemActions checkTasksMenuItemActions = new CheckTasksMenuItemActions();
            checkTasksMenuItem.addActionListener(checkTasksMenuItemActions);
            logItems.add(checkTasksMenuItem);

            JMenuItem runningMenuItem = new JMenuItem("Log Uncompleted Tasks");
            PrintUncompletedTasksMenuItemActions runningTasksMenuItemActions = new PrintUncompletedTasksMenuItemActions();
            runningMenuItem.addActionListener(runningTasksMenuItemActions);
            logItems.add(runningMenuItem);

            // === Configuration Menu Items ==== //
            JMenuItem toggleLoggingMenuItem = new JMenuItem(extensionConfig.loggingConfigMenuItemText());
            ToggleLoggingMenuItemActions toggleLoggingMenuItemActions = new ToggleLoggingMenuItemActions();
            toggleLoggingMenuItem.addActionListener(toggleLoggingMenuItemActions);
            configItems.add(toggleLoggingMenuItem);

            JMenuItem toggleBurpPassiveScanMenuItem = new JMenuItem(extensionConfig.passiveConfigMenuItemText());
            ToggleBurpPassiveMenuItemActions toggleBurpPassiveMenuItemActions = new ToggleBurpPassiveMenuItemActions();
            toggleBurpPassiveScanMenuItem.addActionListener(toggleBurpPassiveMenuItemActions);
            configItems.add(toggleBurpPassiveScanMenuItem);

            items.add(configItems);
            items.add(scanItems);
            items.add(logItems);
        }
        return items;
    }

    /*
     *  Action menu items
     */
    class SecretsItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        SecretsItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanSecrets()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class DependencyConfusionItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        DependencyConfusionItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanDependencyConfusion()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class SubDomainsItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        SubDomainsItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanSubDomains()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class CloudURLsItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        CloudURLsItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanCloudURLs()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class InlineSourceMapsItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        InlineSourceMapsItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files (of the same host) can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanInlineSourceMapFiles()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class ActiveSourceMapsItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        ActiveSourceMapsItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .activeSourceMapperScan()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class JSAutoMineItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        JSAutoMineItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .runAllScans()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class AllPassiveScansItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        AllPassiveScansItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .runAllPassiveScans()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class DumpStaticFilesItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        DumpStaticFilesItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .dumpStaticFiles()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class EndpointsFinderItemAction implements ActionListener {
        private final IHttpRequestResponse[] httpReqResArray;

        EndpointsFinderItemAction(IHttpRequestResponse[] httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .endpointsFinder()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class CheckTasksMenuItemActions implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            mStdOut.println("[=============== Tasks Summary =============]");
            mStdOut.println("Total Tasks: " + getTaskRepository().getSize());
            mStdOut.println("Queued tasks: " + taskRepository.getQueuedTasks().size());
            mStdOut.println("Completed tasks: " + taskRepository.getCompletedTasks().size());
            mStdOut.println("Running tasks: " + taskRepository.getRunningTasks().size());
            mStdOut.println("Failed tasks: " + taskRepository.getFailedTasks().size());
            mStdOut.println("============================================");
        }
    }

    class PrintUncompletedTasksMenuItemActions implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            mStdOut.println("[=============== Uncompleted Tasks =============]");

            int runningTasksSize = taskRepository.getRunningTasks().size();
            // If there was some timed out tasks, print them for troubleshooting or local checking
            if (runningTasksSize > 0) {
                mStdOut.println("Running tasks:" + taskRepository.printRunningTasks().toString());
                mStdOut.println("=============================================");
            }

            int failedTasksSize = taskRepository.getFailedTasks().size();
            // If there was some timed out tasks, print them for troubleshooting or local checking
            if (failedTasksSize > 0) {
                mStdOut.println("Failed tasks:" + taskRepository.printFailedTasks().toString());
                mStdOut.println("=============================================");
            }
        }
    }

    class ToggleLoggingMenuItemActions implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            extensionConfig.toggleLogging();
            updateExtensionConfig();
        }
    }

    class ToggleBurpPassiveMenuItemActions implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            extensionConfig.togglePassiveScans();
            updateExtensionConfig();
        }
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        if (extensionConfig.isPassiveEnabled()) {
            new Thread(() -> {
                // run passive scans against JS/JSON files
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(new IHttpRequestResponse[]{baseRequestResponse})
                        .runAllPassiveScans()
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }

}