package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, IExtensionStateListener, IScannerCheck {
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static final ExecutorServiceManager executorServiceManager = ExecutorServiceManager.getInstance();
    private static boolean loaded = true;
    static PrintWriter mStdOut;
    static PrintWriter mStdErr;
    public static final String EXTENSION_NAME = "JS Miner";
    private static final String EXTENSION_VERSION = "1.11";

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

    }

    @Override
    public void extensionUnloaded() {
        setLoaded(false);
        mStdOut.println("[*] Sending shutdown signal to terminate any running threads..");
        executorServiceManager.getExecutorService().shutdownNow();
        mStdOut.println("[*] Extension was unloaded.");
        mStdOut.println("=================================================");
    }

    /*
     * Context menu items
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();

        if (IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_PROXY_HISTORY == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST == invocation.getInvocationContext() ||
                IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE == invocation.getInvocationContext()
        ) {
            IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

            JMenuItem autoMineItem = new JMenuItem("JS Auto-Mine (check everything)");
            menuItemActions autoAction = new menuItemActions(selectedMessages, true, true);
            autoMineItem.addActionListener(autoAction);
            items.add(autoMineItem);

            JMenuItem jsSourceMapItem = new JMenuItem("Only guess JS source maps (active)");
            menuItemActions jsMapAction = new menuItemActions(selectedMessages, true, false);
            jsSourceMapItem.addActionListener(jsMapAction);
            items.add(jsSourceMapItem);

            JMenuItem findInterestingStuffItem = new JMenuItem("Only find interesting stuff (passive)");
            menuItemActions findStuffAction = new menuItemActions(selectedMessages, false, true);
            findInterestingStuffItem.addActionListener(findStuffAction);
            items.add(findInterestingStuffItem);

        }
        return items;
    }

    /**
     * Class to handle menu items actions
     */
    class menuItemActions implements ActionListener {

        private final IHttpRequestResponse[] httpReqResArray;
        private final boolean scanSourceMapFiles;
        private final boolean checkInterestingStuff;

        menuItemActions(IHttpRequestResponse[] httpReqResArr, boolean scanSourceMapFiles, boolean checkInterestingStuff) {
            this.httpReqResArray = httpReqResArr;
            this.scanSourceMapFiles = scanSourceMapFiles;
            this.checkInterestingStuff = checkInterestingStuff;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> handleTargets(httpReqResArray, scanSourceMapFiles, checkInterestingStuff)).start();
        }
    }

    static void handleTargets(IHttpRequestResponse[] siteMapReqResArray, boolean sourceMapScan, boolean findInterestingStuffScan) {
        HashSet<String> uniqueTargets = new HashSet<>();
        for (IHttpRequestResponse httpReqRes : siteMapReqResArray) {
            String host = helpers.analyzeRequest(httpReqRes).getUrl().getHost();
            // If host is in the list, add to our unique targets & scan it
            if (!uniqueTargets.contains(host)) {
                uniqueTargets.add(host);
                new JSMinerScan(httpReqRes, sourceMapScan, findInterestingStuffScan);
            }
        }

        uniqueTargets.clear();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        new Thread(() -> new JSMinerScan(baseRequestResponse, false, true)).start();
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