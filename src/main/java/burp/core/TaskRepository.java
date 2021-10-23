package burp.core;

import burp.BurpExtender;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static burp.BurpExtender.mStdOut;
import static burp.utils.Constants.LOG_FORMAT;
import static burp.utils.Constants.LOG_TASK_ID_PREFIX;

public class TaskRepository {
    private static TaskRepository taskRepository = null;
    private final List<Task> tasks = new ArrayList<>();
    private static final String LINE_SEPARATOR_PROPERTY = "line.separator";

    public static TaskRepository getInstance() {
        if (taskRepository == null)
            taskRepository = new TaskRepository();
        return taskRepository;
    }

    private TaskRepository() {
    }

    public void addTask(Task task) {
        getTasks().add(task);
        logTask(task);
    }

    public boolean notDuplicate(TaskName taskName, String url, byte[] hash) {
        String normalizedURL = Task.normalizeURL(url);
        for (Task task : getTasks()) {
            if (Arrays.equals(task.getHash(), hash)
                    && task.getUrl().equals(normalizedURL)
                    && task.getName().equals(taskName)) {
                // If task failed -> Re-Scan / Not duplicate.
                return task.getStatus().equals(TaskStatus.FAILED);
            }
        }
        return true;
    }

    public Task findTaskByUUID(UUID taskUUID) {
        for (Task task : getTasks()) {
            if (task.getUuid().equals(taskUUID)) {
                return task;
            }
        }
        return null;
    }

    public List<Task> getQueuedTasks() {
        List<Task> tasksList = new ArrayList<>();
        for (Task task : getTasks()) {
            if (task.getStatus().equals(TaskStatus.QUEUED)) {
                tasksList.add(task);
            }
        }
        return tasksList;
    }

    public List<Task> getCompletedTasks() {
        List<Task> tasksList = new ArrayList<>();
        for (Task task : getTasks()) {
            if (task.getStatus().equals(TaskStatus.COMPLETED)) {
                tasksList.add(task);
            }
        }
        return tasksList;
    }

    public List<Task> getRunningTasks() {
        List<Task> tasksList = new ArrayList<>();
        for (Task task : getTasks()) {
            if (task.getStatus().equals(TaskStatus.RUNNING)) {
                tasksList.add(task);
            }
        }
        return tasksList;
    }

    public List<Task> getFailedTasks() {
        List<Task> tasksList = new ArrayList<>();
        for (Task task : getTasks()) {
            if (task.getStatus().equals(TaskStatus.FAILED)) {
                tasksList.add(task);
            }
        }
        return tasksList;
    }

    public StringBuilder printRunningTasks() {
        StringBuilder tasksSB = new StringBuilder();
        for (Task task : getTasks()) {
            if (task.getStatus().equals(TaskStatus.RUNNING)) {
                tasksSB.append(System.getProperty(LINE_SEPARATOR_PROPERTY));
                tasksSB.append(task);
            }
        }
        return tasksSB;
    }

    public StringBuilder printFailedTasks() {
        StringBuilder tasksSB = new StringBuilder();
        for (Task task : getTasks()) {
            if (task.getStatus().equals(TaskStatus.FAILED)) {
                tasksSB.append(System.getProperty(LINE_SEPARATOR_PROPERTY));
                tasksSB.append(task);
            }
        }
        return tasksSB;
    }

    public void startTask(UUID taskId) {
        Task task = findTaskByUUID(taskId);
        task.setStatus(TaskStatus.RUNNING);
        logTask(task);
    }

    public void completeTask(UUID taskId) {
        Task task = findTaskByUUID(taskId);
        task.setStatus(TaskStatus.COMPLETED);
        logTask(task);
    }

    public void failTask(UUID taskId) {
        Task task = findTaskByUUID(taskId);
        task.setStatus(TaskStatus.FAILED);
        logTask(task);
    }

    public void destroy(){
        tasks.clear();
    }

    public int getSize() {
        return getTasks().size();
    }

    private synchronized List<Task> getTasks() {
        return tasks;
    }

    private static void logTask(Task task) {
        if (task.getId() != -1 && BurpExtender.getExtensionConfig().isVerboseLogging()) {
            mStdOut.printf(LOG_FORMAT, "[" + task.getStatus() + "]", LOG_TASK_ID_PREFIX + task.getId(), task.getName(), task.getUrl());
        }
    }

}
