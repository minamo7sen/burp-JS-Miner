package burp.core;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;

public class Task {
    private final int id;
    private final UUID uuid;
    private final TaskName name;
    private final String url;
    private final byte[] hash;
    private TaskStatus status;

    public Task(int id, UUID uuid, TaskName name, String url, byte[] hash) {
        this.id = id;
        this.uuid = uuid;
        this.name = name;
        this.url = normalizeURL(url);
        this.hash = hash;
        this.status = TaskStatus.QUEUED;
    }

    public UUID getUuid() {
        return uuid;
    }

    public TaskName getName() {
        return name;
    }

    public TaskStatus getStatus() {
        return status;
    }

    public void setStatus(TaskStatus status) {
        this.status = status;
    }

    public int getId() {
        return id;
    }

    public String getUrl() {
        return url;
    }

    public byte[] getHash() {
        return hash;
    }

    public static String normalizeURL(String url) {
        try {
            URI uri = new URI(url);
            uri = uri.normalize();
            if (uri.getPort() == -1) {
                return uri.getScheme() + "://" +
                        uri.getHost() +
                        uri.getPath();
            } else {
                return uri.getScheme() + "://" +
                        uri.getHost() + ":" +
                        uri.getPort() +
                        uri.getPath();
            }
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
       return null;
    }

    @Override
    public String toString() {
        return "Task{" +
                "id=" + id +
                ", name=" + name +
                ", url='" + url + '\'' +
                ", status=" + status +
                '}';
    }
}

enum TaskStatus {
    QUEUED,
    RUNNING,
    COMPLETED,
    FAILED,
    SKIPPED
}

enum TaskName {
    SOURCE_MAPPER_ACTIVE_SCAN,
    INLINE_JS_SOURCE_MAPPER,
    SECRETS_SCAN,
    CLOUD_URLS_SCAN,
    DEPENDENCY_CONFUSION_SCAN,
    DEPENDENCY_CONFUSION_SCAN_2,
    SUBDOMAINS_SCAN,
    STATIC_FILES_DUMPER,
    ENDPOINTS_FINDER,
}