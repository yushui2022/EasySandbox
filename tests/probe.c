#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/landlock.h>
#include <sys/syscall.h>
#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_landlock_create_ruleset 444
#endif
#endif
#endif

extern char **environ;

static int write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    size_t len = strlen(text);
    ssize_t n = write(fd, text, len);
    int saved = errno;
    close(fd);
    errno = saved;
    return n == (ssize_t)len ? 0 : -1;
}

static int delayed_write(const char *path, unsigned seconds) {
    sleep(seconds);
    return write_file(path, "late\n");
}

static int check_devices(void) {
    const char *paths[] = {"/dev/null", "/dev/zero", "/dev/urandom"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        int fd = open(paths[i], O_RDONLY);
        if (fd < 0) return 1;
        unsigned char byte = 0;
        ssize_t n = read(fd, &byte, 1);
        if ((i == 0 && n != 0) || (i != 0 && n != 1)) {
            close(fd);
            return 1;
        }
        close(fd);
    }
    return 0;
}

static int check_caps_and_nnp(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 1;
    char line[512];
    int cap_ok = 0;
    int nnp_ok = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            char *p = line + 7;
            while (*p == ' ' || *p == '\t') ++p;
            cap_ok = 1;
            for (; *p && *p != '\n'; ++p) {
                if (*p != '0' && *p != ' ' && *p != '\t') cap_ok = 0;
            }
        } else if (strncmp(line, "NoNewPrivs:", 11) == 0) {
            char *p = line + 11;
            while (*p == ' ' || *p == '\t') ++p;
            nnp_ok = (*p == '1');
        }
    }
    fclose(f);
    return cap_ok && nnp_ok ? 0 : 1;
}

static int check_clean_environment(void) {
    const char *allowed[] = {"PATH", "HOME", "USER", "LANG"};
    for (char **entry = environ; entry && *entry; ++entry) {
        const char *equals = strchr(*entry, '=');
        size_t len = equals ? (size_t)(equals - *entry) : strlen(*entry);
        int allowed_name = 0;
        for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i) {
            if (strlen(allowed[i]) == len && strncmp(*entry, allowed[i], len) == 0) {
                allowed_name = 1;
                break;
            }
        }
        if (!allowed_name) return 1;
    }
    return getenv("EASY_SANDBOX_SECRET") ? 1 : 0;
}

static int check_no_network(void) {
    FILE *routes = fopen("/proc/net/route", "r");
    if (routes) {
        char line[512];
        int first = 1;
        while (fgets(line, sizeof(line), routes)) {
            if (!first && line[0] != '\0' && line[0] != '\n') {
                fclose(routes);
                return 1;
            }
            first = 0;
        }
        fclose(routes);
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0; /* A network-disabled namespace may reject socket(). */
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 200000};
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "192.0.2.1", &addr.sin_addr);
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int saved = errno;
    close(fd);
    return rc < 0 && (saved == ENETUNREACH || saved == EHOSTUNREACH || saved == ETIMEDOUT) ? 0 : 1;
}

static int check_closed_fds(void) {
    errno = 0;
    int fd3 = fcntl(3, F_GETFD);
    int e3 = errno;
    errno = 0;
    int fd4 = fcntl(4, F_GETFD);
    int e4 = errno;
    return fd3 < 0 && e3 == EBADF && fd4 < 0 && e4 == EBADF ? 0 : 1;
}

static int check_landlock_abi(void) {
#if defined(__linux__) && defined(__NR_landlock_create_ruleset)
    errno = 0;
    long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        printf("abi=0 errno=%d\n", errno);
        return 2;
    }
    printf("abi=%ld\n", abi);
    return abi >= 3 ? 0 : 2;
#else
    return 2;
#endif
}

static int check_allowed_write(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 1;
    ssize_t n = write(fd, "allowed\n", 8);
    int saved = errno;
    close(fd);
    errno = saved;
    return n == 8 ? 0 : 1;
}

/* A denied write may come from Landlock (EACCES) or from a read-only mount
   (EROFS); both prove that the policy did not grant the path. */
static int check_denied_write(const char *path) {
    errno = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        close(fd);
        unlink(path);
        return 1;
    }
    return (errno == EACCES || errno == EROFS) ? 0 : 1;
}

static int check_allowed_read(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 1;
    unsigned char byte = 0;
    ssize_t n = read(fd, &byte, 1);
    close(fd);
    return n >= 0 ? 0 : 1;
}

static int check_denied_read(const char *path) {
    errno = 0;
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return errno == EACCES ? 0 : 1;
}

/* uname(2) is not part of the P1 baseline deny list, so a policy that lists it
   is the only thing that can make this fail. */
static int check_syscall_denied(void) {
    struct utsname buffer;
    errno = 0;
    long rc = syscall(SYS_uname, &buffer);
    return (rc == -1 && errno == EPERM) ? 0 : 1;
}

static int check_syscall_allowed(void) {
    struct utsname buffer;
    errno = 0;
    return syscall(SYS_uname, &buffer) == 0 ? 0 : 1;
}

/* ---- P3 proxy helpers ------------------------------------------------- */

/* Connect to the CONNECT proxy the launcher mounted inside the sandbox. */
static int unix_connect_proxy(void) {
    const char *path = getenv("EASY_SANDBOX_PROXY");
    struct sockaddr_un addr;
    int fd;

    if (!path || !*path) return -1;
    if (strlen(path) >= sizeof addr.sun_path) return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* glibc marks write(2) with warn_unused_result, so an explicit `(void)` cast
   still warns.  Where the bytes are best-effort, funnel them through here. */
static void write_best_effort(int fd, const char *text, size_t length) {
    ssize_t written = write(fd, text, length);
    (void)written;
}

/* Send one request head and print whatever comes back, including tunnelled
   bytes.  The test parses the status line out of stdout.

   Without a payload the connection is closed by the proxy as soon as it has
   answered, so a short receive timeout is enough to collect the whole status
   line.  With a payload the tunnel stays open and the probe reads until the
   upstream closes, which is what the timeout tests rely on. */
static int proxy_request(const char *request, const char *payload) {
    char buffer[4096];
    size_t length = strlen(request);
    ssize_t got;
    int fd = unix_connect_proxy();

    if (fd < 0) return 1;
    if (!payload) {
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 300000;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    }
    if (write(fd, request, length) != (ssize_t)length) {
        close(fd);
        return 1;
    }
    if (payload) {
        write_best_effort(fd, payload, strlen(payload));
        write_best_effort(fd, "\n", 1);
    }
    for (;;) {
        got = read(fd, buffer, sizeof buffer - 1);
        if (got <= 0) break;
        buffer[got] = 0;
        fputs(buffer, stdout);
    }
    close(fd);
    return 0;
}

/* A tiny multi-connection upstream for the network tests: bind a loopback
   port, answer every connection, and never block the next accept.  With
   `silent` it accepts and stalls, which is how the timeout case is built. */
static int run_upstream_server(const char *port_text, int silent) {
    struct sockaddr_in addr;
    int one = 1;
    int listener = socket(AF_INET, SOCK_STREAM, 0);

    if (listener < 0) return 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)atoi(port_text));
    if (bind(listener, (const struct sockaddr *)&addr, sizeof addr) != 0) return 1;
    if (listen(listener, 8) != 0) return 1;
    printf("upstream-listening\n");
    fflush(stdout);
    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) continue;
        if (fork() == 0) {
            if (!silent) write_best_effort(client, "hello-from-upstream\n", 20);
            sleep(silent ? 30 : 1);
            close(client);
            _exit(0);
        }
        close(client);
    }
}

static int usage(void) {
    fprintf(stderr, "probe modes: workspace-write rootfs-write host-absent tmp-write dev-check identity caps-env proc net fd stdin stdout background-write sleep-fork sleep exit landlock-abi socketpair-allowed proc-write-allowed secure-syscalls secure-proc-write-denied detached-sleep detached-exit allowed-write denied-write allowed-read denied-read syscall-denied syscall-allowed proxy-env proxy-connect proxy-raw unix-socketpair inet-socket\n");
    return 2;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    const char *mode = argv[1];

    if (strcmp(mode, "workspace-write") == 0) {
        return write_file("/workspace/probe-workspace-write.txt", "workspace\n") == 0 ? 0 : 1;
    }
    if (strcmp(mode, "rootfs-write") == 0) {
        int fd = open("/bin/probe-rootfs-write", O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) {
            close(fd);
            return 1;
        }
        return errno == EROFS ? 0 : 1;
    }
    if (strcmp(mode, "host-absent") == 0 && argc >= 3) {
        return access(argv[2], F_OK) < 0 && errno == ENOENT ? 0 : 1;
    }
    if (strcmp(mode, "tmp-write") == 0) {
        return write_file("/tmp/probe-tmp.txt", "tmp\n") == 0 ? 0 : 1;
    }
    if (strcmp(mode, "dev-check") == 0) return check_devices();
    if (strcmp(mode, "identity") == 0) return (getuid() == 0 && getgid() == 0) ? 0 : 1;
    if (strcmp(mode, "caps-env") == 0) return check_caps_and_nnp() || check_clean_environment();
    if (strcmp(mode, "proc") == 0) {
        FILE *f = fopen("/proc/1/status", "r");
        if (!f) return 1;
        fclose(f);
        if (argc >= 3) {
            char host_path[128];
            snprintf(host_path, sizeof(host_path), "/proc/%s/status", argv[2]);
            if (access(host_path, F_OK) == 0) return 1;
        }
        return 0;
    }
    if (strcmp(mode, "net") == 0) return check_no_network();
    if (strcmp(mode, "fd") == 0) return check_closed_fds();
    if (strcmp(mode, "landlock-abi") == 0) return check_landlock_abi();
    if (strcmp(mode, "socketpair-allowed") == 0) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 1;
        close(pair[0]);
        close(pair[1]);
        return 0;
    }
    if (strcmp(mode, "proc-write-allowed") == 0) {
        return write_file("/proc/self/comm", "probe\n") == 0 ? 0 : 1;
    }
    if (strcmp(mode, "secure-syscalls") == 0) {
        int pair[2];
        errno = 0;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != -1 || errno != EPERM) return 1;
        errno = 0;
        if (socket(AF_INET, SOCK_STREAM, 0) != -1 || errno != EPERM) return 1;
        errno = 0;
        if (syscall(SYS_clone3, NULL, 0) != -1 || errno != ENOSYS) return 1;
        return 0;
    }
    if (strcmp(mode, "secure-proc-write-denied") == 0) {
        errno = 0;
        return write_file("/proc/self/comm", "probe\n") == -1 && errno == EACCES ? 0 : 1;
    }
    if ((strcmp(mode, "detached-sleep") == 0 || strcmp(mode, "detached-exit") == 0) && argc >= 4) {
        if (setsid() < 0 || prctl(PR_SET_PDEATHSIG, 0) != 0) return 1;
        if (write_file("/workspace/escape-ready", "ready\n") != 0) return 1;
        pid_t child = fork();
        if (child < 0) return 1;
        if (child == 0) _exit(delayed_write(argv[2], (unsigned)strtoul(argv[3], NULL, 10)) == 0 ? 0 : 1);
        if (strcmp(mode, "detached-sleep") == 0) sleep(15);
        return 0;
    }
    if (strcmp(mode, "stdin") == 0) {
        unsigned char byte = 0;
        ssize_t n = read(STDIN_FILENO, &byte, 1);
        return n == 0 ? 0 : 1;
    }
    if (strcmp(mode, "stdout") == 0) {
        return write(STDOUT_FILENO, "probe-output\n", 13) == 13 ? 0 : 1;
    }
    if (strcmp(mode, "background-write") == 0 && argc >= 4) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (child == 0) _exit(delayed_write(argv[2], (unsigned)strtoul(argv[3], NULL, 10)) == 0 ? 0 : 1);
        return 0;
    }
    if (strcmp(mode, "sleep-fork") == 0 && argc >= 4) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (child == 0) _exit(delayed_write(argv[2], (unsigned)strtoul(argv[3], NULL, 10)) == 0 ? 0 : 1);
        sleep((unsigned)strtoul(argv[3], NULL, 10) + 10);
        return 0;
    }
    if (strcmp(mode, "allowed-write") == 0 && argc >= 3) return check_allowed_write(argv[2]);
    if (strcmp(mode, "denied-write") == 0 && argc >= 3) return check_denied_write(argv[2]);
    if (strcmp(mode, "allowed-read") == 0 && argc >= 3) return check_allowed_read(argv[2]);
    if (strcmp(mode, "denied-read") == 0 && argc >= 3) return check_denied_read(argv[2]);
    if (strcmp(mode, "syscall-denied") == 0) return check_syscall_denied();
    if (strcmp(mode, "syscall-allowed") == 0) return check_syscall_allowed();
    if (strcmp(mode, "server") == 0 && argc >= 3) {
        return run_upstream_server(argv[2], argc >= 4 && strcmp(argv[3], "silent") == 0);
    }
    if (strcmp(mode, "proxy-env") == 0) {
        const char *path = getenv("EASY_SANDBOX_PROXY");
        printf("proxy_env=%s\n", path ? path : "(unset)");
        return (path && *path) ? 0 : 1;
    }
    if (strcmp(mode, "proxy-connect") == 0 && argc >= 3) {
        char request[512];
        snprintf(request, sizeof request,
                 "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", argv[2], argv[2]);
        return proxy_request(request, argc >= 4 ? argv[3] : NULL);
    }
    if (strcmp(mode, "proxy-raw") == 0 && argc >= 3) {
        char request[512];
        snprintf(request, sizeof request, "%s\r\nHost: raw\r\n\r\n", argv[2]);
        return proxy_request(request, NULL);
    }
    if (strcmp(mode, "unix-socketpair") == 0) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 1;
        close(pair[0]);
        close(pair[1]);
        return 0;
    }
    if (strcmp(mode, "inet-socket") == 0) {
        /* Must be refused: only AF_UNIX sockets survive the proxy policy. */
        errno = 0;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            close(fd);
            return 1;
        }
        return errno == EPERM ? 0 : 1;
    }
    if (strcmp(mode, "sleep") == 0 && argc >= 3) {
        sleep((unsigned)strtoul(argv[2], NULL, 10));
        return 0;
    }
    if (strcmp(mode, "exit") == 0 && argc >= 3) return (int)strtol(argv[2], NULL, 10);
    return usage();
}
