/* Run a benchmark phase and measure its entire process, including background
 * threads and shutdown. I/O is OS-attributed disk I/O, not SSD wear or NAND
 * writes. A missing kernel counter is reported as null, never as zero. */
#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libproc.h>
#endif

static int disk_writes(pid_t pid, uint64_t *bytes) {
#ifdef __APPLE__
    struct rusage_info_v2 usage = {0};
    if (proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t *)&usage) != 0) return 0;
    *bytes = usage.ri_diskio_byteswritten;
    return 1;
#elif defined(__linux__)
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%ld/io", (long)pid);
    FILE *in = fopen(path, "r");
    if (!in) return 0;
    int found = 0;
    while (fgets(line, sizeof(line), in)) {
        if (sscanf(line, "write_bytes: %" SCNu64, bytes) == 1) { found = 1; break; }
    }
    fclose(in);
    return found;
#else
    (void)pid; (void)bytes; return 0;
#endif
}

static uint64_t micros(struct timeval value) {
    return (uint64_t)value.tv_sec * 1000000 + value.tv_usec;
}

/* Both engine workers keep all artifacts in one private flat directory. Skip
 * a sample if a file disappears during enumeration. Never follow a symlink. */
static int sample_allocated(const char *path, uint64_t *peak) {
    DIR *dir = opendir(path);
    if (!dir) return 0;
    uint64_t bytes = 0;
    int ok = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) ok = 0; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat st;
        if (fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode)) {
            ok = 0; break;
        }
        bytes += (uint64_t)st.st_blocks * 512;
    }
    closedir(dir);
    if (ok && bytes > *peak) *peak = bytes;
    return ok;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fputs("usage: process-usage NEW_REPORT_FILE EXECUTABLE [ARGUMENT...]\n", stderr);
        return 2;
    }
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) { execvp(argv[2], argv + 2); perror("execvp"); _exit(127); }
    const char *db = getenv("INDEXER_KV_DB");
    uint64_t peak = 0, samples = 0;
    int rc;
    for (;;) {
        siginfo_t info = {0};
        if (db) samples += sample_allocated(db, &peak);
        rc = waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT | (db ? WNOHANG : 0));
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) { perror("waitid"); return 1; }
        if (info.si_pid == child) break;
        struct timespec pause = {0, 50000000};
        nanosleep(&pause, NULL);
    }
    uint64_t bytes = 0;
    int available = disk_writes(child, &bytes);
    struct rusage usage;
    int status;
    do { rc = wait4(child, &status, 0, &usage); } while (rc < 0 && errno == EINTR);
    if (rc < 0) { perror("wait4"); return 1; }
    if (!WIFEXITED(status)) return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1;
    if (WEXITSTATUS(status) != 0) return WEXITSTATUS(status);
    FILE *out = fopen(argv[1], "wx");
    if (!out) { perror("create new usage report"); return 1; }
    fprintf(out, "{\"user_cpu_us\":%" PRIu64 ",\"system_cpu_us\":%" PRIu64
            ",\"os_disk_write_bytes\":", micros(usage.ru_utime), micros(usage.ru_stime));
    if (available) fprintf(out, "%" PRIu64, bytes);
    else fputs("null", out);
    // Darwin reports bytes and Linux reports KiB for ru_maxrss.
#if defined(__APPLE__)
    fprintf(out, ",\"peak_process_rss_bytes\":%" PRIu64, (uint64_t)usage.ru_maxrss);
#elif defined(__linux__)
    fprintf(out, ",\"peak_process_rss_bytes\":%" PRIu64, (uint64_t)usage.ru_maxrss * 1024);
#endif
    fprintf(out, ",\"allocation_samples\":%" PRIu64 ",\"sampled_peak_allocated_bytes\":", samples);
    if (samples) fprintf(out, "%" PRIu64, peak);
    else fputs("null", out);
    fputs("}\n", out);
    if (fclose(out)) { perror("close usage report"); return 1; }
    return 0;
}
