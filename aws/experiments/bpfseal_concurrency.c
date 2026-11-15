// BPFSeal Iteration 1B: bounded concurrent PROG_ARRAY mutation test.
// This is a userspace test, NOT an attestation implementation.
#define _GNU_SOURCE
#include <linux/bpf.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

#define MAX_THREADS 16
#define MAX_OPS_PER_THREAD 100
static int mapfd, targets[2], nthreads, operations;
static atomic_int successes, failures;
static pthread_barrier_t start_barrier;
static int bpf_call(enum bpf_cmd cmd, union bpf_attr *attr) {
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}
static int load_xdp(int action) {
    struct bpf_insn insns[2] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = action},
        {.code = BPF_JMP | BPF_EXIT},
    };
    static const char license[] = "GPL";
    static char verifier_log[65536];
    union bpf_attr a = {0};
    a.prog_type = BPF_PROG_TYPE_XDP;
    a.insn_cnt = 2;
    a.insns = (uint64_t)(uintptr_t)insns;
    a.license = (uint64_t)(uintptr_t)license;
    a.log_buf = (uint64_t)(uintptr_t)verifier_log;
    a.log_size = sizeof(verifier_log);
    a.log_level = 1;
    int fd = bpf_call(BPF_PROG_LOAD, &a);
    if (fd < 0) fprintf(stderr, "BPF_PROG_LOAD action=%d: %s\n%s\n", action, strerror(errno), verifier_log);
    return fd;
}
static int update_target(int fd) {
    uint32_t key = 0, value = (uint32_t)fd;
    union bpf_attr a = {0};
    a.map_fd = mapfd;
    a.key = (uint64_t)(uintptr_t)&key;
    a.value = (uint64_t)(uintptr_t)&value;
    a.flags = BPF_ANY;
    return bpf_call(BPF_MAP_UPDATE_ELEM, &a);
}
static int delete_target(void) {
    uint32_t key = 0;
    union bpf_attr a = {0};
    a.map_fd = mapfd;
    a.key = (uint64_t)(uintptr_t)&key;
    return bpf_call(BPF_MAP_DELETE_ELEM, &a);
}
static void *worker(void *arg) {
    intptr_t id = (intptr_t)arg;
    pthread_barrier_wait(&start_barrier);
    for (int i = 0; i < operations; ++i) {
        if (update_target(targets[(id + i) % 2]) == 0)
            atomic_fetch_add(&successes, 1);
        else {
            atomic_fetch_add(&failures, 1);
            fprintf(stderr, "thread=%ld iteration=%d update failed: %s\n", (long)id, i, strerror(errno));
        }
    }
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "Usage: %s THREADS(1-16) OPS_PER_THREAD(1-32)\n", argv[0]); return 2; }
    nthreads = atoi(argv[1]); operations = atoi(argv[2]);
    if (nthreads < 1 || nthreads > MAX_THREADS || operations < 1 || operations > MAX_OPS_PER_THREAD) {
        fprintf(stderr, "Out-of-range arguments\n"); return 2;
    }
    union bpf_attr a = {0};
    a.map_type = BPF_MAP_TYPE_PROG_ARRAY;
    a.key_size = sizeof(uint32_t);
    a.value_size = sizeof(uint32_t);
    a.max_entries = 1;
    mapfd = bpf_call(BPF_MAP_CREATE, &a);
    if (mapfd < 0) { perror("BPF_MAP_CREATE"); return 1; }
    targets[0] = load_xdp(2);
    targets[1] = load_xdp(3);
    if (targets[0] < 0 || targets[1] < 0) return 1;
    pthread_t threads[MAX_THREADS];
    if (pthread_barrier_init(&start_barrier, NULL, (unsigned)nthreads + 1)) return 1;
    for (int i = 0; i < nthreads; ++i)
        if (pthread_create(&threads[i], NULL, worker, (void *)(intptr_t)i)) { perror("pthread_create"); return 1; }
    pthread_barrier_wait(&start_barrier);
    for (int i = 0; i < nthreads; ++i) pthread_join(threads[i], NULL);
    int ok = atomic_load(&successes), bad = atomic_load(&failures);
    printf("threads=%d ops_per_thread=%d successful_updates=%d failed_updates=%d\n", nthreads, operations, ok, bad);
    // A pre-delete empty slot must yield ENOENT without advancing generation.
    // The next delete removes an existing slot; another delete should fail.
    if (delete_target() != 0) { perror("delete occupied slot"); bad++; }
    errno = 0;
    int empty_del = delete_target(), empty_errno = errno;
    printf("empty_delete_result=%d errno=%d expected_errno=%d\n", empty_del, empty_errno, ENOENT);
    if (empty_del != -1 || empty_errno != ENOENT) bad++;
    close(targets[0]); close(targets[1]); close(mapfd);
    pthread_barrier_destroy(&start_barrier);
    return bad ? 1 : 0;
}
