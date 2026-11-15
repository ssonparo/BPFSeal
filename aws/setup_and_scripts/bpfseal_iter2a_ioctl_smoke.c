/* BPFSeal 2A ioctl smoke test: run with sudo on kernel with experimental patch. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

struct bpfseal_ioctl_evidence {
    uint32_t version;
    uint32_t map_id;
    uint32_t max_entries;
    uint32_t valid;
    uint64_t map_cookie;
    uint64_t generation;
    uint8_t digest[32];
};
#define BPFSEAL_IOCTL_GET_EVIDENCE _IOR('Q', 0xe1, struct bpfseal_ioctl_evidence)

static int make_map(enum bpf_map_type type, unsigned entries) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = type;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = entries;
    return (int)syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

int main(void) {
    int fd, other, rc;
    struct bpfseal_ioctl_evidence a = {0}, b = {0};
    if (sizeof(a) != 64) {
        fprintf(stderr, "ABI SIZE ERROR sizeof(evidence)=%zu\n", sizeof(a));
        return 1;
    }
    fd = make_map(BPF_MAP_TYPE_PROG_ARRAY, 1);
    if (fd < 0) { perror("BPF_MAP_CREATE(PROG_ARRAY)"); return 1; }
    rc = ioctl(fd, BPFSEAL_IOCTL_GET_EVIDENCE, &a);
    if (rc) { perror("ioctl(PROG_ARRAY)"); close(fd); return 1; }
    printf("snapshot_1 version=%u map_id=%u max_entries=%u cookie=%" PRIu64
           " gen=%" PRIu64 " valid=%u\n", a.version, a.map_id,
           a.max_entries, a.map_cookie, a.generation, a.valid);
    rc = ioctl(fd, BPFSEAL_IOCTL_GET_EVIDENCE, &b);
    if (rc || memcmp(&a, &b, sizeof(a)) != 0) {
        fprintf(stderr, "FAIL: repeated snapshot mismatch\n"); close(fd); return 1;
    }
    puts("PASS repeated_snapshot");
    if (a.version != 1 || a.max_entries != 1 || a.generation != 0 || a.valid != 0) {
        fprintf(stderr, "FAIL initial_state (generation-zero digest not initialized in this prototype)\n");
        close(fd); return 1;
    }
    puts("PASS initial_generation_zero_invalid");
    errno = 0;
    rc = ioctl(fd, BPFSEAL_IOCTL_GET_EVIDENCE, NULL);
    if (rc != -1 || errno != EFAULT) {
        fprintf(stderr, "FAIL null_buffer rc=%d errno=%d\n", rc, errno);
        close(fd); return 1;
    }
    puts("PASS invalid_buffer");
    other = make_map(BPF_MAP_TYPE_ARRAY, 1);
    if (other < 0) { perror("BPF_MAP_CREATE(ARRAY)"); close(fd); return 1; }
    errno = 0;
    rc = ioctl(other, BPFSEAL_IOCTL_GET_EVIDENCE, &b);
    if (rc != -1 || errno != EOPNOTSUPP) {
        fprintf(stderr, "FAIL unsupported_map rc=%d errno=%d\n", rc, errno);
        close(other); close(fd); return 1;
    }
    puts("PASS unsupported_map");
    close(other);
    close(fd);
    puts("BPFSEAL_ITER2A_IOCTL_SMOKE: PASS");
    return 0;
}
