// BPFSeal Iteration 1C: map-state restoration and idempotent update test.
// Run only on an isolated research VM; requires privileges for bpf(2).
#define _GNU_SOURCE
#include <linux/bpf.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

static int call_bpf(enum bpf_cmd cmd, union bpf_attr *a) {
    return (int)syscall(__NR_bpf, cmd, a, sizeof(*a));
}
static int load_xdp(int action) {
    struct bpf_insn insns[2] = {
        {.code=BPF_ALU64|BPF_MOV|BPF_K,.dst_reg=BPF_REG_0,.imm=action},
        {.code=BPF_JMP|BPF_EXIT},
    };
    static const char license[]="GPL";
    union bpf_attr a={0};
    a.prog_type=BPF_PROG_TYPE_XDP;
    a.insn_cnt=2;
    a.insns=(uint64_t)(uintptr_t)insns;
    a.license=(uint64_t)(uintptr_t)license;
    return call_bpf(BPF_PROG_LOAD,&a);
}
static int set_slot(int mapfd,int progfd) {
    uint32_t k=0,v=(uint32_t)progfd;
    union bpf_attr a={0};
    a.map_fd=mapfd;
    a.key=(uint64_t)(uintptr_t)&k;
    a.value=(uint64_t)(uintptr_t)&v;
    a.flags=BPF_ANY;
    return call_bpf(BPF_MAP_UPDATE_ELEM,&a);
}
static int del_slot(int mapfd) {
    uint32_t k=0;
    union bpf_attr a={0};
    a.map_fd=mapfd;
    a.key=(uint64_t)(uintptr_t)&k;
    return call_bpf(BPF_MAP_DELETE_ELEM,&a);
}
static int print_prog_info(const char *name, int fd) {
    struct bpf_prog_info info = {0};
    union bpf_attr attr = {0};
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uint64_t)(uintptr_t)&info;
    if (call_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0) {
        perror("BPF_OBJ_GET_INFO_BY_FD program");
        return -1;
    }
    printf("program=%s tag=", name);
    for (unsigned int i = 0; i < sizeof(info.tag); i++)
        printf("%02x", info.tag[i]);
    printf(" load_time=%" PRIu64 " id=%u\n", (uint64_t)info.load_time, info.id);
    return 0;
}
static int print_map_info(int fd) {
    struct bpf_map_info info = {0};
    union bpf_attr attr = {0};
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uint64_t)(uintptr_t)&info;
    if (call_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0) {
        perror("BPF_OBJ_GET_INFO_BY_FD map");
        return -1;
    }
    printf("map_id=%u max_entries=%u\n", info.id, info.max_entries);
    return 0;
}
int main(void) {
    int rc=1, m=-1, a=-1, b=-1;
    union bpf_attr attr={0};
    attr.map_type=BPF_MAP_TYPE_PROG_ARRAY;
    attr.key_size=sizeof(uint32_t);
    attr.value_size=sizeof(uint32_t);
    attr.max_entries=1;
    m=call_bpf(BPF_MAP_CREATE,&attr);
    if (m<0) { perror("BPF_MAP_CREATE"); goto end; }
    a=load_xdp(XDP_PASS); b=load_xdp(XDP_TX);
    if (a<0 || b<0) { perror("BPF_PROG_LOAD"); goto end; }
    if (print_map_info(m) || print_prog_info("A",a) || print_prog_info("B",b)) goto end;
    if (set_slot(m,a)) { perror("set A"); goto end; }
    puts("phase=A_first expected_gen=1");
    if (set_slot(m,a)) { perror("set A again"); goto end; }
    puts("phase=A_again expected_gen=2");
    if (set_slot(m,b)) { perror("set B"); goto end; }
    puts("phase=B expected_gen=3");
    if (set_slot(m,a)) { perror("restore A"); goto end; }
    puts("phase=A_restored expected_gen=4");
    if (del_slot(m)) { perror("delete A"); goto end; }
    puts("phase=empty expected_gen=5");
    errno=0;
    int ret=del_slot(m), err=errno;
    printf("empty_delete_result=%d errno=%d expected_errno=%d\n",ret,err,ENOENT);
    if (ret!=-1 || err!=ENOENT) goto end;
    rc=0;
end:
    if(b>=0)close(b);
    if(a>=0)close(a);
    if(m>=0)close(m);
    printf("test_status=%s\n",rc?"FAIL":"PASS");
    return rc;
}
