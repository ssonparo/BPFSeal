#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

struct evidence { uint32_t version, map_id, max_entries, valid; uint64_t map_cookie, generation; uint8_t digest[32]; };
#define EVIDENCE_IOCTL _IOR('Q', 0xe1, struct evidence)
static int bpfcall(enum bpf_cmd cmd, union bpf_attr *a) { return (int)syscall(__NR_bpf, cmd, a, sizeof(*a)); }
static int load_xdp(int action) {
    struct bpf_insn insns[2] = {
        { .code=BPF_ALU64|BPF_MOV|BPF_K, .dst_reg=BPF_REG_0, .imm=action },
        { .code=BPF_JMP|BPF_EXIT }
    };
    static const char license[]="GPL";
    union bpf_attr a={0}; a.prog_type=BPF_PROG_TYPE_XDP; a.insn_cnt=2;
    a.insns=(uint64_t)(uintptr_t)insns; a.license=(uint64_t)(uintptr_t)license;
    return bpfcall(BPF_PROG_LOAD,&a);
}
static int setslot(int mapfd, int progfd) {
    uint32_t key=0, value=(uint32_t)progfd; union bpf_attr a={0};
    a.map_fd=mapfd; a.key=(uint64_t)(uintptr_t)&key;
    a.value=(uint64_t)(uintptr_t)&value; a.flags=BPF_ANY;
    return bpfcall(BPF_MAP_UPDATE_ELEM,&a);
}
static int proginfo(int fd, char name) {
    struct bpf_prog_info info={0}; union bpf_attr a={0};
    a.info.bpf_fd=fd; a.info.info_len=sizeof(info); a.info.info=(uint64_t)(uintptr_t)&info;
    if(bpfcall(BPF_OBJ_GET_INFO_BY_FD,&a)) return -1;
    printf("program=%c tag=",name);
    for(int i=0;i<8;i++) printf("%02x", info.tag[i]);
    printf(" load_time=%" PRIu64 " id=%u\n",(uint64_t)info.load_time,info.id);
    return 0;
}
static int snapshot(int mapfd, int step, char state, uint64_t *previous_gen,
                    uint32_t *previous_mid, uint64_t *previous_cookie) {
    struct evidence e={0};
    if(ioctl(mapfd,EVIDENCE_IOCTL,&e)) return -1;
    if(e.version!=1 || e.valid!=1 || e.max_entries!=1 ||
       e.generation!=*previous_gen+1 ||
       (*previous_mid && e.map_id!=*previous_mid) ||
       (*previous_cookie && e.map_cookie!=*previous_cookie)) { errno=EPROTO; return -1; }
    *previous_gen=e.generation; *previous_mid=e.map_id; *previous_cookie=e.map_cookie;
    printf("step=%d state=%c gen=%" PRIu64 " map=%u cookie=%" PRIu64 " digest=",
           step,state,e.generation,e.map_id,e.map_cookie);
    for(int k=0;k<32;k++) printf("%02x",e.digest[k]);
    putchar('\n');
    return 0;
}
int main(void) {
    int mapfd=-1, progfd[2]={-1,-1}, result=1;
    uint64_t gen=0,cookie=0; uint32_t mid=0;
    union bpf_attr a={0}; a.map_type=BPF_MAP_TYPE_PROG_ARRAY;
    a.key_size=4; a.value_size=4; a.max_entries=1;
    mapfd=bpfcall(BPF_MAP_CREATE,&a); if(mapfd<0){perror("map create");goto done;}
    progfd[0]=load_xdp(2); progfd[1]=load_xdp(3);
    if(progfd[0]<0||progfd[1]<0){perror("program load");goto done;}
    if(proginfo(progfd[0],'A')||proginfo(progfd[1],'B')){perror("program info");goto done;}
    /* Deliberate repeated states: no assumption that successive generations alternate. */
    const char pattern[]="AABBA BBA"; /* whitespace ignored */
    int step=0;
    for(int round=0;round<8;round++) {
        for(size_t i=0;i<sizeof(pattern)-1;i++) {
            char state=pattern[i]; if(state==' ')continue;
            int which=state=='A'?0:1;
            if(setslot(mapfd,progfd[which])){perror("map update");goto done;}
            if(snapshot(mapfd,++step,state,&gen,&mid,&cookie)){perror("snapshot");goto done;}
        }
    }
    printf("summary steps=%d final_generation=%" PRIu64 "\n",step,gen);
    puts("B1_HARNESS: PASS"); result=0;
done:
    for(int i=0;i<2;i++) if(progfd[i]>=0)close(progfd[i]);
    if(mapfd>=0)close(mapfd);
    return result;
}
