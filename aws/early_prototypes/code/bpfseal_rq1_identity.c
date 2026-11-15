#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define I(C,D,S,O,K) ((struct bpf_insn){.code=(C),.dst_reg=(D),.src_reg=(S),.off=(O),.imm=(K)})
#define MOV(D,K) I(BPF_ALU64|BPF_MOV|BPF_K,D,0,0,K)
#define MOVREG(D,S) I(BPF_ALU64|BPF_MOV|BPF_X,D,S,0,0)
#define ADD(D,K) I(BPF_ALU64|BPF_ADD|BPF_K,D,0,0,K)
#define STW(D,O,K) I(BPF_ST|BPF_MEM|BPF_W,D,0,O,K)
#define CALL(K) I(BPF_JMP|BPF_CALL,0,0,0,K)
#define EXIT() I(BPF_JMP|BPF_EXIT,0,0,0,0)

static int bpf_call(enum bpf_cmd cmd, union bpf_attr *a) {
    return (int)syscall(__NR_bpf, cmd, a, sizeof(*a));
}
static int create_map(void) {
    union bpf_attr a = {0};
    a.map_type = BPF_MAP_TYPE_ARRAY;
    a.key_size = 4; a.value_size = 8; a.max_entries = 1;
    return bpf_call(BPF_MAP_CREATE, &a);
}
static int load_prog(int mapfd) {
    struct bpf_insn p[] = {
        STW(BPF_REG_10,-4,0),
        I(BPF_LD|BPF_DW|BPF_IMM,BPF_REG_1,BPF_PSEUDO_MAP_FD,0,mapfd),
        I(0,0,0,0,0),
        MOVREG(BPF_REG_2,BPF_REG_10),
        ADD(BPF_REG_2,-4),
        CALL(BPF_FUNC_map_lookup_elem),
        MOV(BPF_REG_0,0),
        EXIT(),
    };
    static char verifier_log[65536];
    union bpf_attr a = {0};
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    a.insn_cnt = sizeof(p)/sizeof(p[0]);
    a.insns = (uint64_t)(uintptr_t)p;
    a.license = (uint64_t)(uintptr_t)"GPL";
    a.log_buf = (uint64_t)(uintptr_t)verifier_log;
    a.log_size = sizeof(verifier_log);
    a.log_level = 1;
    int fd = bpf_call(BPF_PROG_LOAD,&a);
    if (fd<0) fprintf(stderr,"BPF_PROG_LOAD: %s\n%s\n",strerror(errno),verifier_log);
    return fd;
}
static int info(int fd, struct bpf_prog_info *i, uint32_t *mapid) {
    union bpf_attr a={0};
    memset(i,0,sizeof(*i));
    i->nr_map_ids=1;
    i->map_ids=(uint64_t)(uintptr_t)mapid;
    a.info.bpf_fd=fd;
    a.info.info_len=sizeof(*i);
    a.info.info=(uint64_t)(uintptr_t)i;
    return bpf_call(BPF_OBJ_GET_INFO_BY_FD,&a);
}
static void tag(const uint8_t *t,char *out) {
    for(int k=0;k<8;k++) sprintf(out+k*2,"%02x",t[k]);
    out[16]=0;
}
int main(void) {
    int m1=create_map(),m2=create_map();
    if(m1<0||m2<0){perror("BPF_MAP_CREATE (run with sudo)");return 1;}
    int p1=load_prog(m1),p2=load_prog(m1),p3=load_prog(m2);
    if(p1<0||p2<0||p3<0) return 1;
    struct bpf_prog_info a,b,c;
    uint32_t x=0,y=0,z=0;
    if(info(p1,&a,&x)<0||info(p2,&b,&y)<0||info(p3,&c,&z)<0){perror("BPF_OBJ_GET_INFO_BY_FD");return 1;}
    char t1[17],t2[17],t3[17];
    tag(a.tag,t1); tag(b.tag,t2);tag(c.tag,t3);
    puts("case,prog_id,prog_tag,map_id,jited_bytes");
    printf("same_map_load_1,%u,%s,%u,%u\n",a.id,t1,x,a.jited_prog_len);
    printf("same_map_load_2,%u,%s,%u,%u\n",b.id,t2,y,b.jited_prog_len);
    printf("different_map,%u,%s,%u,%u\n",c.id,t3,z,c.jited_prog_len);
    printf("separate_loads_same_tag=%s\n",(a.id!=b.id && !strcmp(t1,t2))?"PASS":"FAIL");
    printf("different_maps_same_tag=%s\n",(x!=z && !strcmp(t1,t3))?"PASS":"FAIL");
    close(p1);close(p2);close(p3);close(m1);close(m2);
    return 0;
}
