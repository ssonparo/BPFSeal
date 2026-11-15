// BPFSeal RQ1: multi-hop dependency mutation changes effective execution
// without changing root or intermediary program identity. No interface attachment.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define INS(C,D,S,O,I) ((struct bpf_insn){.code=(C),.dst_reg=(D),.src_reg=(S),.off=(O),.imm=(I)})
#define MOV(D,I) INS(BPF_ALU64|BPF_MOV|BPF_K,D,0,0,I)
#define EXIT() INS(BPF_JMP|BPF_EXIT,0,0,0,0)
#define CALL(F) INS(BPF_JMP|BPF_CALL,0,0,0,F)

static int load_prog(const char *name, const struct bpf_insn *ins, size_t n) {
    char log[65536] = {0};
    struct bpf_prog_load_opts opts = {.sz = sizeof(opts), .log_buf = log,
                                      .log_size = sizeof(log), .log_level = 1};
    int fd = bpf_prog_load(BPF_PROG_TYPE_XDP, name, "GPL", ins, n, &opts);
    if (fd < 0) fprintf(stderr, "load %s: %s\n%s\n", name, strerror(errno), log);
    return fd;
}
static int load_return(const char *name, int result) {
    struct bpf_insn ins[] = {MOV(BPF_REG_0,result),EXIT()};
    return load_prog(name,ins,sizeof(ins)/sizeof(ins[0]));
}
static int load_tail(const char *name, int mapfd, int fallback) {
    struct bpf_insn ins[] = {
        INS(BPF_LD|BPF_DW|BPF_IMM,BPF_REG_2,BPF_PSEUDO_MAP_FD,0,mapfd),
        INS(0,0,0,0,0), MOV(BPF_REG_3,0), CALL(BPF_FUNC_tail_call),
        MOV(BPF_REG_0,fallback),EXIT()
    };
    return load_prog(name,ins,sizeof(ins)/sizeof(ins[0]));
}
static int identity(int fd, __u32 *id, char tag[17]) {
    struct bpf_prog_info inf = {0}; __u32 len=sizeof(inf);
    if(bpf_obj_get_info_by_fd(fd,&inf,&len)) return -1;
    *id=inf.id;
    for(int i=0;i<8;i++) sprintf(tag+2*i,"%02x",inf.tag[i]);
    tag[16]=0; return 0;
}
static int run(int fd, __u32 *ret) {
    unsigned char pkt[64]={0},out[128]={0};
    struct bpf_test_run_opts opts={.sz=sizeof(opts),.data_in=pkt,.data_size_in=sizeof(pkt),
        .data_out=out,.data_size_out=sizeof(out),.repeat=1};
    if(bpf_prog_test_run_opts(fd,&opts)) return -1;
    *ret=opts.retval; return 0;
}
static int phase(const char *name,int root,__u32 expected,__u32 rid,const char *rtag,
                 __u32 mid,const char *mtag) {
    __u32 got=0, r2=0,m2=0;char rt2[17],mt2[17];
    // mid FD is checked separately by caller because not visible in root metadata
    if(run(root,&got)){fprintf(stderr,"test_run %s: %s\n",name,strerror(errno));return -1;}
    if(identity(root,&r2,rt2) || r2!=rid || strcmp(rt2,rtag)){
        fprintf(stderr,"root identity changed at %s\n",name);return -1;
    }
    (void)m2;(void)mt2;(void)mid;(void)mtag;
    printf("%s,%u,%s,%u\n",name,rid,rtag,got);
    if(got!=expected){fprintf(stderr,"%s expected %u got %u\n",name,expected,got);return -1;}
    return 0;
}
int main(void){
    int mapA=-1,mapB=-1,root=-1,middle=-1,pass=-1,tx=-1,status=1;
    __u32 k=0,rid,mid,rid2,mid2;char rt[17],mt[17],rt2[17],mt2[17];
    struct bpf_map_create_opts mo={.sz=sizeof(mo)};
    mapA=bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY,"bpfseal_edge_a",4,4,1,&mo);
    mapB=bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY,"bpfseal_edge_b",4,4,1,&mo);
    if(mapA<0 || mapB<0){perror("create maps");goto done;}
    root=load_tail("bpfseal_root",mapA,XDP_DROP);
    middle=load_tail("bpfseal_middle",mapB,XDP_ABORTED);
    pass=load_return("bpfseal_pass",XDP_PASS);
    tx=load_return("bpfseal_tx",XDP_TX);
    if(root<0 || middle<0 || pass<0 || tx<0)goto done;
    if(identity(root,&rid,rt) || identity(middle,&mid,mt)){perror("identity");goto done;}
    printf("phase,root_id,root_tag,returned_action\n");
    if(phase("no_edges",root,XDP_DROP,rid,rt,mid,mt))goto done;
    if(bpf_map_update_elem(mapA,&k,&middle,BPF_ANY)){perror("link root->middle");goto done;}
    if(phase("middle_no_leaf",root,XDP_ABORTED,rid,rt,mid,mt))goto done;
    if(bpf_map_update_elem(mapB,&k,&pass,BPF_ANY)){perror("middle->pass");goto done;}
    if(phase("leaf_pass",root,XDP_PASS,rid,rt,mid,mt))goto done;
    if(bpf_map_update_elem(mapB,&k,&tx,BPF_ANY)){perror("middle->tx");goto done;}
    if(phase("leaf_tx",root,XDP_TX,rid,rt,mid,mt))goto done;
    if(bpf_map_delete_elem(mapB,&k)){perror("remove leaf");goto done;}
    if(phase("leaf_deleted",root,XDP_ABORTED,rid,rt,mid,mt))goto done;
    if(identity(root,&rid2,rt2) || identity(middle,&mid2,mt2)){
        perror("identity final");goto done;
    }
    if(rid!=rid2 || mid!=mid2 || strcmp(rt,rt2) || strcmp(mt,mt2)){
        fprintf(stderr,"root or middle identity changed\n");goto done;
    }
    printf("middle_id=%u middle_tag=%s\n",mid,mt);
    printf("root_and_middle_identity_unchanged=PASS\n");
    printf("multihop_execution_changed_with_leaf_update=PASS\n");
    printf("multihop_execution_restored_after_delete=PASS\n");
    status=0;
done:
    if(tx>=0)close(tx);
    if(pass>=0)close(pass);
    if(middle>=0)close(middle);
    if(root>=0)close(root);
    if(mapB>=0)close(mapB);
    if(mapA>=0)close(mapA);
    return status;
}
