// BPFSeal RQ1: PROG_ARRAY mutation changes execution while caller tag remains fixed.
// Uses XDP BPF_PROG_TEST_RUN only; no network attachment and no kernel changes.
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

static int load_prog(const char *name, const struct bpf_insn *ins, size_t cnt) {
    struct bpf_prog_load_opts opts = { .sz = sizeof(opts) };
    int fd = bpf_prog_load(BPF_PROG_TYPE_XDP, name, "GPL", ins, cnt, &opts);
    if (fd < 0) fprintf(stderr, "load %s failed: %s\n", name, strerror(errno));
    return fd;
}
static int load_return(const char *name, int retval) {
    struct bpf_insn ins[] = { MOV(BPF_REG_0,retval), EXIT() };
    return load_prog(name, ins, sizeof(ins)/sizeof(ins[0]));
}
static int load_caller(int mapfd) {
    struct bpf_insn ins[] = {
        // r1=ctx, r2=map_fd, r3=index 0, call bpf_tail_call(ctx,map,0)
        INS(BPF_LD|BPF_DW|BPF_IMM, BPF_REG_2, BPF_PSEUDO_MAP_FD,0,mapfd),
        INS(0,0,0,0,0),
        MOV(BPF_REG_3,0),
        CALL(BPF_FUNC_tail_call),
        MOV(BPF_REG_0,XDP_DROP), // executes if slot is empty or tail call fails
        EXIT()
    };
    return load_prog("bpfseal_caller",ins,sizeof(ins)/sizeof(ins[0]));
}
static int get_prog_identity(int fd, __u32 *id, char taghex[17]) {
    struct bpf_prog_info info={0}; __u32 len=sizeof(info);
    if (bpf_obj_get_info_by_fd(fd,&info,&len)) return -1;
    *id=info.id;
    for (int i=0;i<8;i++) sprintf(taghex+2*i,"%02x",info.tag[i]);
    taghex[16]='\0'; return 0;
}
static int test_run(int fd, __u32 *retval) {
    unsigned char packet[64]={0};
    unsigned char output[128]={0};
    struct bpf_test_run_opts opts={
        .sz=sizeof(opts), .data_in=packet, .data_size_in=sizeof(packet),
        .data_out=output, .data_size_out=sizeof(output), .repeat=1
    };
    if (bpf_prog_test_run_opts(fd,&opts)) return -1;
    *retval=opts.retval; return 0;
}
int main(void) {
    int mapfd=-1, caller=-1, pass=-1, tx=-1, status=1;
    __u32 key=0,id=0,initial_id=0,retval=0;
    char tag[17],initial_tag[17];
    struct bpf_map_create_opts map_opts={.sz=sizeof(map_opts)};
    mapfd=bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY,"bpfseal_targets",sizeof(key),sizeof(__u32),1,&map_opts);
    if(mapfd<0){perror("bpf_map_create");goto done;}
    caller=load_caller(mapfd); if(caller<0)goto done;
    pass=load_return("bpfseal_pass",XDP_PASS); if(pass<0)goto done;
    tx=load_return("bpfseal_tx",XDP_TX); if(tx<0)goto done;
    if(get_prog_identity(caller,&initial_id,initial_tag)){perror("caller info");goto done;}
    printf("phase,caller_id,caller_tag,slot_target,returned_action\n");
    if(test_run(caller,&retval)){perror("run empty");goto done;}
    printf("empty,%u,%s,none,%u\n",initial_id,initial_tag,retval);
    if(retval!=XDP_DROP){fprintf(stderr,"empty slot did not fall back\n");goto done;}
    if(bpf_map_update_elem(mapfd,&key,&pass,BPF_ANY)){perror("set pass");goto done;}
    if(test_run(caller,&retval)){perror("run pass");goto done;}
    printf("target_pass,%u,%s,XDP_PASS,%u\n",initial_id,initial_tag,retval);
    if(retval!=XDP_PASS){fprintf(stderr,"expected XDP_PASS\n");goto done;}
    if(bpf_map_update_elem(mapfd,&key,&tx,BPF_ANY)){perror("set tx");goto done;}
    if(test_run(caller,&retval)){perror("run tx");goto done;}
    printf("target_tx,%u,%s,XDP_TX,%u\n",initial_id,initial_tag,retval);
    if(retval!=XDP_TX){fprintf(stderr,"expected XDP_TX\n");goto done;}
    if(bpf_map_delete_elem(mapfd,&key)){perror("delete slot");goto done;}
    if(test_run(caller,&retval)){perror("run deleted");goto done;}
    printf("deleted,%u,%s,none,%u\n",initial_id,initial_tag,retval);
    if(retval!=XDP_DROP){fprintf(stderr,"expected XDP_DROP\n");goto done;}
    if(get_prog_identity(caller,&id,tag)){perror("caller info after");goto done;}
    if(id!=initial_id || strcmp(tag,initial_tag)){
        fprintf(stderr,"caller identity changed unexpectedly\n");goto done;
    }
    printf("caller_identity_unchanged=PASS\nexecution_changed_with_map_update=PASS\nexecution_restored_after_delete=PASS\n");
    status=0;
done:
    if(tx>=0)close(tx); if(pass>=0)close(pass); if(caller>=0)close(caller); if(mapfd>=0)close(mapfd);
    return status;
}
