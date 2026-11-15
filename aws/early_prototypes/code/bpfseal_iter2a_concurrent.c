/* BPFSeal Iteration 2A: concurrent writer/reader evidence stress, research VM only. */
#define _GNU_SOURCE
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/ioctl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#define MAX_WRITERS 16
#define READERS 4
#define MAX_SAMPLES 3000
struct evidence { uint32_t version,map_id,max_entries,valid; uint64_t map_cookie,generation; uint8_t digest[32]; };
#define EVIDENCE_IOCTL _IOR('Q',0xe1,struct evidence)
static int mapfd=-1, progfd[2]={-1,-1}, writers, ops;
static atomic_int writes_ok, writes_bad, reads_bad, writers_done, go;
static pthread_mutex_t output_lock=PTHREAD_MUTEX_INITIALIZER;
static int bpfcall(enum bpf_cmd cmd,union bpf_attr *attr) {return (int)syscall(__NR_bpf,cmd,attr,sizeof(*attr));}
static int load_xdp(int action){
    struct bpf_insn insns[2]={{.code=BPF_ALU64|BPF_MOV|BPF_K,.dst_reg=BPF_REG_0,.imm=action},{.code=BPF_JMP|BPF_EXIT}};
    static const char license[]="GPL";union bpf_attr a={0};
    a.prog_type=BPF_PROG_TYPE_XDP;a.insn_cnt=2;a.insns=(uint64_t)(uintptr_t)insns;a.license=(uint64_t)(uintptr_t)license;
    return bpfcall(BPF_PROG_LOAD,&a);
}
static int setslot(int prog){uint32_t k=0,v=(uint32_t)prog;union bpf_attr a={0};a.map_fd=mapfd;a.key=(uint64_t)(uintptr_t)&k;a.value=(uint64_t)(uintptr_t)&v;a.flags=BPF_ANY;return bpfcall(BPF_MAP_UPDATE_ELEM,&a);}
static int delslot(void){uint32_t k=0;union bpf_attr a={0};a.map_fd=mapfd;a.key=(uint64_t)(uintptr_t)&k;return bpfcall(BPF_MAP_DELETE_ELEM,&a);}
static int mapinfo(void){struct bpf_map_info i={0};union bpf_attr a={0};a.info.bpf_fd=mapfd;a.info.info_len=sizeof(i);a.info.info=(uint64_t)(uintptr_t)&i;if(bpfcall(BPF_OBJ_GET_INFO_BY_FD,&a))return -1;printf("map_id=%u max_entries=%u\n",i.id,i.max_entries);return 0;}
static int proginfo(int which){struct bpf_prog_info i={0};union bpf_attr a={0};a.info.bpf_fd=progfd[which];a.info.info_len=sizeof(i);a.info.info=(uint64_t)(uintptr_t)&i;if(bpfcall(BPF_OBJ_GET_INFO_BY_FD,&a))return -1;printf("program=%c tag=",which?'B':'A');for(int j=0;j<8;j++)printf("%02x",i.tag[j]);printf(" load_time=%" PRIu64 " id=%u\n",(uint64_t)i.load_time,i.id);return 0;}
static void startwait(void){while(!atomic_load(&go))sched_yield();}
static void *writer(void *arg){intptr_t id=(intptr_t)arg;startwait();for(int i=0;i<ops;i++){if(setslot(progfd[(id+i)&1]))atomic_fetch_add(&writes_bad,1);else atomic_fetch_add(&writes_ok,1);}atomic_fetch_add(&writers_done,1);return NULL;}
static void *reader(void *arg){intptr_t id=(intptr_t)arg;uint64_t last=0;int samples=0;startwait();while(samples<MAX_SAMPLES){struct evidence e={0};if(ioctl(mapfd,EVIDENCE_IOCTL,&e)){atomic_fetch_add(&reads_bad,1);break;}if(e.version!=1||e.valid!=1||e.max_entries!=1||e.generation<1||e.generation<last){atomic_fetch_add(&reads_bad,1);break;}last=e.generation;
        pthread_mutex_lock(&output_lock);printf("snapshot reader=%ld gen=%" PRIu64 " map=%u cookie=%" PRIu64 " digest=",(long)id,e.generation,e.map_id,e.map_cookie);for(int k=0;k<32;k++)printf("%02x",e.digest[k]);putchar('\n');pthread_mutex_unlock(&output_lock);samples++;
        if(atomic_load(&writers_done)==writers && samples>=100)break;
        if(samples%8==0)sched_yield();
    }return NULL;
}
int main(int argc,char**argv){if(argc!=3){fprintf(stderr,"Usage: %s WRITERS(4|8|16) OPS_PER_WRITER(1..100)\n",argv[0]);return 2;}writers=atoi(argv[1]);ops=atoi(argv[2]);if((writers!=4&&writers!=8&&writers!=16)||ops<1||ops>100){fputs("Invalid arguments\n",stderr);return 2;}
    int exitcode=1;union bpf_attr a={0};a.map_type=BPF_MAP_TYPE_PROG_ARRAY;a.key_size=4;a.value_size=4;a.max_entries=1;mapfd=bpfcall(BPF_MAP_CREATE,&a);if(mapfd<0){perror("map create");goto done;}
    progfd[0]=load_xdp(2);progfd[1]=load_xdp(3);if(progfd[0]<0||progfd[1]<0){perror("prog load");goto done;}
    if(mapinfo()||proginfo(0)||proginfo(1)){perror("object info");goto done;}
    if(setslot(progfd[0])){perror("initial update");goto done;}
    pthread_t wt[MAX_WRITERS],rt[READERS];int wc=0,rc=0;
    for(int i=0;i<READERS;i++){int err=pthread_create(&rt[i],NULL,reader,(void*)(intptr_t)i);if(err){fprintf(stderr,"reader pthread_create: %s\n",strerror(err));goto launch_fail;}rc++;}
    for(int i=0;i<writers;i++){int err=pthread_create(&wt[i],NULL,writer,(void*)(intptr_t)i);if(err){fprintf(stderr,"writer pthread_create: %s\n",strerror(err));goto launch_fail;}wc++;}
    atomic_store(&go,1);
    for(int i=0;i<wc;i++)pthread_join(wt[i],NULL);
    for(int i=0;i<rc;i++)pthread_join(rt[i],NULL);
    {struct evidence e={0};if(ioctl(mapfd,EVIDENCE_IOCTL,&e)){perror("final ioctl");goto done;}
      printf("final gen=%" PRIu64 " cookie=%" PRIu64 " digest=",e.generation,e.map_cookie);for(int k=0;k<32;k++)printf("%02x",e.digest[k]);putchar('\n');
      printf("summary writers=%d ops=%d successful_updates=%d failed_updates=%d failed_reads=%d expected_generation=%d\n",writers,ops,atomic_load(&writes_ok),atomic_load(&writes_bad),atomic_load(&reads_bad),1+writers*ops);
      if(atomic_load(&writes_ok)!=writers*ops||atomic_load(&writes_bad)||atomic_load(&reads_bad)||e.generation!=(uint64_t)(1+writers*ops)){fputs("CONCURRENT_TEST: FAIL\n",stderr);goto done;}
    }
    if(delslot()){perror("final delete");goto done;}
    errno=0;int dr=delslot(),de=errno;if(dr!=-1||de!=ENOENT){fprintf(stderr,"empty delete unexpected rc=%d errno=%d\n",dr,de);goto done;}
    puts("CONCURRENT_TEST: PASS");exitcode=0;goto done;
launch_fail:
    atomic_store(&go,1);
    /* If startup failed, release launched threads; incomplete tests fail. */
    for(int i=0;i<wc;i++)pthread_join(wt[i],NULL);
    for(int i=0;i<rc;i++)pthread_join(rt[i],NULL);
done:
    for(int i=0;i<2;i++)if(progfd[i]>=0)close(progfd[i]);
    if(mapfd>=0)close(mapfd);
    return exitcode;
}
