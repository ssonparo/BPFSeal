#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define MAX_WRITERS 16
static int mapfd=-1, progfd[2]={-1,-1}, writers, ops;
static uint64_t *samples;
static atomic_int go, ready, failed;
static uint64_t begin_ns, end_ns;
static pthread_t threads[MAX_WRITERS];
static uint64_t nanos(void) { struct timespec ts; if(clock_gettime(CLOCK_MONOTONIC_RAW,&ts)) {perror("clock_gettime");exit(2);} return (uint64_t)ts.tv_sec*1000000000ULL+ts.tv_nsec; }
static int bpfcall(enum bpf_cmd cmd, union bpf_attr *a) {return (int)syscall(__NR_bpf,cmd,a,sizeof(*a));}
static int load_xdp(int action) {
 struct bpf_insn insns[2]={{.code=BPF_ALU64|BPF_MOV|BPF_K,.dst_reg=BPF_REG_0,.imm=action},{.code=BPF_JMP|BPF_EXIT}};
 const char license[]="GPL";union bpf_attr a={0}; a.prog_type=BPF_PROG_TYPE_XDP;a.insn_cnt=2;a.insns=(uint64_t)(uintptr_t)insns;a.license=(uint64_t)(uintptr_t)license;
 return bpfcall(BPF_PROG_LOAD,&a);
}
static int setslot(int fd) {uint32_t key=0,v=(uint32_t)fd;union bpf_attr a={0};a.map_fd=mapfd;a.key=(uint64_t)(uintptr_t)&key;a.value=(uint64_t)(uintptr_t)&v;a.flags=BPF_ANY;return bpfcall(BPF_MAP_UPDATE_ELEM,&a);}
static void *worker(void *vp) {
 intptr_t id=(intptr_t)vp; atomic_fetch_add(&ready,1);
 while(!atomic_load_explicit(&go,memory_order_acquire)) sched_yield();
 for(int i=0;i<ops;i++) {
   uint64_t t0=nanos(); int rc=setslot(progfd[(id+i)&1]); uint64_t t1=nanos();
   samples[(size_t)id*ops+i]=t1-t0;
   if(rc) atomic_fetch_add(&failed,1);
 }
 return NULL;
}
static int cmpu64(const void *a,const void *b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return (x>y)-(x<y);}
static uint64_t pct(uint64_t *s,size_t n,unsigned num){size_t i=((n-1)*num+99)/100;return s[i];}
int main(int argc,char **argv){
 if(argc!=5){fprintf(stderr,"usage: %s WRITERS OPS TRIAL OUTPUT_CSV\n",argv[0]);return 2;}
 char *end;long w=strtol(argv[1],&end,10);if(*end||w<1||w>16){fputs("bad WRITERS\n",stderr);return 2;}
 long o=strtol(argv[2],&end,10);if(*end||o<1||o>100000){fputs("bad OPS\n",stderr);return 2;}
 long tr=strtol(argv[3],&end,10);if(*end||tr<1||tr>1000){fputs("bad TRIAL\n",stderr);return 2;}
 writers=(int)w;ops=(int)o;size_t n=(size_t)writers*ops;
 samples=calloc(n,sizeof(*samples));if(!samples){perror("calloc");return 2;}
 union bpf_attr a={0};a.map_type=BPF_MAP_TYPE_PROG_ARRAY;a.key_size=4;a.value_size=4;a.max_entries=1;
 mapfd=bpfcall(BPF_MAP_CREATE,&a);if(mapfd<0){perror("BPF_MAP_CREATE");return 1;}
 progfd[0]=load_xdp(2);progfd[1]=load_xdp(3);if(progfd[0]<0||progfd[1]<0){perror("BPF_PROG_LOAD");return 1;}
 if(setslot(progfd[0])){perror("initial update");return 1;}
 for(int i=0;i<writers;i++){int rc=pthread_create(&threads[i],NULL,worker,(void*)(intptr_t)i);if(rc){fprintf(stderr,"pthread_create: %s\n",strerror(rc));return 1;}}
 while(atomic_load(&ready)!=writers) sched_yield();
 begin_ns=nanos();atomic_store_explicit(&go,1,memory_order_release);
 for(int i=0;i<writers;i++)pthread_join(threads[i],NULL);
 end_ns=nanos();
 int bad=atomic_load(&failed);if(bad){fprintf(stderr,"FAIL: %d updates failed; no statistics accepted\n",bad);return 1;}
 FILE *fp=fopen(argv[4],"w");if(!fp){perror("fopen CSV");return 1;}
 fprintf(fp,"trial,writers,ops_per_writer,writer,op,latency_ns\n");
 for(int i=0;i<writers;i++)for(int j=0;j<ops;j++)fprintf(fp,"%ld,%d,%d,%d,%d,%" PRIu64 "\n",tr,writers,ops,i,j,samples[(size_t)i*ops+j]);
 if(fclose(fp)){perror("fclose");return 1;}
 qsort(samples,n,sizeof(*samples),cmpu64);
 double seconds=(end_ns-begin_ns)/1e9;
 printf("P1_PASS trial=%ld writers=%d ops_per_writer=%d successes=%zu elapsed_s=%.6f throughput_ops_s=%.2f p50_ns=%" PRIu64 " p95_ns=%" PRIu64 " p99_ns=%" PRIu64 " csv=%s\n",tr,writers,ops,n,seconds,n/seconds,pct(samples,n,50),pct(samples,n,95),pct(samples,n,99),argv[4]);
 close(progfd[0]);close(progfd[1]);close(mapfd);free(samples);return 0;
}
