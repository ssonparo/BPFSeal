/* BPFSeal P3A native userspace cryptographic-cost microbenchmark.
 * Does not exercise the Linux kernel, mutexes or BPF syscalls.
 * Compare BPFSeal-v1 fixed 1116-byte canonical SHA256 against the
 * P3A Python reference model's 64-leaf Merkle update (8 SHA256 calls).
 * Build: gcc -O2 -Wall -Wextra -std=c11 -o bpfseal_p3a_native_bench bpfseal_p3a_native_bench.c -lcrypto
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#define SLOTS 64
#define SIZE_V1 (28 + 17*SLOTS)
#define RUNS 7
#define OPS 200000
#define HLEN 32
static volatile unsigned long long guard;
static const unsigned char A[8] = {0x61,0x4b,0x43,0x4c,0xd8,0x32,0x4e,0xcc};
static const unsigned char B[8] = {0x79,0xaa,0x95,0x55,0x5f,0x6b,0x99,0xc7};
static void be32(unsigned char*p,uint32_t x){for(int i=3;i>=0;i--){p[i]=(unsigned char)x;x>>=8;}}
static void be64(unsigned char*p,uint64_t x){for(int i=7;i>=0;i--){p[i]=(unsigned char)x;x>>=8;}}
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC_RAW,&t);return t.tv_sec+t.tv_nsec*1.e-9;}
static int cmpdbl(const void*a,const void*b){double x=*(const double*)a,y=*(const double*)b;return(x>y)-(x<y);}
static uint64_t rngstate=0x89524711aabbccddULL;
static uint32_t rng32(void){rngstate^=rngstate>>12;rngstate^=rngstate<<25;rngstate^=rngstate>>27;return (uint32_t)((rngstate*2685821657736338717ULL)>>32);}
struct action {int slot; int state;}; /* state 0 empty, 1 A, 2 B */
struct v1 { unsigned char canonical[SIZE_V1], digest[32]; };
static void v1_init(struct v1*v,int capacity){memset(v,0,sizeof(*v));memcpy(v->canonical,"BPFSeal-array-v1",16);be64(v->canonical+16,0x0123456789abcdefULL);be32(v->canonical+24,(uint32_t)capacity);}
static void v1_update(struct v1*v,int slot,int state){unsigned char*p=v->canonical+28+17*slot;memset(p,0,17);if(state){p[0]=1;memcpy(p+1,state==1?A:B,8);be64(p+9,state==1?171224815712ULL:171224868507ULL);}SHA256(v->canonical,SIZE_V1,v->digest);guard += v->digest[0];}
struct merkle { unsigned char nodes[128][32]; unsigned char digest[32]; int cap; };
static const char LD[]="BPFSeal-Merkle-v1:leaf";
static const char ND[]="BPFSeal-Merkle-v1:node";
static const char RD[]="BPFSeal-Merkle-v1:root";
/* Include NUL delimiters, matching Python's b'...\\x00'. */
static void merkle_leaf(unsigned char*out,int index,int state){unsigned char b[sizeof(LD)-1+1+4+17]={0};memcpy(b,LD,sizeof(LD)-1);be32(b+sizeof(LD),(uint32_t)index);unsigned char*p=b+sizeof(LD)+4;if(state){p[0]=1;memcpy(p+1,state==1?A:B,8);be64(p+9,state==1?171224815712ULL:171224868507ULL);}SHA256(b,sizeof(b),out);}
static void merkle_node(unsigned char*out,const unsigned char*l,const unsigned char*r){unsigned char b[sizeof(ND)-1+1+64];memcpy(b,ND,sizeof(ND));memcpy(b+sizeof(ND),l,32);memcpy(b+sizeof(ND)+32,r,32);SHA256(b,sizeof(b),out);}
static void merkle_root(struct merkle*m){unsigned char b[sizeof(RD)-1+1+8+4+32];memcpy(b,RD,sizeof(RD));be64(b+sizeof(RD),0x0123456789abcdefULL);be32(b+sizeof(RD)+8,(uint32_t)m->cap);memcpy(b+sizeof(RD)+12,m->nodes[1],32);SHA256(b,sizeof(b),m->digest);}
static void merkle_init(struct merkle*m,int capacity){memset(m,0,sizeof(*m));m->cap=capacity;for(int i=0;i<SLOTS;i++)merkle_leaf(m->nodes[64+i],i,0);for(int i=63;i>0;i--)merkle_node(m->nodes[i],m->nodes[2*i],m->nodes[2*i+1]);merkle_root(m);}
static void merkle_update(struct merkle*m,int slot,int state){int p=64+slot;merkle_leaf(m->nodes[p],slot,state);while(p>1){p/=2;merkle_node(m->nodes[p],m->nodes[2*p],m->nodes[2*p+1]);}merkle_root(m);guard += m->digest[0];}
static void fill_actions(struct action*a,int cap,int n){uint8_t state[SLOTS]={0};rngstate=0x89524711aabbccddULL^(uint64_t)cap;for(int i=0;i<n;i++){int idx=(int)(rng32()%(uint32_t)cap);int s=(int)(rng32()%3);/* Avoid unsuccessful deletes, so every action is a committed mutation. */if(s==0 && state[idx]==0)s=1;state[idx]=(uint8_t)s;a[i]=(struct action){idx,s};}}
static void run(int cap,int n){struct action*a=malloc((size_t)n*sizeof(*a));if(!a){perror("malloc");exit(1);}fill_actions(a,cap,n);double v[RUNS],m[RUNS];for(int round=0;round<RUNS;round++){/* Alternate order to limit systematic cache/frequency bias. */int order=round%2;for(int z=0;z<2;z++){int method=(order+z)%2;double start=now();if(method==0){struct v1 x;v1_init(&x,cap);start=now();for(int i=0;i<n;i++)v1_update(&x,a[i].slot,a[i].state);v[round]=(now()-start)*1e9/n;}else{struct merkle x;merkle_init(&x,cap);start=now();for(int i=0;i<n;i++)merkle_update(&x,a[i].slot,a[i].state);m[round]=(now()-start)*1e9/n;}}}
qsort(v,RUNS,sizeof(double),cmpdbl);qsort(m,RUNS,sizeof(double),cmpdbl);printf("capacity=%d ops=%d trials=%d v1_ns_op=%.1f merkle_ns_op=%.1f merkle_over_v1=%.2fx guard=%llu\n",cap,n,RUNS,v[RUNS/2],m[RUNS/2],m[RUNS/2]/v[RUNS/2],guard);free(a);}
int main(int argc,char**argv){int n=OPS;if(argc>2){fprintf(stderr,"usage: %s [operations_per_trial]\n",argv[0]);return 2;}if(argc==2){char*end;long x=strtol(argv[1],&end,10);if(*end||x<1000||x>1000000){fprintf(stderr,"operations must be 1000..1000000\n");return 2;}n=(int)x;}printf("P3A_NATIVE_BENCH userspace_only=1 openssl_SHA256=1 fixed_buffer_bytes=%d merkle_hashes_per_mutation=8\n",SIZE_V1);for(int cap=1;cap<=64;cap*=4)run(cap,n);return 0;}
