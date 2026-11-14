#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/zuc.h>
#include <gmssl/sm2.h>

static uint64_t now_ns(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return (uint64_t)ts.tv_sec*1000000000ull+ts.tv_nsec; }

static uint8_t buf1m[1024*1024];
static uint8_t out1m[1024*1024];
volatile uint8_t sink;

static void bench_sm3(size_t len, int n, const char *name){
    uint8_t d[32]; uint64_t t0,t1;
    t0=now_ns();
    for(int i=0;i<n;i++){ SM3_CTX c; sm3_init(&c); sm3_update(&c,buf1m,len); sm3_finish(&c,d); sink=d[0]; }
    t1=now_ns(); printf("%s_ns=%llu\n",name,(unsigned long long)((t1-t0)/n));
}
static void bench_sm4_ecb(size_t len,int n,int dec,const char *name){
    SM4_KEY k; uint8_t key[16]={0}; sm4_set_encrypt_key(&k,key); uint64_t t0,t1;
    t0=now_ns();
    for(int i=0;i<n;i++){ if(dec){SM4_KEY dk; sm4_set_decrypt_key(&dk,key); sm4_encrypt_blocks(&dk,out1m,len/16,buf1m);} else sm4_encrypt_blocks(&k,buf1m,len/16,out1m); sink=out1m[0]; }
    t1=now_ns(); printf("%s_ns=%llu\n",name,(unsigned long long)((t1-t0)/n));
}
static void bench_zuc_crypt(size_t len,int n,const char *name){
    uint8_t key[16]={0}, iv[16]={0}; uint64_t t0,t1;
    t0=now_ns();
    for(int i=0;i<n;i++){ ZUC_STATE st; zuc_init(&st,key,iv); zuc_encrypt(&st,buf1m,len,out1m); sink=out1m[0]; }
    t1=now_ns(); printf("%s_ns=%llu\n",name,(unsigned long long)((t1-t0)/n));
}
int main(void){
    for(size_t i=0;i<sizeof(buf1m);i++) buf1m[i]=(uint8_t)i;
    bench_sm3(64,100000,"sm3_64B");
    bench_sm3(1024,100000,"sm3_1K");
    bench_sm3(65536,5000,"sm3_64K");
    bench_sm3(1024*1024,300,"sm3_1M");
    bench_sm4_ecb(16,100000,0,"sm4_ecb_e_16B");
    bench_sm4_ecb(16,100000,1,"sm4_ecb_d_16B");
    bench_sm4_ecb(1024,100000,0,"sm4_ecb_e_1K");
    bench_sm4_ecb(1024,100000,1,"sm4_ecb_d_1K");
    bench_sm4_ecb(65536,5000,0,"sm4_ecb_e_64K");
    bench_sm4_ecb(1024*1024,300,0,"sm4_ecb_e_1M");
    bench_zuc_crypt(1024,100000,"zuc_crypt_1K");
    bench_zuc_crypt(65536,5000,"zuc_crypt_64K");

    SM2_KEY key; sm2_key_generate(&key);
    uint8_t dgst[32]={0x42}; SM2_SIGNATURE sig;
    uint64_t t0,t1;
    int n=2000;
    t0=now_ns(); for(int i=0;i<n;i++){ sm2_do_sign(&key,dgst,&sig); sink=sig.r[0]; } t1=now_ns();
    printf("sm2_sign_ns=%llu\n",(unsigned long long)((t1-t0)/n));
    t0=now_ns(); for(int i=0;i<n;i++){ sink=sm2_do_verify(&key,dgst,&sig); } t1=now_ns();
    printf("sm2_verify_ns=%llu\n",(unsigned long long)((t1-t0)/n));
    SM2_CIPHERTEXT ct; uint8_t pt[256]; size_t ptlen;
    uint8_t msg[32]; for(int i=0;i<32;i++) msg[i]=(uint8_t)i;
    t0=now_ns(); for(int i=0;i<n;i++){ sm2_do_encrypt(&key,msg,sizeof(msg),&ct); } t1=now_ns();
    printf("sm2_encrypt_32B_ns=%llu\n",(unsigned long long)((t1-t0)/n));
    t0=now_ns(); for(int i=0;i<n;i++){ ptlen=sizeof(pt); sm2_do_decrypt(&key,&ct,pt,&ptlen); } t1=now_ns();
    printf("sm2_decrypt_32B_ns=%llu\n",(unsigned long long)((t1-t0)/n));
    t0=now_ns(); for(int i=0;i<n;i++){ sm2_key_generate(&key); } t1=now_ns();
    printf("sm2_keygen_ns=%llu\n",(unsigned long long)((t1-t0)/n));
    return 0;
}
