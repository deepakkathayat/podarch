#ifndef POD_COMMON_H
#define POD_COMMON_H 1

/* NOTE:
 * Suppress the below definition to stop
 * printing PodArch logs. Otherwise, this will
 * print logs/debug statements in STDOUT
 */

#define ENABLE_PODARCH_LOG 1

#include "uthash.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdbool.h>

#ifdef ENABLE_PODARCH_LOG
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define PA_log(M, ...) fprintf(stdout, "[%20s:%6d] " M "\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#else
#define PA_log(M, ...)
#endif

#define PG_SIZE getpagesize()
#define PG_MASK ~(getpagesize() - 1)

#define DATA_INITIALIZED        0
#define DATA_UNINITIALIZED      1
#define DATA_UNINITIALIZED_BSS  2

#define COPY_FROM_MEMORY   0
#define COPY_TO_MEMORY     1

#define TAG_UPDATED_WITH_ZERO 0
#define TAG_UPDATED           1

#define POD_LOAD_CR3             0
#define POD_LOAD_KEY             1
#define POD_LOAD_INIT_INTERVAL   2
#define POD_LOAD_UNINIT_INTERVAL 3
#define POD_LOAD_BSS_INTERVAL    4
#define POD_LOAD_HEAP            5
#define POD_ENTER                6

#define TAGLEN   16 
#define IVLEN    12 
#define AADLEN   20
#define KEY_SIZE 16
#define KCAP_CHUNKS 32

#define NORMAL_PF  0
#define VDF_PF     1

#define MAX_INTERVALS 100000

typedef struct {
    target_ulong start;
    target_ulong end;
    target_ulong VDTB;
    int is_uninitialized;
} interval_struct;

/* The Podarch CPU private table 
   This has CR3 value <-> Kapp mapping
*/

typedef struct {
    target_ulong cr3;
    target_ulong kcap[KCAP_CHUNKS];
    target_ulong kapp;
    target_ulong interval_cnt;
    interval_struct intervals[MAX_INTERVALS];

    /* To track entry points after system call
     * and flags needed for proper working of
     * special syscalls (brk and mmap)
     */
    target_ulong entry_point;
    target_ulong brk_zero_flag;
    target_ulong brk_flag;
    target_ulong brk_begin;
    target_ulong brk_end;
    target_ulong brk_VDTB;
    target_ulong mmap_flag;
    target_ulong mmap_VDTB;
    /* [Optimization]
     * qemu_delva_state is needed just because we are using QEMU to emulate.
     * This is done for improving performance while checking & removing
     * unused pages which will not have an entry in IPACT-table.
     * QEMU does a longjmp and begins munmap emulation from again its start
     * causing TLB translations to happen again (and again) for all when we
     * are checking IPACT-table.
     */
    target_ulong qemu_delva_state;
    UT_hash_handle cr3_table_hash;
}   cr3_table_struct;

/* The Inverted Page Access Control Table (I-PACT)
 * This has Physical <-> [kapp, Virtual] mapping
 *
 * NOTE:
 * In QEMU emulation, we track the Physical page of
 * the Guest machine in terms of the Virtual Page of
 * the Host machine.
 */

typedef struct {
    target_ulong ppn;
    target_ulong kapp;
    target_ulong vpn;
    target_ulong buflen;
    bool swap_bit;
    bool private_bit;
    bool r_bit, w_bit, e_bit;
    unsigned char integrity_tag[KEY_SIZE];
    UT_hash_handle ipact_hash;
} ipact_struct;

void pod_load(CPUX86State *env, target_ulong index,
              target_ulong A, target_ulong B, target_ulong C);
void pod_enter(CPUX86State *env);
void pod_exit(CPUX86State *env);

void handle_tlb_miss_again(CPUX86State *env, target_ulong addr, int is_VDF,
                           uintptr_t retaddr, int is_write1);
int update_integrity_tag(CPUX86State *env, target_ulong pod_int_addr,
                         ipact_struct *item, int direction,
                         uintptr_t retaddr, int no_tag_zero);
void ipact_flush(CPUX86State *env);
void do_page_decrypt(ipact_struct *item);
void do_page_encrypt(ipact_struct *item);
target_ulong is_sealed(cr3_table_struct *item, target_ulong addr);
int is_uninitialized(cr3_table_struct *item, target_ulong addr);
void add_interval(cr3_table_struct *item, target_ulong start,
                  target_ulong end, target_ulong VDTB,
                  int is_uninitialized);

void delete_interval(cr3_table_struct *item, target_ulong start,
                     target_ulong end);
void update_interval(cr3_table_struct *item, target_ulong start,
                     target_ulong end, target_ulong new_end);
target_ulong _kcap_decrypt(target_ulong *kcap);
RSA *createRSA(char *key, int pub);
int private_decrypt(unsigned char *enc_data, int data_len,
                    char *key, unsigned char *decrypted);
void printLastError(const char *msg);

#endif /*!POD_COMMON_H*/
