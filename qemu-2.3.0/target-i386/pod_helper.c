/*
 *  PodArch related helpers
 *
 *  Copyright (c) 2015 visweshn92
 */

#include "cpu.h"
#include "exec/helper-proto.h"

void helper_pod(CPUX86State *env) {

    target_ulong kcap_chunk, chunk, cr3_value, index, start;
    target_ulong end, VDTB, brk_VDTB, mmap_VDTB;

    index = env->regs[R_EAX];

    switch (index) {
        case POD_LOAD_CR3:
            PA_log("Inside Helper Pod eip:0x%" PRIx64, env->eip);
            /* QEMU treats 32-bit value of CR3 */
            cr3_value = env->regs[R_EBX] & 0x00000000FFFFFFFF;
            PA_log("cr3: %" PRIx64, cr3_value);
            pod_load(env, POD_LOAD_CR3, cr3_value, 0, 0);
            break;
           
        case POD_LOAD_KEY:
            kcap_chunk =  env->regs[R_EBX];
            chunk      =  env->regs[R_ECX];
            PA_log("kcap[%" PRIu64 "]: %" PRIu64, chunk, kcap_chunk);
            pod_load(env, POD_LOAD_KEY, kcap_chunk, chunk, 0);
            break;

        case POD_LOAD_INIT_INTERVAL:
            start = env->regs[R_EBX];
            end   = env->regs[R_ECX];
            VDTB  = env->regs[R_EDX]; 
            pod_load(env, POD_LOAD_INIT_INTERVAL, start, end, VDTB);
            break;

        case POD_LOAD_UNINIT_INTERVAL:
            start = env->regs[R_EBX];
            end   = env->regs[R_ECX];
            VDTB  = env->regs[R_EDX];
            pod_load(env, POD_LOAD_UNINIT_INTERVAL, start, end, VDTB);
            break;

        case POD_LOAD_BSS_INTERVAL:
            start = env->regs[R_EBX];
            end   = env->regs[R_ECX];
            VDTB  = env->regs[R_EDX];
            pod_load(env, POD_LOAD_BSS_INTERVAL, start, end, VDTB);
            break;


        case POD_LOAD_HEAP:
            brk_VDTB  = env->regs[R_EBX];
            mmap_VDTB = env->regs[R_ECX];
            pod_load(env, POD_LOAD_HEAP, brk_VDTB, mmap_VDTB, 0);
            break;

        case POD_ENTER:
            pod_enter(env);
			break;

        default:
            break;
    }
}

/* ========================================================================= */

/* Kcpu */
target_ulong kcpu = 0;

/* Reg_Kapp */
target_ulong Reg_kapp = 0;

/* CR3 <-> Kapp private table */
cr3_table_struct *cr3_table = NULL;

/* I-PACT */
ipact_struct *ipact = NULL;
 
void pod_load(CPUX86State *env, target_ulong index, target_ulong A,
              target_ulong B, target_ulong C)
{
    cr3_table_struct *item = NULL;
    HASH_FIND(cr3_table_hash, cr3_table, &env->cr[3], sizeof(target_ulong), item);

    switch(index) {

        case POD_LOAD_CR3:
            assert(item == NULL);
            item = (cr3_table_struct*)malloc(sizeof(cr3_table_struct)); 
            memset(item, 0, sizeof(cr3_table_struct));
            assert(env->cr[3] == A);
            item->cr3  = A;
            HASH_ADD(cr3_table_hash, cr3_table, cr3, sizeof(target_ulong), item);
            break;

        case POD_LOAD_KEY:
            assert(item != NULL);
            item->kcap[B] = A;
            break;

        case POD_LOAD_INIT_INTERVAL:
            assert(item != NULL);
            add_interval(item, A, B, C, DATA_INITIALIZED);
            break;

        case POD_LOAD_UNINIT_INTERVAL:
            assert(item != NULL);
            add_interval(item, A, B, C, DATA_UNINITIALIZED);
            break;

        case POD_LOAD_BSS_INTERVAL:
            assert(item != NULL);
            add_interval(item, A, B, C, DATA_UNINITIALIZED_BSS);
            break;

        case POD_LOAD_HEAP:
            assert(item != NULL);
            item->brk_VDTB  = A;
            item->mmap_VDTB = B;
            break;
    }
}

void add_interval(cr3_table_struct *item, target_ulong start,
                  target_ulong end, target_ulong VDTB, int is_uninitialized)
{
    int cnt;
    cnt = item->interval_cnt++;
    item->intervals[cnt].start = start;
    item->intervals[cnt].end   = end;
    item->intervals[cnt].VDTB  = VDTB;
    item->intervals[cnt].is_uninitialized = is_uninitialized;
    PA_log("add_interval (id=%d, start=0x%" PRIx64 ", end=0x%" PRIx64
           ", VDTB=0x%" PRIx64 ", is_uninitialized=%d)", cnt, start,
            end, VDTB, is_uninitialized);
}

void delete_interval(cr3_table_struct *item, target_ulong start,
                     target_ulong end)
{
    int i, cnt;
    cnt = item->interval_cnt;
    for (i = 0 ; i < cnt; i++) {
        if (start == item->intervals[i].start && end == item->intervals[i].end) {
            PA_log("Deleting [s=0x%" PRIx64 ",e=0x%" PRIx64 "]",
                    item->intervals[i].start, item->intervals[i].end);
            /* NOTE:
             * We are not deleting the space and shifting all others
             * Instead we will simply put start = end = -1
             */
            item->intervals[i].start = -1;
            item->intervals[i].end   = -1;
            item->intervals[i].VDTB  = -1;
            return;
        }
    }
    fprintf(stderr, "Munmaping a region [0x%" PRIx64 " - 0x%" PRIx64
            "not in memory !!", start, end);
    exit(-1);
}

/* This function modifies the end of an interval. Mostly used for
 * handling brk calls and heap modifications
 */
void update_interval(cr3_table_struct *item, target_ulong start,
                    target_ulong end, target_ulong new_end)
{
    int i, cnt;
    cnt = item->interval_cnt;
    for (i = 0 ; i < cnt; i++) {
        if (start == item->intervals[i].start && end == item->intervals[i].end) {
            PA_log("Updating [s=0x%" PRIx64 ",e=0x%" PRIx64 "] to [s=0x%"
                    PRIx64 " ,e=0x%" PRIx64 "]", start, end, start, new_end);
            item->intervals[i].end = new_end;
            return;
        }
    }
    fprintf(stderr, "Updating a region [0x%" PRIx64 " - 0x%" PRIx64
            "not in memory !!", start, end);
    exit(-1);


}

/* Check if an address lies in sensitive regions
 * " 0"  - does not belong to sensitive regions
 * "-1"  - belongs to senstive region but no virtual descriptor 
 * ">0"  - addr of virtual descriptor in sensitive region  
 */
target_ulong is_sealed(cr3_table_struct *item, target_ulong addr) {

    int i, cnt;
    cnt = item->interval_cnt;
    for (i = 0; i < cnt; i++)
        if (addr >= item->intervals[i].start && addr <= item->intervals[i].end) {

            PA_log("Found addr=0x%" PRIx64 " in [s=0x%" PRIx64 ",e=0x%" PRIx64 "]",
                        addr, item->intervals[i].start, item->intervals[i].end);

            if (item->intervals[i].VDTB == -1)
                return -1;

             target_ulong offset = ((addr & PG_MASK) - item->intervals[i].start) / PG_SIZE;
            target_ulong pod_int_addr = item->intervals[i].VDTB + (offset * 32);
            return pod_int_addr;
        }
    return 0;
}

/* Check if the addr falls in initialzed or uninitialized segment.
 */
int is_uninitialized(cr3_table_struct *item, target_ulong addr) {

    int i, cnt;
    cnt = item->interval_cnt;
    for (i = 0; i < cnt; i++)
        if (addr >= item->intervals[i].start && addr <= item->intervals[i].end) {
            return item->intervals[i].is_uninitialized;
        }
    return -1;
}

void printLastError(const char *msg)
{
    char *err = malloc(130);
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    PA_log("%s ERROR: %s", msg, err);
    free(err);
}

RSA *createRSA(char *key, int public)
{
    RSA *rsa= NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL)
    {
        PA_log("Failed to create key BIO");
        exit(1);
    }

    if (public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    if (rsa == NULL)
    {
        PA_log("Failed to create RSA");
        exit(1);
    }

    return rsa;
}

int private_decrypt(unsigned char *enc_data, int data_len,
                    char *key, unsigned char *decrypted)
{
    RSA *rsa   = createRSA(key, 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted,
                                     rsa, RSA_PKCS1_PADDING);
    return result;
}

target_ulong _kcap_decrypt(target_ulong *kcap) {

    PA_log("RSA Decrypting to get kapp");

    char *privateKey = NULL;
    size_t read_size, string_size;
    FILE *handler;
    target_ulong kapp = 0;
    int i;
    unsigned char kcap_buffer[KCAP_CHUNKS * 8];
    unsigned char decrypted[KCAP_CHUNKS * 8];

    for (i = 0; i < KCAP_CHUNKS; i++) {
        unsigned long long longInt = *(kcap + i);
        kcap_buffer[i * 8 + 0] = (unsigned char)((longInt >> 56) & 0xFF);
        kcap_buffer[i * 8 + 1] = (unsigned char)((longInt >> 48) & 0xFF);
        kcap_buffer[i * 8 + 2] = (unsigned char)((longInt >> 40) & 0xFF);
        kcap_buffer[i * 8 + 3] = (unsigned char)((longInt >> 32) & 0xFF);
        kcap_buffer[i * 8 + 4] = (unsigned char)((longInt >> 24) & 0xFF);
        kcap_buffer[i * 8 + 5] = (unsigned char)((longInt >> 16) & 0xFF);
        kcap_buffer[i * 8 + 6] = (unsigned char)((longInt >> 8) & 0xFF);
        kcap_buffer[i * 8 + 7] = (unsigned char)((longInt) & 0xFF);
    }

    handler = fopen("key-cpu", "r");

    if (handler) {
        // Scan to find the length of buffer
        fseek(handler, 0, SEEK_END);
        string_size = ftell (handler);
        rewind(handler);

        privateKey = (char*) malloc (sizeof(char) * (string_size + 1));
        read_size = fread(privateKey, sizeof(char), string_size, handler);
        privateKey[string_size] = '\0';
        assert (string_size == read_size);
        fclose(handler);
    } else {
        PA_log("Private key file not found\n");
        exit(1);
    }

    int decrypted_length = private_decrypt(kcap_buffer, sizeof kcap_buffer,
                                           privateKey, decrypted);
    if(decrypted_length == -1)
    {
        printLastError("Private Decrypt failed ");
        exit(1);
    }
    kapp = strtoull((char*)decrypted, (char**) NULL, 10);
    return kapp;
}


void pod_enter(CPUX86State *env) {
    int ret = 0;
    cr3_table_struct *temp = NULL;
    target_ulong kapp;

    HASH_FIND(cr3_table_hash, cr3_table, &env->cr[3], sizeof(target_ulong), temp);
    if(temp && temp->kapp == 0) {
        // Recover the kapp
        kapp = _kcap_decrypt(&temp->kcap[0]);
        if (kapp) {
            temp->kapp = kapp;
            ret = 1;
            PA_log("pod_enter (kapp=%" PRIu64 ")", kapp);
            /* In PodArch, the CPU assumes that the _start is located on a 
               pre-defined offset from code segment. This will cause the EIP
               to jump to correct starting point after pod_enter. Note that
               ELF binary will have starting address as pod_enter which is in
               public area and accessible to OS as well.

               Adversarial thoughts:
               i)  If OS does not issue pod_enter => The kapp will remain in decrypted form
               ii) If OS keeps reissuing the pod_enter => The kapp decryption will catch
            */
            env->eip = temp->intervals[0].start + 0x7000;
            cpu_resume_from_signal(ENV_GET_CPU(env), NULL);
        }
    }
    if (ret == 0)
        pod_exit(env);

}

void pod_exit(CPUX86State *env) {

    PA_log("pod_exit()");

    // Flush IPACT first
    ipact_flush(env);

    cr3_table_struct *temp = NULL;
    HASH_FIND(cr3_table_hash, cr3_table, &env->cr[3], sizeof(target_ulong), temp);
    // Delete the cr3 entry
    if(temp) {
        HASH_DELETE(cr3_table_hash, cr3_table, temp);
        free(temp);
    }

    Reg_kapp = 0;
}

void ipact_flush(CPUX86State *env) {

    PA_log("Flusing IPACT");

    cr3_table_struct *temp = NULL;
    HASH_FIND(cr3_table_hash, cr3_table, &env->cr[3], sizeof(target_ulong), temp);
    if (temp == NULL || Reg_kapp != temp->kapp) {
        PA_log("Something is wrong in ipact_flush()");
        return;
    }

    ipact_struct *temp1 = NULL;
    ipact_struct *dummy = NULL;

    HASH_ITER(ipact_hash, ipact, temp1, dummy) {
        if (temp1 && temp1->kapp == Reg_kapp) {
            /* Check if pages are in decrypted form.
             * If yes, encrypt the pages matching the
             * current authority
             */
            if (temp1->swap_bit == false) {
                do_page_encrypt(temp1);

                /* We need to update the integrity tags (virtual descriptors) again
                 * This is needed as contents (like data section) could have been
                 * modified during the program execution.
                 */

                target_ulong val = is_sealed(temp, temp1->vpn);
                if (val != -1) {
                    target_ulong pod_int_addr = val;
                    update_integrity_tag(env, pod_int_addr, temp1, COPY_TO_MEMORY,
                                         (uintptr_t)NULL, !is_uninitialized(temp, temp1->vpn));
                }
            }
            PA_log("Deleting 0x%" PRIx64 " from I-PACT", temp1->vpn);
            HASH_DELETE(ipact_hash, ipact, temp1);
            free(temp1);
        }
    }
    tlb_flush(ENV_GET_CPU(env), 1);
}

/* AES-GCM-128 related constants */
static const unsigned char AAD[AADLEN] = {
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
    0xab,0xad,0xda,0xd2
};

static const unsigned char IV[IVLEN] = {
    0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
};

/* NOTE: retaddr is QEMU TCG related, hence do not tamper with it. */
void handle_tlb_miss_again(CPUX86State *env, target_ulong addr,
                           int is_VDF, uintptr_t retaddr, int is_write1)
{
    PA_log("handle_tlb_miss_again() for %d 0x%" PRIx64, is_VDF, addr);
    int ret = x86_cpu_handle_mmu_fault(ENV_GET_CPU(env), addr, is_write1 ? MMU_DATA_STORE: MMU_DATA_LOAD, MMU_USER_IDX, is_VDF);

    if (ret) {
        PA_log("Page fault exception for 0x%" PRIx64 ", error=%d", addr, env->error_code);
        if (retaddr) {
            /* now we have a real cpu fault */
            cpu_restore_state(ENV_GET_CPU(env), retaddr);
        }
        raise_exception_err(env, ENV_GET_CPU(env)->exception_index, env->error_code);
    }
}

/*
 * INPUT:
 * -----
 * This function is two-way function. If direction is
 *  COPY_FROM_MEMORY [0] - copies integrity tags from memory to CPU data structures
 *  COPY_TO_MEMORY   [1] - copies integrity tags from CPU data structures to memory
 *
 * OUTPUT:
 * ------
 * This returns whether it handled a zero tag or not
 * TAG_UPDATED           [1]
 * TAG_UPDATED_WITH_ZERO [0]
 */
int update_integrity_tag(CPUX86State *env, target_ulong pod_int_addr,
                          ipact_struct *item, int direction, uintptr_t retaddr,
                          int no_tag_zero)
{
    int z;
    unsigned char *pod_int_host_va;
    unsigned char zero_tag[TAGLEN] = {0};
    int pod_int_index = (pod_int_addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong pod_int_tlb_addr = env->tlb_table[MMU_USER_IDX][pod_int_index].addr_write;

    /* Ideally this function must be called only after a TLB
     * hit for Virtual descriptor page. Handle if there is a miss
     */
    if((pod_int_addr & TARGET_PAGE_MASK) != (pod_int_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        handle_tlb_miss_again(env, pod_int_addr, VDF_PF, retaddr, 1);
    }

    pod_int_host_va = (unsigned char*)(pod_int_addr + env->tlb_table[MMU_USER_IDX][pod_int_index].addend);
    PA_log("update_intergity_tag() %d %d %d pod_int_address 0x%" PRIx64,
           no_tag_zero, direction, pod_int_index, pod_int_addr);
    for(z = 0; z < TAGLEN; z++) {
        if (direction) {
            if (no_tag_zero) {
                *((unsigned char*)pod_int_host_va + (int)z) = item->integrity_tag[z];
            } else {
                *((unsigned char*)pod_int_host_va + (int)z) = 0;
            }
        } else {
            item->integrity_tag[z] = (unsigned char)* ((unsigned char*)pod_int_host_va + (int)z);
        }
    }

    unsigned char pod_buf_var[5];
    if (direction) {
        snprintf((char*)pod_buf_var, 5, "%04d", (int)item->buflen);
    }

    for(z = 0; z < 4; z++) {
        if (direction) {
            *((unsigned char*)pod_int_host_va + TAGLEN + (int)z) = pod_buf_var[z];
        } else {
            pod_buf_var[z] = (unsigned char)* ((unsigned char*)pod_int_host_va + TAGLEN + (int)z);
        }
    }

    if (!direction) {
        pod_buf_var[4] = '\0';
        char *stopstring;
        item->buflen = strtoull((char*) pod_buf_var, &stopstring, 10);

        /* Integrity with zero denotes it was uninitialized page
         * (like bss, stack or heap) so no need to the actual
         * decryption in such a case. Hence flag that to MMU
         */
        if(!memcmp(zero_tag, item->integrity_tag, TAGLEN)) {
            return TAG_UPDATED_WITH_ZERO;
        }
    } else if (!no_tag_zero) {
        return TAG_UPDATED_WITH_ZERO;
    }

    return TAG_UPDATED;
}

void do_page_decrypt(ipact_struct *item)
{
    PA_log("do_page_decrypt(): 0x%" PRIx64, item->vpn);

    int i, thesize, dec_success, howmany;
    unsigned char *pod_host_va, *CT, *tag, *ptbuf;
    unsigned char Key[KEY_SIZE];
    const EVP_CIPHER *gcm = EVP_aes_128_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    item->swap_bit = false;
    thesize = item->buflen;
    tag = item->integrity_tag;
    pod_host_va = (unsigned char*) item->ppn;

    CT = (unsigned char*)malloc(PG_SIZE);
    memset(CT, 0, PG_SIZE);

    for(i = 0; i < thesize; i++) {
        *((unsigned char*)CT + (int)i) = (unsigned char)* ((unsigned char*)pod_host_va + (int)i);
    }

    int nlen = snprintf(NULL, 0, "%"PRIu64, item->kapp);
    assert(nlen > 0);
    assert(nlen == KEY_SIZE);
    unsigned char tempkeybuf[nlen + 1];
    int clen = snprintf((char*) tempkeybuf, (unsigned int) nlen + 1, "%"PRIu64, item->kapp);
    assert(tempkeybuf[nlen] == '\0');
    assert(clen == nlen);

    for (i = 0; i < KEY_SIZE; i++)
        Key[i] = tempkeybuf[i];

    ptbuf = (unsigned char*) malloc(PG_SIZE);
    memset(ptbuf, 0, PG_SIZE);

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit (ctx, gcm, Key, IV);
    EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, TAGLEN, tag);
    EVP_DecryptInit (ctx, NULL, Key, IV);
    EVP_DecryptUpdate (ctx, NULL, &howmany, AAD, AADLEN);

    EVP_DecryptUpdate (ctx, ptbuf, &howmany, CT, thesize);

    dec_success = EVP_DecryptFinal (ctx, tag, &howmany);
    EVP_CIPHER_CTX_free(ctx);

    if (dec_success) {
        PA_log("GCM works!");
        for(i = 0; i < PG_SIZE; i++) {
            *((unsigned char*) pod_host_va+ (int)i) = (unsigned char)* ((unsigned char*)ptbuf + (int)i);
        }
    } else {
        PA_log("GCM failed at vaddr=0x%" PRIx64, item->vpn);
        exit(-1);
    }

    free(CT);
    free(ptbuf);
}

void do_page_encrypt(ipact_struct *item) {

    PA_log("do_page_encrypt(): 0x%" PRIx64, item->vpn);

    int i, howmany;
    unsigned char *buf, *CT, *pod_host_va;
    unsigned char Key[KEY_SIZE];
    unsigned char tagbuf[TAGLEN];
    const EVP_CIPHER *gcm = EVP_aes_128_gcm();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    item->swap_bit = true;
    buf = (unsigned char*)malloc(PG_SIZE);
    memset(buf, 0, PG_SIZE);

    pod_host_va = (unsigned char*) item->ppn;
    for(i = 0; i < item->buflen; i++)
        buf[i] = *((unsigned char*)pod_host_va + (int)i);

    int nlen = snprintf(NULL, 0, "%"PRIu64, item->kapp);
    assert(nlen > 0);
    assert(nlen == KEY_SIZE);
    unsigned char tempkeybuf[nlen + 1];
    int clen = snprintf((char*)tempkeybuf, nlen+1, "%"PRIu64, item->kapp);
    assert(tempkeybuf[nlen] == '\0');
    assert(clen == nlen);

    for(i = 0; i < KEY_SIZE; i++)
        Key[i] = tempkeybuf[i];

    CT = (unsigned char*)malloc(PG_SIZE);
    memset(CT, 0, PG_SIZE);

    EVP_EncryptInit (ctx, gcm, Key, IV);
    EVP_EncryptUpdate (ctx, NULL, &howmany, AAD, AADLEN);

    EVP_EncryptUpdate (ctx, CT, &howmany, buf, item->buflen);

    // Update the memory content with ciphertext
    for(i = 0; i < item->buflen; i++)
        *((unsigned char*)pod_host_va + (int)i) = CT[i];

    EVP_EncryptFinal (ctx, tagbuf, &howmany);
    EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, TAGLEN, tagbuf);

    memcpy(item->integrity_tag, &tagbuf, TAGLEN);

    EVP_CIPHER_CTX_free(ctx);
    free(CT);
    free(buf);
}
