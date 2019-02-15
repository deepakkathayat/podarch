/*
 *  Software MMU support
 *
 * Generate helpers used by TCG for qemu_ld/st ops and code load
 * functions.
 *
 * Included from target op helpers and exec.c.
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"

#define DATA_SIZE (1 << SHIFT)

#if DATA_SIZE == 8
#define SUFFIX q
#define LSUFFIX q
#define SDATA_TYPE  int64_t
#define DATA_TYPE  uint64_t
#elif DATA_SIZE == 4
#define SUFFIX l
#define LSUFFIX l
#define SDATA_TYPE  int32_t
#define DATA_TYPE  uint32_t
#elif DATA_SIZE == 2
#define SUFFIX w
#define LSUFFIX uw
#define SDATA_TYPE  int16_t
#define DATA_TYPE  uint16_t
#elif DATA_SIZE == 1
#define SUFFIX b
#define LSUFFIX ub
#define SDATA_TYPE  int8_t
#define DATA_TYPE  uint8_t
#else
#error unsupported data size
#endif


/* For the benefit of TCG generated code, we want to avoid the complication
   of ABI-specific return type promotion and always return a value extended
   to the register size of the host.  This is tcg_target_long, except in the
   case of a 32-bit host and 64-bit data, and for that we always have
   uint64_t.  Don't bother with this widened value for SOFTMMU_CODE_ACCESS.  */
#if defined(SOFTMMU_CODE_ACCESS) || DATA_SIZE == 8
# define WORD_TYPE  DATA_TYPE
# define USUFFIX    SUFFIX
#else
# define WORD_TYPE  tcg_target_ulong
# define USUFFIX    glue(u, SUFFIX)
# define SSUFFIX    glue(s, SUFFIX)
#endif

#ifdef SOFTMMU_CODE_ACCESS
#define READ_ACCESS_TYPE MMU_INST_FETCH
#define ADDR_READ addr_code
#else
#define READ_ACCESS_TYPE MMU_DATA_LOAD
#define ADDR_READ addr_read
#endif

#if DATA_SIZE == 8
# define BSWAP(X)  bswap64(X)
#elif DATA_SIZE == 4
# define BSWAP(X)  bswap32(X)
#elif DATA_SIZE == 2
# define BSWAP(X)  bswap16(X)
#else
# define BSWAP(X)  (X)
#endif

#ifdef TARGET_WORDS_BIGENDIAN
# define TGT_BE(X)  (X)
# define TGT_LE(X)  BSWAP(X)
#else
# define TGT_BE(X)  BSWAP(X)
# define TGT_LE(X)  (X)
#endif

#if DATA_SIZE == 1
# define helper_le_ld_name  glue(glue(helper_ret_ld, USUFFIX), MMUSUFFIX)
# define helper_be_ld_name  helper_le_ld_name
# define helper_le_lds_name glue(glue(helper_ret_ld, SSUFFIX), MMUSUFFIX)
# define helper_be_lds_name helper_le_lds_name
# define helper_le_st_name  glue(glue(helper_ret_st, SUFFIX), MMUSUFFIX)
# define helper_be_st_name  helper_le_st_name
#else
# define helper_le_ld_name  glue(glue(helper_le_ld, USUFFIX), MMUSUFFIX)
# define helper_be_ld_name  glue(glue(helper_be_ld, USUFFIX), MMUSUFFIX)
# define helper_le_lds_name glue(glue(helper_le_ld, SSUFFIX), MMUSUFFIX)
# define helper_be_lds_name glue(glue(helper_be_ld, SSUFFIX), MMUSUFFIX)
# define helper_le_st_name  glue(glue(helper_le_st, SUFFIX), MMUSUFFIX)
# define helper_be_st_name  glue(glue(helper_be_st, SUFFIX), MMUSUFFIX)
#endif

#ifdef TARGET_WORDS_BIGENDIAN
# define helper_te_ld_name  helper_be_ld_name
# define helper_te_st_name  helper_be_st_name
#else
# define helper_te_ld_name  helper_le_ld_name
# define helper_te_st_name  helper_le_st_name
#endif

/* macro to check the victim tlb */
#define VICTIM_TLB_HIT(ty)                                                    \
({                                                                            \
    /* we are about to do a page table walk. our last hope is the             \
     * victim tlb. try to refill from the victim tlb before walking the       \
     * page table. */                                                         \
    int vidx;                                                                 \
    hwaddr tmpiotlb;                                                          \
    CPUTLBEntry tmptlb;                                                       \
    for (vidx = CPU_VTLB_SIZE-1; vidx >= 0; --vidx) {                         \
        if (env->tlb_v_table[mmu_idx][vidx].ty == (addr & TARGET_PAGE_MASK)) {\
            /* found entry in victim tlb, swap tlb and iotlb */               \
            tmptlb = env->tlb_table[mmu_idx][index];                          \
            env->tlb_table[mmu_idx][index] = env->tlb_v_table[mmu_idx][vidx]; \
            env->tlb_v_table[mmu_idx][vidx] = tmptlb;                         \
            tmpiotlb = env->iotlb[mmu_idx][index];                            \
            env->iotlb[mmu_idx][index] = env->iotlb_v[mmu_idx][vidx];         \
            env->iotlb_v[mmu_idx][vidx] = tmpiotlb;                           \
            break;                                                            \
        }                                                                     \
    }                                                                         \
    /* return true when there is a vtlb hit, i.e. vidx >=0 */                 \
    vidx >= 0;                                                                \
})

#ifdef CONFIG_PODARCH
#define PREFETCH_VDF(num)                                                                       \
({                                                                                              \
        if (Reg_kapp && mmu_idx == MMU_USER_IDX) {                                              \
            cr3_table_struct *temp = NULL;                                                      \
            HASH_FIND(cr3_table_hash, cr3_table, &env->cr[3], sizeof(target_ulong), temp);      \
            /* Check the current authority*/                                                    \
            if(temp && temp->kapp == Reg_kapp) {                                                \
                target_ulong val = is_sealed(temp, addr);                                       \
                if (val != 0 && val != -1) {                                                    \
                    target_ulong pod_int_addr = val;                                            \
                    int pod_int_index = (pod_int_addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);\
                    target_ulong pod_int_tlb_addr =                                             \
                        env->tlb_table[mmu_idx][pod_int_index].addr_write;                      \
                                                                                                \
                    PA_log("[%d] addr: 0x%" PRIx64 ", pod_int_addr: 0x%" PRIx64,                \
                            num, addr, pod_int_addr);                                           \
                                                                                                \
                    /* Check for TLB miss of virtual descriptors first */                       \
                    /* and handle it accordingly. */                                            \
                    if ((pod_int_addr & TARGET_PAGE_MASK) !=                                    \
                        (pod_int_tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {           \
                        handle_tlb_miss_again(env, pod_int_addr, VDF_PF, retaddr, 1);           \
                    }                                                                           \
                }                                                                               \
            }                                                                                   \
        }                                                                                       \
})

#define CHECK_N_POPULATE_IPACT(num)                                                             \
({                                                                                              \
    cr3_table_struct *temp = NULL;                                                              \
    int visited = 0;                                                                            \
    int ret = TAG_UPDATED;                                                                      \
    HASH_FIND(cr3_table_hash, cr3_table, &env->cr[3], sizeof(target_ulong), temp);              \
    ipact_struct  *temp1 = NULL;                                                                \
    target_ulong PPN =                                                                          \
        (addr & TARGET_PAGE_MASK) + env->tlb_table[mmu_idx][index].addend;                      \
                                                                                                \
    HASH_FIND(ipact_hash, ipact, &PPN, sizeof(target_ulong), temp1);                            \
    if (temp1 != NULL && temp1->swap_bit == false) {                                            \
        if (mmu_idx != MMU_USER_IDX) {                                                          \
            visited = 1;                                                                        \
            PA_log("[%d] Cloaking entry in IPACT: 0x%" PRIx64 "-> (0x%" PRIx64                  \
                   ", %" PRIu64 ")", num, PPN, temp1->vpn, temp1->kapp);                        \
            do_page_encrypt(temp1);                                                             \
            /* Iterate over the cr3 table to find the VDTB details of this                      \
             * page owner so that we can update the integrity as well                           \
             */                                                                                 \
            cr3_table_struct *iter  = NULL;                                                     \
            cr3_table_struct *dummy = NULL;                                                     \
            target_ulong old_cr3;                                                               \
            HASH_ITER(cr3_table_hash, cr3_table, iter, dummy) {                                 \
                if (iter != NULL && iter->kapp == temp1->kapp) {                                \
                    target_ulong val = is_sealed(iter, temp1->vpn);                             \
                    old_cr3 = env->cr[3];                                                       \
                    if (val != -1) {                                                            \
                        env->cr[3] = iter->cr3;                                                 \
                        target_ulong pod_int_addr = val;                                        \
                        update_integrity_tag(env, pod_int_addr, temp1, COPY_TO_MEMORY,          \
                                             retaddr, 1);                                       \
                    }                                                                           \
                    env->cr[3] = old_cr3;                                                       \
                    break;                                                                      \
                }                                                                               \
            }                                                                                   \
            /* Make sure we were successful in updating the tag */                              \
            assert (iter != NULL);                                                              \
        }                                                                                       \
    }                                                                                           \
    if (temp1 != NULL && Reg_kapp && temp1->kapp != temp->kapp) {                               \
        assert(temp1->swap_bit == true);                                                        \
        PA_log("[%d] Deleting entry from IPACT: 0x%" PRIx64 "-> (0x%" PRIx64                    \
               ", %" PRIu64 ")", num, PPN, temp1->vpn, temp1->kapp);                            \
        HASH_DELETE(ipact_hash, ipact, temp1);                                                  \
        free(temp1);                                                                            \
    }                                                                                           \
                                                                                                \
    if (temp1 == NULL && Reg_kapp > 0 && mmu_idx == MMU_USER_IDX) {                             \
        target_ulong val = is_sealed(temp, addr);                                               \
        if (val != 0) {                                                                         \
            visited = 1;                                                                        \
            temp1 = (ipact_struct*)malloc(sizeof(ipact_struct));                                \
            memset(temp1, 0, sizeof(ipact_struct));                                             \
            temp1->kapp = Reg_kapp;                                                             \
            temp1->ppn  = PPN;                                                                  \
            temp1->vpn  = addr & PG_MASK;                                                       \
            temp1->private_bit = true;                                                          \
            temp1->swap_bit    = false;                                                         \
            if (val != -1) {                                                                    \
                target_ulong pod_int_addr = val;                                                \
                ret = update_integrity_tag(env, pod_int_addr, temp1, COPY_FROM_MEMORY,          \
                                           retaddr, 1);                                         \
                if (ret != TAG_UPDATED_WITH_ZERO) {                                             \
                    do_page_decrypt(temp1);                                                     \
                } else {                                                                        \
                    PA_log("do_page_decrypt() [Zero Tag] : 0x%" PRIx64, temp1->vpn);            \
                }                                                                               \
            }                                                                                   \
            /* When BSS pages are used for writing, kernel creates a copy of *shared* zero      \
             * page [COW] and gives it to the process. However, there are cases when the        \
             * BSS zero-ed page is read *first* and then written. In that case, I-PACT gets     \
             * populated with two entries of PPN <-> [VPN, KEY] where the first entry is        \
             * physical page corresponding to shared page. This entry during pod_exit() will    \
             * get encrypted and compromises the benign working of other processes. Thus,       \
             * make CPU aware of skipping I-PACT population for BSS region when it is read      \
             * first.                                                                           \
             */                                                                                 \
            if (num == 1 && ret == TAG_UPDATED_WITH_ZERO                                        \
                && is_uninitialized(temp, temp1->vpn) == DATA_UNINITIALIZED_BSS)                \
            {                                                                                   \
                PA_log("[%d] Skipping entry [BSS] into IPACT: 0x%" PRIx64 "-> (0x%" PRIx64      \
                       ", %" PRIu64 ")", num, PPN, temp1->vpn, temp1->kapp);                    \
                free(temp1);                                                                    \
            } else {                                                                            \
                PA_log("[%d] Adding entry into IPACT: 0x%" PRIx64 "-> (0x%" PRIx64              \
                       ", %" PRIu64 ")", num, PPN, temp1->vpn, temp1->kapp);                    \
                HASH_ADD(ipact_hash, ipact, ppn, sizeof(target_ulong), temp1);                  \
            }                                                                                   \
        }                                                                                       \
    }                                                                                           \
    /* The TLB entries are entirely based on index lookups. Sometimes due to VDF, we            \
     * might end up overriding the normal translation hits with VDF hits (say in case the       \
     * lookup index happens to be same). So better to cross check again and restore the         \
     * TLB as it would have been without any intervention of VDF hits.                          \
     */                                                                                         \
    if (visited) {                                                                              \
        tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;                                    \
        if ((addr & TARGET_PAGE_MASK)                                                           \
            != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {                            \
            tlb_fill(ENV_GET_CPU(env), addr, (num > 2 ? MMU_DATA_STORE: MMU_INST_FETCH),        \
                     mmu_idx, retaddr);                                                         \
            tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;                                \
        }                                                                                       \
    }                                                                                           \
})
#endif

#ifndef SOFTMMU_CODE_ACCESS
static inline DATA_TYPE glue(io_read, SUFFIX)(CPUArchState *env,
                                              hwaddr physaddr,
                                              target_ulong addr,
                                              uintptr_t retaddr)
{
    uint64_t val;
    CPUState *cpu = ENV_GET_CPU(env);
    MemoryRegion *mr = iotlb_to_region(cpu, physaddr);

    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;
    cpu->mem_io_pc = retaddr;
    if (mr != &io_mem_rom && mr != &io_mem_notdirty && !cpu_can_do_io(cpu)) {
        cpu_io_recompile(cpu, retaddr);
    }

    cpu->mem_io_vaddr = addr;
    io_mem_read(mr, physaddr, &val, 1 << SHIFT);
    return val;
}
#endif

#ifdef SOFTMMU_CODE_ACCESS
static __attribute__((unused))
#endif
WORD_TYPE helper_le_ld_name(CPUArchState *env, target_ulong addr, int mmu_idx,
                            uintptr_t retaddr)
{
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    uintptr_t haddr;
    DATA_TYPE res;

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
         != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0) {
            cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                                 mmu_idx, retaddr);
        }
#endif

#ifdef CONFIG_PODARCH
        PREFETCH_VDF(1);
#endif

        if (!VICTIM_TLB_HIT(ADDR_READ)) {
            tlb_fill(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                     mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    }

#ifdef CONFIG_PODARCH
    CHECK_N_POPULATE_IPACT(1);
#endif

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        hwaddr ioaddr;
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }
        ioaddr = env->iotlb[mmu_idx][index];

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        res = glue(io_read, SUFFIX)(env, ioaddr, addr, retaddr);
        res = TGT_LE(res);
        return res;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;
        DATA_TYPE res1, res2;
        unsigned shift;
    do_unaligned_access:
#ifdef ALIGNED_ONLY
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
#endif
        addr1 = addr & ~(DATA_SIZE - 1);
        addr2 = addr1 + DATA_SIZE;
        /* Note the adjustment at the beginning of the function.
           Undo that for the recursion.  */
        res1 = helper_le_ld_name(env, addr1, mmu_idx, retaddr + GETPC_ADJ);
        res2 = helper_le_ld_name(env, addr2, mmu_idx, retaddr + GETPC_ADJ);
        shift = (addr & (DATA_SIZE - 1)) * 8;

        /* Little-endian combine.  */
        res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
        return res;
    }

    /* Handle aligned access or unaligned access in the same page.  */
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
    }
#endif

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
#if DATA_SIZE == 1
    res = glue(glue(ld, LSUFFIX), _p)((uint8_t *)haddr);
#else
    res = glue(glue(ld, LSUFFIX), _le_p)((uint8_t *)haddr);
#endif
    return res;
}

#if DATA_SIZE > 1
#ifdef SOFTMMU_CODE_ACCESS
static __attribute__((unused))
#endif
WORD_TYPE helper_be_ld_name(CPUArchState *env, target_ulong addr, int mmu_idx,
                            uintptr_t retaddr)
{
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    uintptr_t haddr;
    DATA_TYPE res;

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
         != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0) {
            cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                                 mmu_idx, retaddr);
        }
#endif

#ifdef CONFIG_PODARCH
        PREFETCH_VDF(2);
#endif

        if (!VICTIM_TLB_HIT(ADDR_READ)) {
            tlb_fill(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                     mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    }

#ifdef CONFIG_PODARCH
    CHECK_N_POPULATE_IPACT(2);
#endif

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        hwaddr ioaddr;
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }
        ioaddr = env->iotlb[mmu_idx][index];

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        res = glue(io_read, SUFFIX)(env, ioaddr, addr, retaddr);
        res = TGT_BE(res);
        return res;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;
        DATA_TYPE res1, res2;
        unsigned shift;
    do_unaligned_access:
#ifdef ALIGNED_ONLY
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
#endif
        addr1 = addr & ~(DATA_SIZE - 1);
        addr2 = addr1 + DATA_SIZE;
        /* Note the adjustment at the beginning of the function.
           Undo that for the recursion.  */
        res1 = helper_be_ld_name(env, addr1, mmu_idx, retaddr + GETPC_ADJ);
        res2 = helper_be_ld_name(env, addr2, mmu_idx, retaddr + GETPC_ADJ);
        shift = (addr & (DATA_SIZE - 1)) * 8;

        /* Big-endian combine.  */
        res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
        return res;
    }

    /* Handle aligned access or unaligned access in the same page.  */
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
    }
#endif

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
    res = glue(glue(ld, LSUFFIX), _be_p)((uint8_t *)haddr);
    return res;
}
#endif /* DATA_SIZE > 1 */

DATA_TYPE
glue(glue(helper_ld, SUFFIX), MMUSUFFIX)(CPUArchState *env, target_ulong addr,
                                         int mmu_idx)
{
    return helper_te_ld_name (env, addr, mmu_idx, GETRA());
}

#ifndef SOFTMMU_CODE_ACCESS

/* Provide signed versions of the load routines as well.  We can of course
   avoid this for 64-bit data, or for 32-bit data on 32-bit host.  */
#if DATA_SIZE * 8 < TCG_TARGET_REG_BITS
WORD_TYPE helper_le_lds_name(CPUArchState *env, target_ulong addr,
                             int mmu_idx, uintptr_t retaddr)
{
    return (SDATA_TYPE)helper_le_ld_name(env, addr, mmu_idx, retaddr);
}

# if DATA_SIZE > 1
WORD_TYPE helper_be_lds_name(CPUArchState *env, target_ulong addr,
                             int mmu_idx, uintptr_t retaddr)
{
    return (SDATA_TYPE)helper_be_ld_name(env, addr, mmu_idx, retaddr);
}
# endif
#endif

static inline void glue(io_write, SUFFIX)(CPUArchState *env,
                                          hwaddr physaddr,
                                          DATA_TYPE val,
                                          target_ulong addr,
                                          uintptr_t retaddr)
{
    CPUState *cpu = ENV_GET_CPU(env);
    MemoryRegion *mr = iotlb_to_region(cpu, physaddr);

    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;
    if (mr != &io_mem_rom && mr != &io_mem_notdirty && !cpu_can_do_io(cpu)) {
        cpu_io_recompile(cpu, retaddr);
    }

    cpu->mem_io_vaddr = addr;
    cpu->mem_io_pc = retaddr;
    io_mem_write(mr, physaddr, val, 1 << SHIFT);
}

void helper_le_st_name(CPUArchState *env, target_ulong addr, DATA_TYPE val,
                       int mmu_idx, uintptr_t retaddr)
{
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    uintptr_t haddr;

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
        != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0) {
            cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                                 mmu_idx, retaddr);
        }
#endif

#ifdef CONFIG_PODARCH
        PREFETCH_VDF(3);
#endif
        if (!VICTIM_TLB_HIT(addr_write)) {
            tlb_fill(ENV_GET_CPU(env), addr, MMU_DATA_STORE, mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    }

#ifdef CONFIG_PODARCH
    CHECK_N_POPULATE_IPACT(3);
#endif

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        hwaddr ioaddr;
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }
        ioaddr = env->iotlb[mmu_idx][index];

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        val = TGT_LE(val);
        glue(io_write, SUFFIX)(env, ioaddr, val, addr, retaddr);
        return;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                     >= TARGET_PAGE_SIZE)) {
        int i;
    do_unaligned_access:
#ifdef ALIGNED_ONLY
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
#endif
        /* XXX: not efficient, but simple */
        /* Note: relies on the fact that tlb_fill() does not remove the
         * previous page from the TLB cache.  */
        for (i = DATA_SIZE - 1; i >= 0; i--) {
            /* Little-endian extract.  */
            uint8_t val8 = val >> (i * 8);
            /* Note the adjustment at the beginning of the function.
               Undo that for the recursion.  */
            glue(helper_ret_stb, MMUSUFFIX)(env, addr + i, val8,
                                            mmu_idx, retaddr + GETPC_ADJ);
        }
        return;
    }

    /* Handle aligned access or unaligned access in the same page.  */
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
    }
#endif

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
#if DATA_SIZE == 1
    glue(glue(st, SUFFIX), _p)((uint8_t *)haddr, val);
#else
    glue(glue(st, SUFFIX), _le_p)((uint8_t *)haddr, val);
#endif
}

#if DATA_SIZE > 1
void helper_be_st_name(CPUArchState *env, target_ulong addr, DATA_TYPE val,
                       int mmu_idx, uintptr_t retaddr)
{
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    uintptr_t haddr;

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
        != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0) {
            cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                                 mmu_idx, retaddr);
        }
#endif
#ifdef CONFIG_PODARCH
        PREFETCH_VDF(4);
#endif
        if (!VICTIM_TLB_HIT(addr_write)) {
            tlb_fill(ENV_GET_CPU(env), addr, MMU_DATA_STORE, mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    }

#ifdef CONFIG_PODARCH
    CHECK_N_POPULATE_IPACT(4);
#endif

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        hwaddr ioaddr;
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }
        ioaddr = env->iotlb[mmu_idx][index];

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        val = TGT_BE(val);
        glue(io_write, SUFFIX)(env, ioaddr, val, addr, retaddr);
        return;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                     >= TARGET_PAGE_SIZE)) {
        int i;
    do_unaligned_access:
#ifdef ALIGNED_ONLY
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
#endif
        /* XXX: not efficient, but simple */
        /* Note: relies on the fact that tlb_fill() does not remove the
         * previous page from the TLB cache.  */
        for (i = DATA_SIZE - 1; i >= 0; i--) {
            /* Big-endian extract.  */
            uint8_t val8 = val >> (((DATA_SIZE - 1) * 8) - (i * 8));
            /* Note the adjustment at the beginning of the function.
               Undo that for the recursion.  */
            glue(helper_ret_stb, MMUSUFFIX)(env, addr + i, val8,
                                            mmu_idx, retaddr + GETPC_ADJ);
        }
        return;
    }

    /* Handle aligned access or unaligned access in the same page.  */
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
    }
#endif

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
    glue(glue(st, SUFFIX), _be_p)((uint8_t *)haddr, val);
}
#endif /* DATA_SIZE > 1 */

void
glue(glue(helper_st, SUFFIX), MMUSUFFIX)(CPUArchState *env, target_ulong addr,
                                         DATA_TYPE val, int mmu_idx)
{
    helper_te_st_name(env, addr, val, mmu_idx, GETRA());
}

#endif /* !defined(SOFTMMU_CODE_ACCESS) */

#undef READ_ACCESS_TYPE
#undef SHIFT
#undef DATA_TYPE
#undef SUFFIX
#undef LSUFFIX
#undef DATA_SIZE
#undef ADDR_READ
#undef WORD_TYPE
#undef SDATA_TYPE
#undef USUFFIX
#undef SSUFFIX
#undef BSWAP
#undef TGT_BE
#undef TGT_LE
#undef CPU_BE
#undef CPU_LE
#undef helper_le_ld_name
#undef helper_be_ld_name
#undef helper_le_lds_name
#undef helper_be_lds_name
#undef helper_le_st_name
#undef helper_be_st_name
#undef helper_te_ld_name
#undef helper_te_st_name
