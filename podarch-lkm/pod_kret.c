/*
 * Author: Kunal Baweja
 * 
 * Module Name: pod_kret
 * Description: This is a kretprobe module which intercepts the load_elf_binary
 *              function (fs/binfmt_elf) called during ELF loading on a PodArch CPU,
 *              reads through the program and section headers of the binary to collect 
 *              pod specific metadata and key data required to set up the pod binary.
 * 
 * Usage: At time of development this module was written against the kernel version 4.0.5
 *        Compile it using the Makefile in the parent directory of this file by issuing the
 *        `make` command on terminal. Insert the module as `sudo insmod pod_kret.ko` on a 
 *        PodArch compliant CPU before running pod binaries. Normal binaries don't need this
 *        module for execution.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <asm/uaccess.h>
#include <asm/current.h>
#include <asm/param.h>

/* Macros defined for pod executables*/
#define KCAP_SIZE 256
#define POD_STACK_SIZE 0x40000
#define SEC_NAME_LEN 12

/* Pod global variables to initialise in entry handler and pass on to return handler */
unsigned char *pod_kcap = NULL;
unsigned long pod_start_intc_address, pod_start_intd_address, pod_start_ints_address;
unsigned long pod_start_intbrk_address, pod_start_intmmap_address, pod_start_intbss_address;
unsigned long pod_start_code_address, pod_end_code_address, pod_start_data_address;
unsigned long pod_end_data_address, pod_start_bss_address, pod_end_bss_address;
unsigned long stack_top_address=0;

/*Parse pod elf encryption key and pass on to the CPU
* Author: Kunal Baweja, bawejakunal15@gmail.com
*/
static unsigned char* elf_parse_binary_podkey(struct elfhdr *ehdr, struct file *file, char *section_name)
{

	loff_t file_sz;
	loff_t offset;
	unsigned char * key = NULL;
	int retval, i;
	size_t key_len;
	struct elf_shdr *elf_shtable, *elf_spnt, *elf_shstrpnt;
	unsigned int  shtable_sz;
	uint16_t shstrndx;
	bool found_podid_section = false;


	if (!ehdr->e_shnum)
		return NULL;

	if (ehdr->e_shstrndx == SHN_UNDEF)
		return NULL;

	/* Read in elf section table */
	file_sz = i_size_read(file->f_path.dentry->d_inode);
	shtable_sz = ehdr->e_shnum * sizeof(struct elf_shdr);
	elf_shtable = kmalloc(shtable_sz, GFP_KERNEL);
	if (!elf_shtable)
		return ERR_PTR(-ENOMEM);

	retval = kernel_read(file, ehdr->e_shoff, (char *)elf_shtable,
					shtable_sz);
	if (retval != shtable_sz) {
		if (retval >= 0)
			retval = -EIO;
		goto out_free_shtable;
	}

	if (ehdr->e_shstrndx == 0xffff)
		shstrndx = elf_shtable[0].sh_link;
	else
		shstrndx = ehdr->e_shstrndx;

	if (shstrndx >= ehdr->e_shnum) {
		retval = -EINVAL;
		goto out_free_shtable;
	}

	elf_shstrpnt = elf_shtable + shstrndx;
	elf_spnt = elf_shtable;

	/* Scan for section with name section_name */
	for (i = 0; i < ehdr->e_shnum; i++) {
		char sec_name[SEC_NAME_LEN];
		offset = elf_shstrpnt->sh_offset + elf_spnt->sh_name;
		retval = kernel_read(file, offset, sec_name, SEC_NAME_LEN);
		if (retval != SEC_NAME_LEN) {
			if(retval>0)
				retval = -EIO;
			goto out_free_shtable;
		}

		if(!strcmp(sec_name, section_name)) {
			found_podid_section = true;
			break;
		}
		elf_spnt++;
	}
	
	if (!found_podid_section) {
		/* File is not pod-enabled */
		retval = 0;		
		goto out_free_shtable;
	}
	
	key_len = KCAP_SIZE;
	if(key_len!=elf_spnt->sh_size){
		printk("Error: key_len != KCAP_SIZE\n");
		goto out_free_shtable;
	}
		
	key = kmalloc(key_len+1, GFP_KERNEL);
	offset = elf_spnt->sh_offset;
	retval = kernel_read(file, offset, key, key_len);
	if (retval != key_len) {
		key = NULL;
		if (retval >= 0)
			retval = -EIO;
		goto out_free_key;
	}
	kfree(elf_shtable);
    return key;

out_free_key:
	kfree(key);
out_free_shtable:
	kfree(elf_shtable);
	return NULL;
}

static unsigned long elf_pod_section_address(struct elfhdr *ehdr, struct file *file, char *section_name)
{ 
	loff_t file_sz, offset;
	int retval, i;
	struct elf_shdr *elf_shtable, *elf_spnt, *elf_shstrpnt;
	unsigned int  shtable_sz;
	uint16_t shstrndx;

	if (!ehdr->e_shnum)
		return 0;

	if (ehdr->e_shstrndx == SHN_UNDEF)
		return 0;

	/* Read in elf section table */
	file_sz = i_size_read(file->f_path.dentry->d_inode);
	shtable_sz = ehdr->e_shnum * sizeof(struct elf_shdr);
	elf_shtable = kmalloc(shtable_sz, GFP_KERNEL);
	if (!elf_shtable)
		return -ENOMEM;

	retval = kernel_read(file, ehdr->e_shoff, (char *)elf_shtable,
					shtable_sz);
	if (retval != shtable_sz) {
		if (retval >= 0)
			retval = -EIO;
		goto out_free_shtable;
	}

	if (ehdr->e_shstrndx == 0xffff)
		shstrndx = elf_shtable[0].sh_link;
	else
		shstrndx = ehdr->e_shstrndx;

	if (shstrndx >= ehdr->e_shnum) {
		retval = -EINVAL;
		goto out_free_shtable;
	}

	elf_shstrpnt = elf_shtable + shstrndx;
	elf_spnt = elf_shtable;

	/* Scan for section with name ".pod_inc" */
	for (i = 0; i < ehdr->e_shnum; i++)
	{
		char sec_name[SEC_NAME_LEN];
		offset = elf_shstrpnt->sh_offset + elf_spnt->sh_name;
		retval = kernel_read(file, offset, sec_name, SEC_NAME_LEN);
		//printk("%s--%d--%lu\n",sec_name,retval,sec_name_len);
		if (retval != SEC_NAME_LEN)
		{
			if(retval > 0)
				retval = -EIO;
			goto out_free_shtable;
		}

		if(!strcmp(sec_name, section_name))
			return elf_spnt->sh_addr;

		elf_spnt++;
	}

	retval = 0;
out_free_shtable:
	kfree(elf_shtable);
	return retval;
}

/* Kretprobe entry handler executes upon entry to the probed function i.e load_elf_binary here.
 * Extracts te `struct linux_bprm *bprm` argument passed on to load_elf_binary and uses that to
 * read through the program and section headers of the ELF to extract encryption/decryption metadata.
 * Sets the global variables `pod_kcap` and `pod_int_data` which are later referenced in `ret_handler`
 */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = 0;
	unsigned int i, size;
	struct linux_binprm *bprm = (struct linux_binprm *)(regs->r12);	//r12 contains the first arg of load_elf_binary
	struct{
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
	} *loc;
	struct elf_phdr *elf_ppnt, *elf_phdata;
	int POD_LOAD_SEG_NUM=1;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	loc = kmalloc(sizeof(*loc), GFP_KERNEL);
	if (!loc) {
		retval = -ENOMEM;
		goto out_ret;
	}

	/* Get the exec-header */
	loc->elf_ex = *((struct elfhdr *)bprm->buf);

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(&loc->elf_ex))
		goto out;
	if (!bprm->file->f_op || !bprm->file->f_op->mmap)
		goto out;

	retval = 0;

	/* Now read in all of the header information */
	if (loc->elf_ex.e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (loc->elf_ex.e_phnum < 1 ||
	 	loc->elf_ex.e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;
	size = loc->elf_ex.e_phnum * sizeof(struct elf_phdr);
	
	elf_phdata = kmalloc(size, GFP_KERNEL);
	if (!elf_phdata){
		retval = -ENOMEM;
		goto out;
	}
	retval = kernel_read(bprm->file, loc->elf_ex.e_phoff,(char *)elf_phdata, size);
	if (retval != size) {
		if (retval >= 0)
			retval = -EIO;
		goto out_free_ph;
	}
	retval = 0;	//bug fix entry_handler must always return 0

	pod_kcap = elf_parse_binary_podkey(&loc->elf_ex, bprm->file, ".pod_id");
	if (pod_kcap)
	{
		pod_start_intc_address    = elf_pod_section_address(&loc->elf_ex, bprm->file, ".intc");
		pod_start_intd_address    = elf_pod_section_address(&loc->elf_ex, bprm->file, ".intd");
		pod_start_ints_address    = elf_pod_section_address(&loc->elf_ex, bprm->file, ".ints");
		pod_start_intbrk_address  = elf_pod_section_address(&loc->elf_ex, bprm->file, ".intbrk");
		pod_start_intbss_address  = elf_pod_section_address(&loc->elf_ex, bprm->file, ".intbss");
		pod_start_intmmap_address = elf_pod_section_address(&loc->elf_ex, bprm->file, ".intmmap");
	
		for(i=0,elf_ppnt=elf_phdata; i < loc->elf_ex.e_phnum; elf_ppnt++, i++)
		{
			if (elf_ppnt->p_type != PT_LOAD)
				continue;
			if(POD_LOAD_SEG_NUM==1)	//first loadable segment
			{
				pod_start_code_address = elf_ppnt->p_vaddr;
				pod_end_code_address = pod_start_code_address + elf_ppnt->p_memsz;
				POD_LOAD_SEG_NUM++;	//increment to check for second
			}
			else if(POD_LOAD_SEG_NUM==2)
			{
				pod_start_data_address = elf_ppnt->p_vaddr;
				pod_end_data_address = pod_start_data_address + elf_ppnt->p_filesz;
				pod_start_bss_address = pod_end_data_address;
				pod_end_bss_address = pod_start_bss_address + elf_ppnt->p_memsz;
				break;	//break after checking second program header
			}
		}
	}

out_free_ph:
	kfree(elf_phdata);
out:
	kfree(loc);
out_ret:
	return retval;
}

/*
 * Return-probe handler: Uses the `pod_kcap` and `pod_start_int_address`
 * global variables initialised in the entry_handler and executes the 
 * `pod_load` CPU instruction to notify the CPU about the pod binary
 * and set up the pod environment.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (pod_kcap)
	{
		unsigned long long eax, edx, ebx, ecx;
        unsigned long long chunk;
		pgd_t *ebx_pgd;
	    unsigned char buffer[8];	
        // ======== POD_LOAD(cr3_value)============ //
		eax = 0;
        ebx_pgd = current->mm->pgd;
        ecx = 0;
        edx = 0;

		__asm__ __volatile__ (".byte 0xf1"
							  :
							  : "a"(eax), "b"(ebx_pgd), "c"(ecx), "d"(edx));


        // ======== POD_LOAD(kcap) ============== //

        /* We are doing in chunks as we have 2048-bit kcap and 64-bit register. */
        pod_kcap[KCAP_SIZE] = '\0';
        for (chunk = 0; chunk < 32; chunk++) {
            eax = 1;
            ebx = 0;
            ecx = chunk;
            edx = 0;

            memcpy(buffer, pod_kcap + 8 * chunk, 8);
            ebx = (uint64_t)buffer[0] << 56 |
                  (uint64_t)buffer[1] << 48 |
                  (uint64_t)buffer[2] << 40 |
                  (uint64_t)buffer[3] << 32 |
                  (uint64_t)buffer[4] << 24 |
                  (uint64_t)buffer[5] << 16 |
                  (uint64_t)buffer[6] << 8  |
                  (uint64_t)buffer[7];


            __asm__ __volatile__ (".byte 0xf1"
                                  :
                                  : "a"(eax), "b"(ebx), "c"(ecx), "d"(edx));
        }

        // ======== POD_LOAD(code_start, code_end, C_VDTB) ==== //
        eax = 2;
        ebx = pod_start_code_address + 0x1000;
        ecx = pod_end_code_address;
        edx = pod_start_intc_address;

        __asm__ __volatile__ (".byte 0xf1"
                              :
                              : "a"(eax), "b"(ebx), "c"(ecx), "d"(edx));

        // ======== POD_LOAD(data_start, data_end, D_VDTB) ==== //
        eax = 2;
        ebx = pod_start_data_address;
        ecx = pod_end_data_address;
        edx = pod_start_intd_address;

        __asm__ __volatile__ (".byte 0xf1"
                              :
                              : "a"(eax), "b"(ebx), "c"(ecx), "d"(edx));

        // ======== POD_LOAD(bss_start, bss_end, BSS_VDTB) ==== //
        eax = 4;
        ebx = (pod_start_bss_address & PAGE_MASK) + 0x1000;
        ecx = pod_end_bss_address;
        edx = pod_start_intbss_address;
        __asm__ __volatile__ (".byte 0xf1"
                              :
                              : "a"(eax), "b"(ebx), "c"(ecx), "d"(edx));


        // ======== POD_LOAD(stack_start, stack_end, S_VDTB) ==== //
        eax = 3;
        ebx = stack_top_address - POD_STACK_SIZE;
        ecx = stack_top_address;
        edx = pod_start_ints_address;
        __asm__ __volatile__ (".byte 0xf1"
                              :
                              : "a"(eax), "b"(ebx), "c"(ecx), "d"(edx));


        // ======== POD_LOAD(brk_VDTB, mmap_VDTB) ==== //
        eax = 5;
        ebx = pod_start_intbrk_address;
        ecx = pod_start_intmmap_address;
        edx = 0;
        __asm__ __volatile__ (".byte 0xf1"
                              :
                              : "a"(eax), "b"(ebx), "c"(ecx), "d"(edx));

		kfree(pod_kcap);
	}

	return 0;
}

//setup_arg_pages() kretprobe handler
int setup_arg_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
	stack_top_address = (unsigned long)(regs->r12);	//set the global variable to use in kretprobe return handler
	return 0;
}

//empty return handler needed by the kreturn probe specifications
int setup_arg_return_handler(struct kretprobe_instance *ri, struct pt_regs *regs){
	return 0;
}


//load_elf_binary return probe
static struct kretprobe pod_kretprobe = {
	.handler		= ret_handler,
	.entry_handler		= entry_handler,
	.kp = {
		.symbol_name = "load_elf_binary",
	},
	/* Probe up to NR_CPUS instances concurrently. */
	.maxactive		= NR_CPUS,
};

//setup_arg_pages kretprobe
static struct kretprobe setup_arg_kretprobe = {
	.handler = setup_arg_return_handler,
	.entry_handler = setup_arg_entry_handler,
	.kp = {
		.symbol_name	= "setup_arg_pages",
	},
	.maxactive		= NR_CPUS,
};

/* Register probes */
static int __init kretprobe_init(void)
{
	int ret;

	//register kretprobe for load_elf_binary
	ret = register_kretprobe(&pod_kretprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n",
				ret);
		return -1;
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n",
			pod_kretprobe.kp.symbol_name, pod_kretprobe.kp.addr);

	//register kretprobe on setup_arg_pages
	ret = register_kretprobe(&setup_arg_kretprobe);
	if(ret < 0){
		printk(KERN_INFO "register_kretprobe failed, returned %d\n",ret);
		return -1;
	}
	printk(KERN_INFO "Planted kretprobe at %s: %p\n",
		setup_arg_kretprobe.kp.symbol_name, setup_arg_kretprobe.kp.addr);

	return 0;
}

/* Unregister probes */
static void __exit kretprobe_exit(void)
{
	unregister_kretprobe(&setup_arg_kretprobe);
	printk(KERN_INFO "kretprobe at %p unregistered\n",
		setup_arg_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	printk(KERN_INFO "Missed probing %d instances of %s\n",
		setup_arg_kretprobe.nmissed, setup_arg_kretprobe.kp.symbol_name);

	unregister_kretprobe(&pod_kretprobe);
	printk(KERN_INFO "kretprobe at %p unregistered\n",
			pod_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	printk(KERN_INFO "Missed probing %d instances of %s\n",
		pod_kretprobe.nmissed, pod_kretprobe.kp.symbol_name);


}

module_init(kretprobe_init);
module_exit(kretprobe_exit);
MODULE_LICENSE("GPL");
