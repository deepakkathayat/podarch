/*
 * USAGE:
 * -----
 * > gcc -o get_pod_int get_pod_int.c -lcrypto
 * 
 * Gets integrity tags for code, data and bss segments
 * Puts placeholder tags for stack and heap [brk and mmap]
 *
 * Created by Deepak Kathayat, Viswesh
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <byteswap.h>
#include <elf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdbool.h>
#include <endian.h>

struct signelf_info {
	char *in_file, *out_file, *privkey_file, *certificate_file;
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdr;
	unsigned char *integrityc;
    unsigned char *integrityd;
    unsigned char *integritys;
    unsigned char *integritybss;
    unsigned char *integritymmap;
    unsigned char *integritybrk;
	unsigned int integrity_lenc;
    unsigned int integrity_lend;
    unsigned int integrity_lenbss;
    unsigned int integrity_lenmmap;
    unsigned int integrity_lens;
    unsigned int integrity_lenbrk;
	unsigned char *pod_key;
	};

/*
 * Contains the encrypted application key which gets into a section.
 * objcopy uses it
 */
char *tempkeysection_file = "/tmp/makepod.keysection";

/*
 * Contains the integrity which gets into a section.
 * objcopy uses it
 */
char *tempintsection_filec    = "./podintc";
char *tempintsection_filed    = "./podintd";
char *tempintsection_files    = "./podints";
char *tempintsection_filebss  = "./podintbss";
char *tempintsection_filebrk  = "./podintbrk";
char *tempintsection_filemmap = "./podintmmap";

size_t get_file_offset(struct signelf_info *sinfo)
{
    int fd = open(sinfo->in_file, O_RDWR);

    Elf64_Ehdr *ehdr = &sinfo->ehdr;
    size_t rem_file_sz, file_sz;
    size_t offset;
    int retval, i;
    unsigned int int_len;
    unsigned int write_len;
    Elf64_Shdr *elf_shtable, *elf_spnt, *elf_shstrpnt;
    unsigned int  shtable_sz;
    uint16_t shstrndx;
    bool found_podid_section = false;

    if (!ehdr->e_shnum) {
        return 0;
    }
    if (ehdr->e_shstrndx == SHN_UNDEF) {
        return 0;
    }
    /* Read in elf section table */
    shtable_sz = ehdr->e_shnum * sizeof(Elf64_Shdr);
    elf_shtable = malloc(shtable_sz);
    if (!elf_shtable) {
        return 0;
    }

    retval = pread(fd, elf_shtable,shtable_sz, ehdr->e_shoff);
    if (retval != shtable_sz) {
        if (retval >= 0)
            retval = -EIO;
    }

    shstrndx = ehdr->e_shstrndx;

    if (shstrndx >= ehdr->e_shnum) {
        retval = -EINVAL;
        goto out_free_shtable;
    }

    elf_shstrpnt = elf_shtable + shstrndx;
    elf_spnt = elf_shtable;

    /* Scan for section with name ".bss */
    for (i = 0; i < ehdr->e_shnum; i++) {
        char sec_name[5];
        offset = elf_shstrpnt->sh_offset + elf_spnt->sh_name;
        retval = pread(fd, sec_name, 5, offset);

        if(!strcmp(sec_name, ".bss")) {
            found_podid_section = true;
            break;
        }
        elf_spnt++;
    }
    
    if (!found_podid_section) {
        retval = 0;
        printf("Not found bss\n");
        goto out_free_shtable;
    }
    else
        printf("Found bss\n");
    
    offset = elf_spnt->sh_offset;

out_free_shtable:
    return offset;
}
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ELFDATANATIVE ELFDATA2LSB
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ELFDATANATIVE ELFDATA2MSB
#else
#error "Unknown machine endian"
#endif

static uint16_t file16_to_cpu(struct signelf_info *sinfo, uint16_t val)
{
	if (sinfo->ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_16(val);
	return val;
}

static uint32_t file32_to_cpu(struct signelf_info *sinfo, uint32_t val)
{
	if (sinfo->ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_32(val);
	return val;
}

static uint64_t file64_to_cpu(struct signelf_info *sinfo, uint64_t val)
{
	if (sinfo->ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_64(val);
	return val;
}

static int read_elf32(struct signelf_info *sinfo, int fd)
{
	Elf32_Ehdr ehdr32;
	Elf32_Phdr *phdr32;
	size_t phdrs32_size;
	ssize_t ret = 0, i;

	ret = pread(fd, &ehdr32, sizeof(ehdr32), 0);
	if (ret != sizeof(ehdr32)) {
		fprintf(stdout, "Read of Elf header failed: %s\n",
			strerror(errno));
		return 1;
	}

	sinfo->ehdr.e_type	= file16_to_cpu(sinfo, ehdr32.e_type);
	sinfo->ehdr.e_machine	= file16_to_cpu(sinfo, ehdr32.e_machine);
	sinfo->ehdr.e_version	= file32_to_cpu(sinfo, ehdr32.e_version);
	sinfo->ehdr.e_entry	= file32_to_cpu(sinfo, ehdr32.e_entry);
	sinfo->ehdr.e_phoff	= file32_to_cpu(sinfo, ehdr32.e_phoff);
	sinfo->ehdr.e_shoff	= file32_to_cpu(sinfo, ehdr32.e_shoff);
	sinfo->ehdr.e_flags	= file32_to_cpu(sinfo, ehdr32.e_flags);
	sinfo->ehdr.e_ehsize	= file16_to_cpu(sinfo, ehdr32.e_ehsize);
	sinfo->ehdr.e_phentsize= file16_to_cpu(sinfo, ehdr32.e_phentsize);
	sinfo->ehdr.e_phnum	= file16_to_cpu(sinfo, ehdr32.e_phnum);
	sinfo->ehdr.e_shentsize= file16_to_cpu(sinfo, ehdr32.e_shentsize);
	sinfo->ehdr.e_shnum	= file16_to_cpu(sinfo, ehdr32.e_shnum);
	sinfo->ehdr.e_shstrndx	= file16_to_cpu(sinfo, ehdr32.e_shstrndx);

	if (sinfo->ehdr.e_version != EV_CURRENT) {
		fprintf(stdout, "Bad Elf header version %u\n",
			sinfo->ehdr.e_version);
		return 1;
	}
	if (sinfo->ehdr.e_phentsize != sizeof(Elf32_Phdr)) {
		fprintf(stdout, "Bad Elf program header size %u expected %zu\n",
			sinfo->ehdr.e_phentsize, sizeof(Elf32_Phdr));
		return 1;
	}
	phdrs32_size = sinfo->ehdr.e_phnum * sizeof(Elf32_Phdr);
	phdr32 = calloc(sinfo->ehdr.e_phnum, sizeof(Elf32_Phdr));
	if (!phdr32) {
		fprintf(stdout, "Calloc of %u phdrs32 failed: %s\n",
			sinfo->ehdr.e_phnum, strerror(errno));
		return 1;
	}

	sinfo->phdr = calloc(sinfo->ehdr.e_phnum, sizeof(Elf64_Phdr));
	if (!sinfo->phdr) {
		fprintf(stdout, "Calloc of %u phdrs failed: %s\n",
			sinfo->ehdr.e_phnum, strerror(errno));
		ret = 1;
		goto out_free_phdr32;
	}
	ret = pread(fd, phdr32, phdrs32_size, sinfo->ehdr.e_phoff);
	if (ret < 0 || (size_t)ret != phdrs32_size) {
		fprintf(stdout, "Read of program header  <at>  0x%llu for %zu bytes failed: %s\n",
			(unsigned long long)sinfo->ehdr.e_phoff, phdrs32_size, strerror(errno));
		ret = 1;
		goto out_free_phdr;
	}
	for (i = 0; i < sinfo->ehdr.e_phnum; i++) {
		sinfo->phdr[i].p_type = file32_to_cpu(sinfo, phdr32[i].p_type);
		sinfo->phdr[i].p_offset = file32_to_cpu(sinfo,
						phdr32[i].p_offset);
		sinfo->phdr[i].p_vaddr = file32_to_cpu(sinfo,
						phdr32[i].p_vaddr);
		sinfo->phdr[i].p_paddr = file32_to_cpu(sinfo,
						phdr32[i].p_paddr);
		sinfo->phdr[i].p_filesz = file32_to_cpu(sinfo,
						phdr32[i].p_filesz);
		sinfo->phdr[i].p_memsz = file32_to_cpu(sinfo,
						phdr32[i].p_memsz);
		sinfo->phdr[i].p_flags = file32_to_cpu(sinfo,
						phdr32[i].p_flags);
		sinfo->phdr[i].p_align = file32_to_cpu(sinfo,
						phdr32[i].p_align);
	}
	free(phdr32);
	return ret;

out_free_phdr:
	free(sinfo->phdr);
out_free_phdr32:
	free(phdr32);
	return ret;
}

static int read_elf64(struct signelf_info *sinfo, int fd)
{
	Elf64_Ehdr ehdr64;
	Elf64_Phdr *phdr64;
	size_t phdrs_size;
	ssize_t ret, i;

	ret = pread(fd, &ehdr64, sizeof(ehdr64), 0);
	if (ret < 0 || (size_t)ret != sizeof(sinfo->ehdr)) {
		fprintf(stdout, "Read of Elf header failed: %s\n",
			strerror(errno));
		return 1;
	}

	sinfo->ehdr.e_type	    = file16_to_cpu(sinfo, ehdr64.e_type);
	sinfo->ehdr.e_machine	= file16_to_cpu(sinfo, ehdr64.e_machine);
	sinfo->ehdr.e_version	= file32_to_cpu(sinfo, ehdr64.e_version);
	sinfo->ehdr.e_entry	    = file64_to_cpu(sinfo, ehdr64.e_entry);
	sinfo->ehdr.e_phoff	    = file64_to_cpu(sinfo, ehdr64.e_phoff);
	sinfo->ehdr.e_shoff	    = file64_to_cpu(sinfo, ehdr64.e_shoff);
	sinfo->ehdr.e_flags	    = file32_to_cpu(sinfo, ehdr64.e_flags);
	sinfo->ehdr.e_ehsize	= file16_to_cpu(sinfo, ehdr64.e_ehsize);
	sinfo->ehdr.e_phentsize	= file16_to_cpu(sinfo, ehdr64.e_phentsize);
	sinfo->ehdr.e_phnum	    = file16_to_cpu(sinfo, ehdr64.e_phnum);
	sinfo->ehdr.e_shentsize	= file16_to_cpu(sinfo, ehdr64.e_shentsize);
	sinfo->ehdr.e_shnum	    = file16_to_cpu(sinfo, ehdr64.e_shnum);
	sinfo->ehdr.e_shstrndx	= file16_to_cpu(sinfo, ehdr64.e_shstrndx);

	if (sinfo->ehdr.e_version != EV_CURRENT) {
		fprintf(stdout, "Bad Elf header version %u\n",
			sinfo->ehdr.e_version);
		return 1;
	}
	if (sinfo->ehdr.e_phentsize != sizeof(Elf64_Phdr)) {
		fprintf(stdout, "Bad Elf program header size %u expected %zu\n",
			sinfo->ehdr.e_phentsize, sizeof(Elf64_Phdr));
		return 1;
	}
	phdrs_size = sinfo-> ehdr.e_phnum * sizeof(Elf64_Phdr);
	phdr64 = calloc(sinfo->ehdr.e_phnum, sizeof(Elf64_Phdr));
	if (!phdr64) {
		fprintf(stdout, "Calloc of %u phdrs64 failed: %s\n",
			sinfo->ehdr.e_phnum, strerror(errno));
		return 1;
	}
	sinfo->phdr = calloc(sinfo->ehdr.e_phnum, sizeof(Elf64_Phdr));
	if (!sinfo->phdr) {
		fprintf(stdout, "Calloc of %u phdrs failed: %s\n",
			sinfo->ehdr.e_phnum, strerror(errno));
		ret = 1;
		goto out_free_phdr64;
	}
	ret = pread(fd, phdr64, phdrs_size, sinfo->ehdr.e_phoff);
	if (ret < 0 || (size_t)ret != phdrs_size) {
		fprintf(stdout, "Read of program header  <at>  %llu for %zu bytes failed: %s\n",
			(unsigned long long)(sinfo->ehdr.e_phoff), phdrs_size, strerror(errno));
		ret = 1;
		goto out_free_phdr;
	}
	for (i = 0; i < sinfo->ehdr.e_phnum; i++) {
		sinfo->phdr[i].p_type = file32_to_cpu(sinfo, phdr64[i].p_type);
		sinfo->phdr[i].p_flags = file32_to_cpu(sinfo,
						phdr64[i].p_flags);
		sinfo->phdr[i].p_offset = file64_to_cpu(sinfo,
						phdr64[i].p_offset);
		sinfo->phdr[i].p_vaddr = file64_to_cpu(sinfo,
						phdr64[i].p_vaddr);
		sinfo->phdr[i].p_paddr = file64_to_cpu(sinfo,
						phdr64[i].p_paddr);
		sinfo->phdr[i].p_filesz = file64_to_cpu(sinfo,
						phdr64[i].p_filesz);
		sinfo->phdr[i].p_memsz = file64_to_cpu(sinfo,
						phdr64[i].p_memsz);
		sinfo->phdr[i].p_align = file64_to_cpu(sinfo,
						phdr64[i].p_align);
	}
	free(phdr64);
	return ret;

out_free_phdr:
	free(sinfo->phdr);
out_free_phdr64:
	free(phdr64);
	return ret;
}



#define PTLEN  4096
#define TAGLEN 16 
#define IVLEN  12 
#define AADLEN 20
#define KEYLEN 16
#define BUFLEN 4

static const unsigned char AAD[AADLEN] = { 
	0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
	0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
	0xab,0xad,0xda,0xd2
};

static const unsigned char IV[IVLEN] = { 
	0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
};

static int encrypt_and_hash_elfc(struct signelf_info *sinfo){


	const EVP_CIPHER *gcm = EVP_aes_128_gcm();
	unsigned char *tmp_ptr = NULL;
	unsigned char *integritybuf = NULL; 
	unsigned char* bufbuf = NULL;
	unsigned int currentintsize = 0;
	unsigned int currentbufsize = 0;
	unsigned char *ctbuf; 
	unsigned char tagbuf[TAGLEN]; 
	int page_count = 0;
	unsigned char *CT; 
	unsigned int buf_len;
	unsigned int write_len;
	unsigned char *buf;
	
	int i, z, y;
	size_t sz = 0, sz_done = 0, sz_rem = 0;
	int ret;
	int first_segment = 1;

	int fd = open(sinfo->out_file, O_RDWR);
	if (fd < 0) {
		fprintf(stdout, "Cannot open %s: %s\n",
				sinfo->out_file, strerror(errno));
		return 1;
	}

	for (i = 0; i < sinfo->ehdr.e_phnum, first_segment!=0; i++) {

		if (sinfo->phdr[i].p_type != PT_LOAD)
			continue;

        page_count = 0;		
		loff_t offset;
		size_t to_read;
		offset = sinfo->phdr[i].p_offset;
		sz = sinfo->phdr[i].p_filesz;
		
		if (first_segment) {
			first_segment = 0;
			offset = offset + 4096;
			sz = sz - 4096;
		}
		else {
            sz_done = 0;
        }

		sz_rem = sz;
		to_read = PTLEN;
		sz_done = 0;

		while (sz_rem) {
			if (sz_rem < to_read)
				to_read = sz_rem;
			int howmany, dec_success, len,howmany1;

			buf = (unsigned char*)malloc(PTLEN);	
			memset(buf, 0, PTLEN);
			buf_len = pread(fd,(unsigned char*) buf,to_read, offset);
			if (buf_len == -1) {
				fprintf(stdout, "Failed to read:%s\n",
						strerror(errno));
				return 1;
			}
			
			if (buf_len != to_read) {
				fprintf(stdout, "Failed to read %lu bytes."
						" Read %u bytes:%s\n",
						to_read, buf_len, strerror(errno));
				return 1;
			}

			if (buf_len == 0)
				break;
			CT = (unsigned char*)malloc(PTLEN);	
			memset(CT, 0, PTLEN);
			EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			EVP_EncryptInit (ctx, gcm, sinfo->pod_key, IV);
			EVP_EncryptUpdate (ctx, NULL, &howmany, AAD, AADLEN);

			/* Process the plaintext */
			EVP_EncryptUpdate (ctx, CT, &howmany, buf, buf_len);
			
            /* Write ciphertext back to file*/
            write_len = pwrite(fd, (unsigned char*)CT, buf_len, offset);
			if (write_len == -1) {
				fprintf(stdout, "Failed to write:%s\n",
						strerror(errno));
				return 1;
			}

			if (write_len != buf_len) {
				fprintf(stdout, "Failed to write %du bytes."
						"Read %u bytes:%s\n", buf_len, write_len, strerror(errno));
				return 1;
			}

			if (write_len == 0){
				printf("write_len=0, Aborting\n");
				break;
			}
			EVP_EncryptFinal (ctx, tagbuf, &howmany);
			EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, TAGLEN, tagbuf);
			EVP_CIPHER_CTX_free(ctx);
			

			tmp_ptr = realloc(integritybuf, currentintsize + TAGLEN + BUFLEN + 12);
			if (tmp_ptr == NULL) {
				printf("Failed to catch integrity\n");
				return 1;
			}
			integritybuf = tmp_ptr;
			tmp_ptr = NULL;
			for(z=0; z<TAGLEN; z++)
				integritybuf[currentintsize+z] = tagbuf[z];

			unsigned char tempbuflen[5];
			int nlen = snprintf(tempbuflen, 5, "%04d", buf_len);

			for(z=0;z<BUFLEN;z++)
				integritybuf[currentintsize+TAGLEN+z] = tempbuflen[z];
			
			printf("START %d: *",(page_count));
			for(z=currentintsize; z<(currentintsize+TAGLEN);z++){
			 	printf("(%x)",(unsigned char)integritybuf[z]);
			}
			printf("*\n");

			free(CT);
			currentintsize = currentintsize+TAGLEN+BUFLEN+12;
			free(buf);			
			sz_rem -= buf_len;
			sz_done += buf_len;
			offset += buf_len;

			to_read = sz_rem;
			if (to_read > PTLEN)
				to_read = PTLEN;

			page_count++;
		}
		 
		if (sz_done != sz) {
			fprintf(stdout, "Could not encrypt %lu bytes. Encrypted"
					" only %lu bytes\n", sz, sz_done);
			return 1;
		}
	
	}
	
	sinfo->integrityc = (unsigned char*)malloc(currentintsize);
	sinfo->integrity_lenc = currentintsize;
	
	int j;
	for(j=0; j < currentintsize; j++)
		sinfo->integrityc[j] = integritybuf[j];

#ifdef DEBUG
	print_digest(sinfo);
#endif
	return 0;
}

static int encrypt_and_hash_elfd (struct signelf_info *sinfo)
{
	const EVP_CIPHER *gcm = EVP_aes_128_gcm();
	unsigned char *tmp_ptr = NULL;
	unsigned char *integritybuf = NULL; 
	unsigned char* bufbuf = NULL;
	unsigned int currentintsize = 0;
	unsigned int currentbufsize = 0;
	unsigned char *ctbuf; 
	unsigned char tagbuf[TAGLEN]; 
	int page_count = 0;
	unsigned char *CT; 
	unsigned int buf_len;
	unsigned int write_len;
	unsigned char *buf;
	
	int i,z,y;
	size_t sz = 0, sz_done = 0, sz_rem = 0;
	int ret;
	int first_segment = 1;
    int sec_segment = 1;

	int fd = open(sinfo->out_file, O_RDWR);
	if (fd < 0) {
		fprintf(stdout, "Cannot open %s: %s\n",
				sinfo->out_file, strerror(errno));
		return 1;
	}

	for (i = 0; i < sinfo->ehdr.e_phnum, sec_segment != 0; i++) {

		if (sinfo->phdr[i].p_type != PT_LOAD)
			continue;

        page_count = 0;		
		loff_t offset;
		size_t to_read;
		offset = sinfo->phdr[i].p_offset;
		sz = sinfo->phdr[i].p_filesz;
	
		if (first_segment) {
			first_segment = 0;
			offset = offset + 4096;
			sz = sz - 4096;
            continue;
		}
		else {
            sz = get_file_offset(sinfo) - offset;
            printf("0x%lx SIZE: 0x%lx\n", offset, sz);
            sec_segment = 0;
        }

		sz_rem = sz;
		to_read = PTLEN;
		sz_done = 0;

		while (sz_rem) {
			if (sz_rem < to_read)
				to_read = sz_rem;
			int howmany, dec_success, len,howmany1;

			buf = (unsigned char*)malloc(PTLEN);	
			memset(buf, 0, PTLEN);
			buf_len = pread(fd,(unsigned char*) buf,to_read, offset);
			if (buf_len == -1) {
				fprintf(stdout, "Failed to read:%s\n",
						strerror(errno));
				return 1;
			}

			if (buf_len != to_read) {
				fprintf(stdout, "Failed to read %lu bytes."
						" Read %u bytes:%s\n",
						to_read, buf_len, strerror(errno));
				return 1;
			}

			if (buf_len == 0)
				break;
			CT = (unsigned char*) malloc(PTLEN);	
			memset(CT, 0, PTLEN);
			EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			EVP_EncryptInit (ctx, gcm, sinfo->pod_key, IV);
			EVP_EncryptUpdate (ctx, NULL, &howmany, AAD, AADLEN);

			/* Process the plaintext */
			EVP_EncryptUpdate (ctx, CT, &howmany, buf, buf_len);
			
			
            /*	Write ciphertext back to file*/
            write_len = pwrite(fd, (unsigned char*)CT, buf_len, offset);
			if (write_len == -1) {
				fprintf(stdout, "Failed to write:%s\n",
						strerror(errno));
				return 1;
			}

			if (write_len != buf_len) {
				fprintf(stdout, "Failed to write %du bytes."
						"Read %u bytes:%s\n", buf_len, write_len, strerror(errno));
				return 1;
			}

			if (write_len == 0){
				printf("write_len=0, Aborting\n");
				break;
			}
			EVP_EncryptFinal (ctx, tagbuf, &howmany);
			EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, TAGLEN, tagbuf);
			EVP_CIPHER_CTX_free(ctx);
			

			tmp_ptr = realloc(integritybuf, currentintsize + TAGLEN + BUFLEN + 12);
			if (tmp_ptr == NULL) {
				printf("Failed to catch integrity\n");
				return 1;
			}
			integritybuf = tmp_ptr;
			tmp_ptr = NULL;
			for(z = 0; z < TAGLEN; z++)
				integritybuf[currentintsize+z] = tagbuf[z];

			unsigned char tempbuflen[5];
			int nlen = snprintf(tempbuflen, 5, "%04d", buf_len);

			for(z = 0; z < BUFLEN; z++)
				integritybuf[currentintsize+TAGLEN+z] = tempbuflen[z];
			
			printf("START %d: *",(page_count));
			for(z = currentintsize; z < (currentintsize + TAGLEN); z++){
			 	printf("(%x)",(unsigned char)integritybuf[z]);
			}
			printf("*\n");

			free(CT);
			currentintsize = currentintsize+TAGLEN+BUFLEN+12;
			free(buf);			
			sz_rem  -= buf_len;
			sz_done += buf_len;
			offset  += buf_len;

			to_read = sz_rem;
			if (to_read > PTLEN)
				to_read = PTLEN;

			page_count++;
		}
		 
		if (sz_done != sz) {
			fprintf(stdout, "Could not encrypt %lu bytes. Encrypted"
					" only %lu bytes\n", sz, sz_done);
			return 1;
		}
	
	}
	
	sinfo->integrityd = (unsigned char*)malloc(currentintsize);
	sinfo->integrity_lend = currentintsize;
	
	int j;
	for(j = 0; j < currentintsize; j++)
		sinfo->integrityd[j] = integritybuf[j];
	
#ifdef DEBUG
	print_digest(sinfo);
#endif
	return 0;
}

unsigned char* fill_zero_buffer(unsigned int size)
{
    unsigned char* integritybuf = NULL;
    unsigned char* tmp_ptr = NULL;
    int currentintsize = 0;
    int z;
    int buf_len;
    printf("fill_zero_buffer() %d\n", size);

    int sz_done = 0;
    while(sz_done < size) {
        sz_done = sz_done + 0x1000;
        buf_len = 0x1000;
        if (sz_done > size)
            buf_len = size % 4096;

        tmp_ptr = realloc(integritybuf, currentintsize + TAGLEN + BUFLEN + 12);
        integritybuf = tmp_ptr;
        tmp_ptr = NULL;
        for(z = 0; z < TAGLEN; z++)
            integritybuf[currentintsize + z] = 0;

        unsigned char tempbuflen[5];
        int nlen = snprintf(tempbuflen, 5, "%04d", buf_len);

        for(z = 0; z < BUFLEN; z++)
            integritybuf[currentintsize + TAGLEN + z] = tempbuflen[z];

        currentintsize = currentintsize + TAGLEN + BUFLEN + 12;
    }
    return integritybuf;
}

void create_hash_space(struct signelf_info *sinfo)
{

    unsigned int bss_size;
    /*
     ############## USER INPUT ######################
     #                                              #
     # We will need to specify the upper bounds of  #
     # the segment sizes so as to put corresponding #
     # placeholders for integrity tags              #
     #                                              #
     ################################################
    */
    unsigned int stack_size = 0x80000;
    unsigned int mmap_size  = 0x8000000;
    unsigned int brk_size   = 0x80000;

    int i, first_segment = 1;
    for (i = 0; i < sinfo->ehdr.e_phnum; i++) {

        if (sinfo->phdr[i].p_type != PT_LOAD)
            continue;

        if (first_segment == 1) {
            first_segment = 0;
            continue;
        }

        bss_size = sinfo->phdr[i].p_memsz - sinfo->phdr[i].p_filesz;
        break;
    }
    bss_size += 0x1000;
    sinfo->integritybss = (unsigned char*) fill_zero_buffer(bss_size);
    sinfo->integrity_lenbss = bss_size/ 128;

    sinfo->integritys = (unsigned char*) fill_zero_buffer(stack_size);
    sinfo->integrity_lens = stack_size/ 128;

    sinfo->integritymmap = (unsigned char*) fill_zero_buffer(mmap_size);
    sinfo->integrity_lenmmap = mmap_size/ 128;

    sinfo->integritybrk = (unsigned char*) fill_zero_buffer(brk_size);
    sinfo->integrity_lenbrk = brk_size /128;

}

static int read_pod_key(struct signelf_info *sinfo)
{
	/* allocate memory for signature */
	sinfo->pod_key = (unsigned char*)malloc(KEYLEN);

	/* Read pod application key from file */
	FILE *keyfd = fopen(sinfo->privkey_file, "r");
	if(keyfd != NULL) {
		if(fgets(sinfo->pod_key, KEYLEN + 1, keyfd ) == NULL) {
			printf("Error: Cannot read key from key file\n");
			fclose(keyfd);
			return 1;
		}
	}
    fclose(keyfd);
	return 0;
}


RSA *createRSA(char *key, int public)
{
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
    {
        printf("Failed to create key BIO");
        exit(1);
    }

    if (public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    if (rsa == NULL)
    {
        printf("Failed to create RSA");
        exit(1);
    }

    return rsa;
}

int public_encrypt(unsigned char *data, int data_len, 
                   char *key, unsigned char *encrypted)
{
    RSA *rsa   = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted,
                                    rsa, RSA_PKCS1_PADDING);
    return result;
}

void printLastError(const char *msg)
{
    char *err = malloc(130);
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
}

static int add_podkey_in_a_section(struct signelf_info *sinfo)
{
	FILE *outfp   = NULL;
    FILE *handler = NULL;
	int ret = 0, exit_code;
	unsigned int written;
    size_t read_size, string_size;
    char *publicKey = NULL;
	char command[1024];
    unsigned char encrypted[4098] = {};

    /* We will need to encrypt kapp with kpub */
    handler = fopen(sinfo->certificate_file, "r");
    if (handler) {
        // Scan to find the length of buffer
        fseek(handler, 0, SEEK_END);
        string_size = ftell(handler);
        rewind(handler);

        publicKey = (char*) malloc (sizeof(char) * (string_size + 1));
        read_size = fread(publicKey, sizeof(char), string_size, handler);
        if (read_size != string_size) {
            printf("Something wrong while reading public key\n");
            exit(1);
        }
        publicKey[string_size] = '\0';
        fclose(handler);
    } else {
        printf("Public key not found\n");
        exit(1);
    }


    int encrypted_length = public_encrypt(sinfo->pod_key, strlen(sinfo->pod_key),
                                          publicKey, encrypted);
    if (encrypted_length == -1)
    {
        printLastError("Public Encrypt failed");
        exit(1);
    }

	outfp = fopen(tempkeysection_file, "w");
	if (!outfp) {
		fprintf(stdout, "Failed to open %s:%s\n", tempkeysection_file,
				strerror(errno));
		return 1;
	}

	/* Write encrypted key i.e. kcap into temp file */
	written = fwrite(encrypted, 1, encrypted_length, outfp);
	if (written != encrypted_length) {
		fprintf(stdout, "Failed to write pod kcap to file %s\n",
				tempkeysection_file);
		ret = 1;
		goto out_close_outfp;
	}

	/* Add pod_id section */
	fclose(outfp);
	snprintf(command, 1024, "objcopy --add-section .pod_id=%s %s %s", tempkeysection_file, sinfo->in_file, sinfo->out_file);
	ret = system(command);
	if (ret == -1) {
		fprintf(stdout, "Failed to execute system(%s)\n", command);
		goto out_close_outfp;
	}

	exit_code = WEXITSTATUS(ret);
	ret = exit_code;
	if (ret)
		goto out_close_outfp;
	return ret;
out_close_outfp:
	fclose(outfp);
	return ret;
}

static int add_integrity_in_a_section(struct signelf_info *sinfo, int skip_data)
{
	FILE *outfp;
	int ret = 0, exit_code;
	unsigned int written;
	char command[1024];

    // ===================== CODE  START ========================== //
	outfp = fopen(tempintsection_filec, "w");
	if (!outfp) {
		fprintf(stdout, "Failed to open %s:%s\n", tempintsection_filec,
				strerror(errno));
		return 1;
	}

	/* Write integrity into temp file */
	written = fwrite(sinfo->integrityc, 1, sinfo->integrity_lenc, outfp);
	if (written != sinfo->integrity_lenc) {
		fprintf(stdout, "Failed to write pod code integrity to file %s\n",
				tempintsection_filec);
		ret = 1;
		goto out_close_outfp;
	}

	fclose(outfp);
    // ====================== DATA START ============================ // 
    if (!skip_data) {

        outfp = fopen(tempintsection_filed, "w");
        if (!outfp) {
            fprintf(stdout, "Failed to open %s:%s\n", tempintsection_filed,
                    strerror(errno));
            return 1;
        }

        /* Write integrity into temp file */
        written = fwrite(sinfo->integrityd, 1, sinfo->integrity_lend, outfp);
        if (written != sinfo->integrity_lend) {
            fprintf(stdout, "Failed to write pod data integrity to file %s\n",
                    tempintsection_filed);
            ret = 1;
            goto out_close_outfp;
        }

        fclose(outfp);

    }

    outfp = fopen(tempintsection_files, "w");
    if (!outfp) {
        fprintf(stdout, "Failed to open %s:%s\n", tempintsection_files,
                strerror(errno));
        return 1;
    }

    /* Write integrity into temp file */
    written = fwrite(sinfo->integritys, 1, sinfo->integrity_lens, outfp);
    if (written != sinfo->integrity_lens) {
        fprintf(stdout, "Failed to write pod stack integrity to file %s %d %d\n",
                tempintsection_files, sinfo->integrity_lens, written);
        ret = 1;
        goto out_close_outfp;
    }

    fclose(outfp);

    outfp = fopen(tempintsection_filebss, "w");
    if (!outfp) {
        fprintf(stdout, "Failed to open %s:%s\n", tempintsection_filebss,
                strerror(errno));
        return 1;
    }

    /* Write integrity into temp file */
    written = fwrite(sinfo->integritybss, 1, sinfo->integrity_lenbss, outfp);
    if (written != sinfo->integrity_lenbss) {
        fprintf(stdout, "Failed to write pod code integrity to file %s\n",
                tempintsection_filebss);
        ret = 1;
        goto out_close_outfp;
    }

    fclose(outfp);

    outfp = fopen(tempintsection_filemmap, "w");
    if (!outfp) {
        fprintf(stdout, "Failed to open %s:%s\n", tempintsection_filemmap,
                strerror(errno));
        return 1;
    }

    /* Write integrity into temp file */
    written = fwrite(sinfo->integritymmap, 1, sinfo->integrity_lenmmap, outfp);
    if (written != sinfo->integrity_lenmmap) {
        fprintf(stdout, "Failed to write pod code integrity to file %s\n",
                tempintsection_filemmap);
        ret = 1;
        goto out_close_outfp;
    }

    fclose(outfp);

    outfp = fopen(tempintsection_filebrk, "w");
    if (!outfp) {
        fprintf(stdout, "Failed to open %s:%s\n", tempintsection_filebrk,
                strerror(errno));
        return 1;
    }

    /* Write integrity into temp file */
    written = fwrite(sinfo->integritybrk, 1, sinfo->integrity_lenbrk, outfp);
    if (written != sinfo->integrity_lenbrk) {
        fprintf(stdout, "Failed to write pod code integrity to file %s\n",
                tempintsection_filebrk);
        ret = 1;
        goto out_close_outfp;
    }

    fclose(outfp);

	exit_code = WEXITSTATUS(ret);
	ret = exit_code;
	if (ret)
		goto out_close_outfp;
	return ret;
out_close_outfp:
	fclose(outfp);
	return ret;
}

static int sign_elf_executable(struct signelf_info *sinfo)
{
	int ret, fd;

	fd = open(sinfo->in_file, O_RDONLY);
	if (fd < 0) {
		fprintf(stdout, "Cannot open %s: %s\n",
				sinfo->in_file, strerror(errno));
		return 1;
	}

	ret = pread(fd, sinfo->ehdr.e_ident, EI_NIDENT, 0);
	if (ret != EI_NIDENT) {
		fprintf(stdout, "Read of e_ident from %s failed: %s\n",
				sinfo->in_file, strerror(errno));
		ret = 1;
		goto out;
	}

	if (memcmp(sinfo->ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stdout, "Missing elf signature\n");
		ret = 1;
		goto out;
	}

	if (sinfo->ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
		fprintf(stdout, "Bad elf version\n");
		ret = 1;
		goto out;
	}

	if ((sinfo->ehdr.e_ident[EI_CLASS] != ELFCLASS32) &&
	    (sinfo->ehdr.e_ident[EI_CLASS] != ELFCLASS64))
	{
		fprintf(stdout, "Unknown elf class %u\n",
				sinfo->ehdr.e_ident[EI_CLASS]);
		ret = 1;
		goto out;
	}

	if ((sinfo->ehdr.e_ident[EI_DATA] != ELFDATA2LSB) &&
	    (sinfo->ehdr.e_ident[EI_DATA] != ELFDATA2MSB))
	{
		fprintf(stdout, "Unkown elf data order %u\n",
				sinfo->ehdr.e_ident[EI_DATA]);
		ret = 1;
		goto out;
	}

	if (sinfo->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
		ret = read_elf32(sinfo, fd);
	else
		ret = read_elf64(sinfo, fd);

	if (!ret)
		goto out;

    if(read_pod_key(sinfo)){
		ret = 1;
		goto out;
	}
	
	ret = add_podkey_in_a_section(sinfo);
	if (ret) {
	 	fprintf(stdout, "Error while putting pod key into an elf"
				" section\n");
	 	goto out;
	}
	
	if (encrypt_and_hash_elfc(sinfo)) {
		ret = 1;
		goto out;
	}

    if (encrypt_and_hash_elfd(sinfo)) {
        ret = 1;
        goto out;
    }

    create_hash_space(sinfo);

	ret = add_integrity_in_a_section(sinfo, 0);
	if (ret) {
	 	fprintf(stdout, "Error while putting integrity into an elf"
				" section\n");
	 	goto out;
	}

out:
	close(fd);
	return ret;
}

static void print_help()
{
	printf("Usage: get_pod_int [OPTION...]\n");
	printf(" -i, --in=<infile>\t\t\t\tspecify input file\n");
	printf(" -k, --appkey=<appkeyfile>\t\t\tspecify application key file\n");
	printf(" -c, --cpukey=<cpukeyfile>\t\t\tspecify cpu public key file\n");
	printf(" -o, --out=<outfile>\t\t\t\tspecify output file\n");
}

static void free_sinfo_members(struct signelf_info *sinfo)
{
	free(sinfo->in_file);
	free(sinfo->out_file);
	free(sinfo->privkey_file);
	free(sinfo->certificate_file);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	char *option_string = "hi:k:c:o:", c;
	struct signelf_info *sinfo, signelf_info;

	struct option long_options[] =
		{
			{"help", no_argument, 0, 'h'},
			{"in", required_argument, 0, 'i'},
			{"appkey", required_argument, 0, 'k'},
			{"cpukey", required_argument, 0, 'c'},
			{"out", required_argument, 0, 'o'},
			{ 0, 0, 0, 0}
		};

	if (argc < 2) {
		print_help();
		exit(1);
	}

	sinfo = &signelf_info;
	memset(sinfo, 0, sizeof(struct signelf_info));

	while((c = getopt_long(argc, argv, option_string, &long_options[0],
	       NULL)) != -1) {
		switch(c) {
		case '?':
			/* Unknown option or missing argument*/
			print_help();
			exit(1);
		case 'h':
			print_help();
			exit(0);
		case 'i':
			sinfo->in_file = strdup(optarg);
			if (!sinfo->in_file) {
				fprintf(stdout, "Can't duplicate string:%s\n",
						strerror(errno));
				exit(1);
			}
			break;
		case 'k':
			sinfo->privkey_file = strdup(optarg);
			if (!sinfo->privkey_file) {
				fprintf(stdout, "Can't duplicate string:%s\n",
					strerror(errno));
				exit(1);
			}
			break;
		case 'c':
			sinfo->certificate_file = strdup(optarg);
			if (!sinfo->certificate_file) {
				fprintf(stdout, "Can't duplicate string:%s\n",
					strerror(errno));
				exit(1);
			}
			break;
		case 'o':
			sinfo->out_file = strdup(optarg);
			if (!sinfo->out_file) {
				fprintf(stdout, "Can't duplicate string:%s\n",
					strerror(errno));
				exit(1);
			}
			break;
		default:
			printf("Unexpected option\n");
			exit(1);
		}
	}

	if (!sinfo->in_file || !sinfo->out_file || !sinfo->privkey_file ||
	    !sinfo->certificate_file) {
		print_help();
		exit(1);
	}

	ret = sign_elf_executable(sinfo);

	free_sinfo_members(sinfo);
	remove(tempkeysection_file);

	exit(ret);
}
