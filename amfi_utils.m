//  Comes from Electra, adapted for FAT binary support by me
//
//  amfi_utils.c
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "amfi_utils.h"
#include "kernel_utils.h"
#include "patchfinder64.h"
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>
#include <Foundation/Foundation.h>
#include "stdio.h"
#include <sys/sysctl.h>
#include "kernel_call.c"
#include "jelbrek.h"

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint32_t read_magic(FILE* file, off_t offset) {
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

void *load_bytes(FILE *file, off_t offset, size_t size) {
    void *buf = calloc(1, size);
    fseek(file, offset, SEEK_SET);
    fread(buf, size, 1, file);
    return buf;
}

void getSHA256inplace(const uint8_t* code_dir, uint8_t *out) {
    if (code_dir == NULL) {
        printf("NULL passed to getSHA256inplace!\n");
        return;
    }
    uint32_t* code_dir_int = (uint32_t*)code_dir;
    
    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
            realsize = swap_uint32(code_dir_int[j+1]);
            code_dir += 4*j;
        }
    }
    
    CC_SHA256(code_dir, realsize, out);
}

uint8_t *getSHA256(const uint8_t* code_dir) {
    uint8_t *out = malloc(CC_SHA256_DIGEST_LENGTH);
    getSHA256inplace(code_dir, out);
    return out;
}

uint8_t *getCodeDirectory(const char* name) {
    
    FILE* fd = fopen(name, "r");
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    long off = 0, file_off = 0;
    int ncmds = 0;
    BOOL foundarm64 = false;
    
    if (magic == MH_MAGIC_64) { // 0xFEEDFACF
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off = sizeof(mh64);
        ncmds = mh64.ncmds;
    }
    else if (magic == MH_MAGIC) {
        printf("[-] %s is 32bit. What are you doing here?\n", name);
        fclose(fd);
        return NULL;
    }
    else if (magic == 0xBEBAFECA) { //FAT binary magic
        
        size_t header_size = sizeof(struct fat_header);
        size_t arch_size = sizeof(struct fat_arch);
        size_t arch_off = header_size;
        
        struct fat_header *fat = (struct fat_header*)load_bytes(fd, 0, header_size);
        struct fat_arch *arch = (struct fat_arch *)load_bytes(fd, arch_off, arch_size);
        
        int n = swap_uint32(fat->nfat_arch);
        printf("[*] Binary is FAT with %d architectures\n", n);
        
        while (n-- > 0) {
            magic = read_magic(fd, swap_uint32(arch->offset));
            
            if (magic == 0xFEEDFACF) {
                printf("[*] Found arm64\n");
                foundarm64 = true;
                struct mach_header_64* mh64 = (struct mach_header_64*)load_bytes(fd, swap_uint32(arch->offset), sizeof(struct mach_header_64));
                file_off = swap_uint32(arch->offset);
                off = swap_uint32(arch->offset) + sizeof(struct mach_header_64);
                ncmds = mh64->ncmds;
                break;
            }
            
            arch_off += arch_size;
            arch = load_bytes(fd, arch_off, arch_size);
        }
        
        if (!foundarm64) { // by the end of the day there's no arm64 found
            printf("[-] No arm64? RIP\n");
            fclose(fd);
            return NULL;
        }
    }
    else {
        printf("[-] %s is not a macho! (or has foreign endianness?) (magic: %x)\n", name, magic);
        fclose(fd);
        return NULL;
    }
    
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            fclose(fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    fclose(fd);
    return NULL;
}

//from xerub
int strtail(const char *str, const char *tail)
{
    size_t lstr = strlen(str);
    size_t ltail = strlen(tail);
    if (ltail > lstr) {
        return -1;
    }
    str += lstr - ltail;
    return memcmp(str, tail, ltail);
}

void hex_fill(char *buf, size_t max)
{
    static const char hexdigit[16] = "0123456789abcdef";
    
    unsigned int ms = (unsigned int) time(NULL) * 1000;
    srandom(ms);
    if(max < 1)
        return;
    --max;
    
    for(int i = 0; i < max; ++i)
        buf[i] = hexdigit[random() % 16];
    buf[max] = '\0';
}

void inject_trusts(int pathc, const char *paths[])
{
    printf("[+] injecting into trust cache...\n");
    
    uint64_t g_kern_base = KernelBase;
    
    static uint64_t tc = 0;
    if (tc == 0) {
        // loaded_trust_caches: 0xFFFFFFF008F702C8
        tc = 0xFFFFFFF008F702C8 + KASLR_Slide;
//        tc = g_kern_base + (0xFFFFFFF008F702C8 - 0xFFFFFFF007004000);
    }
    
    printf("[+] trust cache: 0x%llx\n", tc);
    
    
    struct trust_chain fake_chain;
    fake_chain.next = KernelRead_64bits(tc);
    
    char* strhex;
    int hexLength = 16;
    strhex = malloc(hexLength* sizeof(char) + 1);
    
    hex_fill(strhex, 16+1);
    
    printf("0x%s uuid\n", strhex);
    
    unsigned long long hexNum;
    
    sscanf(strhex, "%llx", &hexNum);
    
    printf("%llx\n", hexNum);
    
    free(strhex);
    
    //0xabadbabeabadbabe
    
    *(uint64_t *)&fake_chain.uuid[0] = hexNum;
    *(uint64_t *)&fake_chain.uuid[8] = hexNum;
    
    int cnt = 0;
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    hash_t *allhash = malloc(sizeof(hash_t) * pathc);
    for (int i = 0; i != pathc; ++i) {
        uint8_t *cd = getCodeDirectory(paths[i]);
        if (cd != NULL) {
            getSHA256inplace(cd, hash);
            memmove(allhash[cnt], hash, sizeof(hash_t));
            ++cnt;
        }
    }
    
    fake_chain.count = cnt;
    
    size_t length = (sizeof(fake_chain) + cnt * sizeof(hash_t) + 0x3FFF) & ~0x3FFF;
    uint64_t kernel_trust = Kernel_alloc(length);
    printf("[+] kalloc: 0x%llx\n", kernel_trust);
    
    printf("[+] writing fake_chain\n");
    KernelWrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    printf("[+] writing allhash\n");
    KernelWrite(kernel_trust + sizeof(fake_chain), allhash, cnt * sizeof(hash_t));
    printf("[+] writing trust cache\n");
    
#if (0)
    KernelWrite_64bits(tc, kernel_trust);
#else
    // load_trust_cache: 0xFFFFFFF007B80504
    uint64_t f_load_trust_cache = 0xFFFFFFF007B80504 + KASLR_Slide;
//    uint64_t f_load_trust_cache = g_kern_base + (0xFFFFFFF007B80504 - 0xFFFFFFF007004000);
    uint32_t ret = kernel_call_7(f_load_trust_cache, 3,
                                 kernel_trust,
                                 length,
                                 0);
    printf("[+] load_trust_cache: 0x%x\n", ret);

#endif
    free(allhash);
    printf("[+] injected trust cache\n");
}


