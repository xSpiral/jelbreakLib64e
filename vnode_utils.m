//
//  *.c
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "kernel_utils.h"
#import "patchfinder64.h"
#import "offsetof.h"
#import "offsets.h"
#import "kexecute.h"
#import "kernelSymbolFinder.h"
#import <stdlib.h>
#include "kernel_call.h"
#import <stdio.h>

extern uint64_t KASLR_Slide;
static uint64_t _vnode_lookup = 0;
static uint64_t _vnode_put = 0;
static uint64_t _vfs_context_current = 0;

int vnode_lookup(const char *path, int flags, uint64_t *vnode, uint64_t vfs_context) {
    
    size_t len = strlen(path) + 1;
    uint64_t ptr = Kernel_alloc(8);
    uint64_t ptr2 = Kernel_alloc(len);
    KernelWrite(ptr2, path, len);
    
    _vnode_lookup = find_symbol("_vnode_lookup", false);
    
    if (!_vnode_lookup) _vnode_lookup = Find_vnode_lookup();
    else _vnode_lookup += KASLR_Slide;
        
    if (kernel_call_7(_vnode_lookup, 4, ptr2, flags, ptr, vfs_context)){
        printf("Error on vnode lookup\n");
        return -1;
    }else {
        printf("Success on vnode lookup\n");
    }
    
    *vnode = KernelRead_64bits(ptr);
    Kernel_free(ptr2, len);
    Kernel_free(ptr, 8);
    return 0;
}

uint64_t get_vfs_context() {
    
    _vfs_context_current = find_symbol("_vfs_context_current", false);
    if (!_vfs_context_current) _vfs_context_current = Find_vfs_context_current();
    else _vfs_context_current += KASLR_Slide;
    
    return ZmFixAddr(kernel_call_7(_vfs_context_current, 1, 1));
}

int vnode_put(uint64_t vnode) {
    
    _vnode_put = find_symbol("_vnode_put", false);
    if (!_vnode_put) _vnode_put = Find_vnode_put();
    else _vnode_put += KASLR_Slide;
    
    return (int)kernel_call_7(_vnode_put, 1, vnode);

}
