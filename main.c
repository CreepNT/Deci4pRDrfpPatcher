/*
The Clear BSD License

Copyright (c) 2023 CreepNT
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted (subject to the limitations in the disclaimer
below) provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

     * Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

     * Neither the name of the copyright holder nor the names of its
     contributors may be used to endorse or promote products derived from this
     software without specific prior written permission.

NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#include <taihen.h>

#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/iofilemgr.h>
#include <psp2kern/kernel/modulemgr.h>

#define COUNTOF(x) (sizeof(x) / sizeof(x[0]))

//From taiHEN module utils
extern int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t* addr);

#define RDRFP_NAME "SceDeci4pRDrfp"

#define IofilemgrForDriver_NID              0x40FD29C7
#define sceIoGetstatByFd_NID                0x462F059B

#define ThreadmgrForDriver_NID              0xE2C40624
#define sceKernelSetImpersonateId_NID       0x0486F239
#define sceKernelSetThreadAccessLevel_NID   0x02EEDF17

struct tai_patch {
    SceUInt32 segment_and_offset;
    SceUInt32 size;
    const unsigned char* original;
    const unsigned char* replacement;
};

#define TAI_PATCH_ENCODE_SEGMENT_OFFSET(segment, offset)    ((segment << 30) | offset)
#define _TAI_PATCH_DECODE_SEGEMENT(sao)                     ((sao >> 30) & 0x3)
#define _TAI_PATCH_DECODE_OFFSET(sao)                       (sao & ~(0x3 << 30))

#define TAI_PATCH_ARRAY                                     (const unsigned char[])

//offsets for 3.65 TOOL
static const struct tai_patch PATCHES[] = {
    {   //disable path whitelist
        TAI_PATCH_ENCODE_SEGMENT_OFFSET(0, 0x1024), 6,
        TAI_PATCH_ARRAY{ 0x20, 0x29, 0x28, 0xBF, 0x20, 0x21 },
        TAI_PATCH_ARRAY{ 0x40, 0xF2, 0x00, 0x00,    /* movw r0, #0 */
                         0x70, 0x47                 /* bx lr */
        }
    },
    {   //'Vita Card:' -> 'os0:' (display name)
        TAI_PATCH_ENCODE_SEGMENT_OFFSET(0, 0x65d8), 5,
        TAI_PATCH_ARRAY{ 'V', 'i', 't', 'a', ' '  },
        TAI_PATCH_ARRAY{ 'o', 's', '0', ':', '\0' }
    },
    {   //'grw0:' -> 'os0:' (path)
        TAI_PATCH_ENCODE_SEGMENT_OFFSET(0, 0x6724), 5,
        TAI_PATCH_ARRAY{ 'g', 'r', 'w', '0', ':'  },
        TAI_PATCH_ARRAY{ 'o', 's', '0', ':', '\0' }
    },
    {   //grw0 mount id -> os0 mount id
        TAI_PATCH_ENCODE_SEGMENT_OFFSET(0, 0x671D), 1,
        TAI_PATCH_ARRAY{ 0x0A },
        TAI_PATCH_ARRAY{ 0x02 }
    },
};

static SceUID patch_uids[COUNTOF(PATCHES)];

SceUID apply_one_patch(SceUID modid, const struct tai_patch* patch) {
    const unsigned char* patch_loc = NULL;
    const SceUInt32 segment = _TAI_PATCH_DECODE_SEGEMENT(patch->segment_and_offset);
    const SceUInt32 offset = _TAI_PATCH_DECODE_OFFSET(patch->segment_and_offset);

    ksceKernelPrintf("Patching %u bytes at segment %u offset 0x%08X...\n", patch->size, segment, offset);

    int res = module_get_offset(KERNEL_PID, modid, segment, offset, (uintptr_t*)&patch_loc);
    if (res < 0) {
        ksceKernelPrintf("module_get_offset(0x%X, seg %u, 0x%08X) failed: 0x%08X\n", modid, segment, offset, res);
        return res;
    }

    for (int i = 0; i < patch->size; i++) {
        if (patch_loc[i] != patch->original[i]) {
            ksceKernelPrintf("Segment %u @ offset 0x%08X ([%u]): expected 0x%02hhX but found 0x%02hhX instead!",
                segment, offset + i, i, patch->original[i], patch_loc[i]
            );
            return -1;
        }
    }

    if (memcmp(patch_loc, patch->original, patch->size) != 0) {
        ksceKernelPrintf("Cannot patch at segment %u offset 0x%08X: mismatch between expected and actual data\n", segment, offset);
        return -1;
    }

    SceUID patch_uid = taiInjectDataForKernel(KERNEL_PID, modid, segment, offset, patch->replacement, patch->size);
    if (patch_uid < 0) {
        ksceKernelPrintf("Failed patching at segment %u offset 0x%08X: 0x%08X\n", segment, offset, patch_uid);
    }
    return patch_uid;
}

void remove_patches(void) {
    for (int i = 0; i < COUNTOF(patch_uids); i++) {
        if (patch_uids[i] > 0) {
            int res = taiInjectReleaseForKernel(patch_uids[i]);
            if (res < 0) {
                ksceKernelPrintf("Failed to release patch #%d: 0x%X\n", i, patch_uids[i]);
            }
            patch_uids[i] = -1;
        }
    }
    ksceKernelPrintf("Removed all patches\n");
}

SceUID hook_ids[2];
tai_hook_ref_t hook_refs[2];

#define SKSII_HOOK_IDX  0
ScePID sceKernelSetImpersonateId_hook(ScePID pid) {
    static SceBool is_impersonating = SCE_FALSE;
    if (!is_impersonating) {
        is_impersonating = SCE_TRUE;
        return TAI_CONTINUE(ScePID, hook_refs[SKSII_HOOK_IDX], 0x10015);
    } else {
        is_impersonating = SCE_FALSE;
        return TAI_CONTINUE(ScePID, hook_refs[SKSII_HOOK_IDX], pid);
    }
}

#define SKSTAL_HOOK_IDX (SKSII_HOOK_IDX+1)
SceUInt32 sceKernelSetThreadAccessLevel_hook(SceUInt32 access_level) {
    static SceBool is_TAL_overridden = SCE_FALSE;
    if (!is_TAL_overridden) {
        is_TAL_overridden = SCE_TRUE;
        return TAI_CONTINUE(SceUInt32, hook_refs[SKSTAL_HOOK_IDX], 0x80);
    } else {
        is_TAL_overridden = SCE_FALSE;
        return TAI_CONTINUE(SceUInt32, hook_refs[SKSTAL_HOOK_IDX], access_level);
    }
}

void _start() __attribute__((weak, alias("module_start")));
int module_start(SceSize args, ScePVoid argp) {
    SceUID rdrfp = ksceKernelSearchModuleByName(RDRFP_NAME);
    if (rdrfp < 0) {
        ksceKernelPrintf("Cannot find " RDRFP_NAME ": 0x%08X\n", rdrfp);
        return SCE_KERNEL_START_NO_RESIDENT;
    }

    for (int i = 0; i < COUNTOF(PATCHES); i++) {
        SceUID res = apply_one_patch(rdrfp, &PATCHES[i]);
        if (res < 0) {
            ksceKernelPrintf("Failed patch #%d\n", i);
            remove_patches();
            return SCE_KERNEL_START_NO_RESIDENT;
        } else {
            patch_uids[i] = res;
        }
    }

    ksceKernelPrintf(RDRFP_NAME " patching finished!\n");

    hook_ids[SKSII_HOOK_IDX] = taiHookFunctionImportForKernel(KERNEL_PID, hook_refs + SKSII_HOOK_IDX, RDRFP_NAME, ThreadmgrForDriver_NID, sceKernelSetImpersonateId_NID, sceKernelSetImpersonateId_hook);
    hook_ids[SKSTAL_HOOK_IDX] = taiHookFunctionImportForKernel(KERNEL_PID, hook_refs + SKSTAL_HOOK_IDX, RDRFP_NAME, ThreadmgrForDriver_NID, sceKernelSetThreadAccessLevel_NID, sceKernelSetThreadAccessLevel_hook);

    ksceKernelPrintf(RDRFP_NAME " hooks=(0x%08X, 0x%08X)\n",
        hook_ids[SKSII_HOOK_IDX], hook_ids[SKSTAL_HOOK_IDX]
    );

    return SCE_KERNEL_START_SUCCESS;
}