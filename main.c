/* 
 * The Clear BSD License
 * Copyright (c) 2021-2023 Princess of Sleeping, (c) 2023 CreepNT
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the disclaimer
 * below) provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 * 
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
 * THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * SceDeci4pRDrfpUnlimited: Unlimited SceDeci4pRDrfp I/O file control patcher
*/

#include <psp2kern/kernel/iofilemgr.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/cpu.h>
#include <taihen.h>

//From taiHEN module utils
int module_get_import_func(ScePID pid, const char* modname, uint32_t target_libnid, uint32_t funcnid, uintptr_t* stub);

#define HookImport(module_name, library_nid, func_nid, func_name) \
	taiHookFunctionImportForKernel(0x10005, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch)
#define HookOffset(modid, offset, thumb, func_name) \
	taiHookFunctionOffsetForKernel(0x10005, &func_name ## _ref, modid, 0, offset, thumb, func_name ## _patch)

tai_hook_ref_t sceDeci4pRDrfpDriveCheck_ref;
int sceDeci4pRDrfpDriveCheck_patch(const char *path, int a2, int a3, int a4){
	return 0;
}

tai_hook_ref_t sceKernelSetProcessId_ref;
SceUID sceKernelSetProcessId_patch(SceUID pid){
	return TAI_CONTINUE(SceUID, sceKernelSetProcessId_ref, 0x10005);
}

tai_hook_ref_t sceKernelSetPermission_ref;
int sceKernelSetPermission_patch(int perm){
	return TAI_CONTINUE(int, sceKernelSetPermission_ref, 0x80);
}

tai_hook_ref_t sceIoOpen_ref;
int sceIoOpen_patch(const char *path, int flags, int mode){
	return TAI_CONTINUE(SceUID, sceIoOpen_ref, path, flags, 0606); // fixed mode bug
}

tai_hook_ref_t sceIoMkdir_ref;
int sceIoMkdir_patch(const char *path, int mode){
	return TAI_CONTINUE(int, sceIoMkdir_ref, path, 0606); // fixed mode bug
}


tai_hook_ref_t sceIoDread_ref;
int sceIoDread_patch(SceUID fd, SceIoDirent *dent){

	int res = TAI_CONTINUE(int, sceIoDread_ref, fd, dent);
	if(res >= 0){
		dent->d_stat.st_mode |= SCE_S_IWUSR | SCE_S_IRUSR | SCE_S_IWSYS | SCE_S_IRSYS;
	}

	return res;
}

int (* dfmgr_write_uint3)(void* addr, unsigned int val);
int (* rdrfpSendPacket)(void *a1);


void get_dev_size(const char* dev, SceUInt64* pMaxSize, SceUInt64* pFreeSize) {
	SceIoDevInfo info;
	int res = ksceIoDevctl(dev, 0x3001, NULL, 0, &info, sizeof(SceIoDevInfo));
	if (res < 0) {
		*pFreeSize = *pMaxSize = 0;
	} else {
		*pMaxSize = info.max_size;
		*pFreeSize = info.free_size;
	}
}

struct _target {
	uint32_t size;
	uint32_t unk4;
	int32_t unk8;
	uint8_t unkC[4];
	uint64_t max_size;
	uint64_t free_size;
	int32_t name_len;
	char name;
};

#define _ADD_TARGET(_dev_name, _max_size, _free_size)	\
	do {												\
		int _name_slen = strnlen(_dev_name, 0x20);		\
		(*ppTarget)->unk8 = 0xA;						\
		(*ppTarget)->unkC[0] = 0;						\
		(*ppTarget)->unkC[1] = 4;						\
		(*ppTarget)->unkC[2] = 0;						\
		(*ppTarget)->unkC[3] = 0;						\
		(*ppTarget)->max_size = _max_size;				\
		(*ppTarget)->free_size = _free_size;			\
		(*ppTarget)->name_len = _name_slen + 1;			\
		memset(&(*ppTarget)->name, 0, (_name_slen + 4) & ~3);			\
		memcpy(&(*ppTarget)->name, _dev_name, (*ppTarget)->name_len);	\
		(*ppTarget)->size = ((*ppTarget)->name_len + 0x27) & ~3;		\
		*pListSize += (*ppTarget)->size;				\
		*((char**)ppTarget) += (*ppTarget)->size;		\
	} while(0)

void add_vita_card_target(struct _target** ppTarget, unsigned* pListSize) {
	//Check if grw0: exists - don't add Vita Card if not
	SceIoStat stat;
	if (ksceIoGetstat("grw0:", &stat) < 0) {
		return;
	}

	_ADD_TARGET("Vita Card:", 0, 0);
}

void _add_target_raw(const char* dev_name, uint64_t max_size, uint64_t free_size, struct _target** ppTarget, unsigned* pListSize) {
	_ADD_TARGET(dev_name, max_size, free_size);
}

void add_target(const char* dev_name, struct _target** ppTarget, unsigned* pListSize) {
	//Check if device exists
	SceIoStat stat;
	if (ksceIoGetstat(dev_name, &stat) < 0) {
		return;
	}

	_ADD_TARGET(dev_name, 0, 0);
}
#undef _ADD_TARGET

int rdrfpFSCommandHandlerGetDeviceList_patch(void *a1, void *a2, SceUInt32 *a3){

	unsigned nList = 0;
	unsigned ListSize = 0x20;
	struct _target* ListPtr = a2 + ListSize;

	*(int *)(a2 + 0x10) = 0x23;

#define _ARGS &ListPtr, &ListSize
#define _ADD_TGT(dev_name) do { add_target(dev_name, _ARGS); nList++; } while (0)
	{
		SceUInt64 mc_max, mc_free;
		get_dev_size("ux0:", &mc_max, &mc_free);
		_add_target_raw("ux0:", mc_max, mc_free, _ARGS);
	}

	add_vita_card_target(_ARGS); nList++;
	_add_target_raw("Memory Card:", 0, 0, _ARGS); nList++;

	_ADD_TGT("os0:");
	_ADD_TGT("pd0:");
	
	_ADD_TGT("sa0:");
	_ADD_TGT("tm0:");
	_ADD_TGT("ud0:");
	_ADD_TGT("ur0:");

	_ADD_TGT("vd0:");
	_ADD_TGT("vs0:");
#undef _ADD_TGT
#undef _ARGS

	a3[0] = 0;
	a3[1] = nList;

	dfmgr_write_uint3(a2, ListSize);
	rdrfpSendPacket(a1);

	return 0;
}

SceUID hookid[3];

int program_start(void){
	int res;
	SceUID module_id;
	SceUInt32 fingerprint;
	SceKernelModuleInfo moduleInfo;

	res = ksceKernelSearchModuleByName("SceDeci4pRDrfp");
	if(res < 0){
		ksceKernelPrintf("sceKernelSearchModuleByName 0x%X\n", res);
		return res;
	}

	module_id = res;

	moduleInfo.size = sizeof(moduleInfo);

	res = ksceKernelGetModuleInfo(SCE_KERNEL_PROCESS_ID, module_id, &moduleInfo);
	if(res < 0){
		ksceKernelPrintf("sceKernelGetModuleInfo 0x%X\n", res);
		return res;
	}

	res = ksceKernelGetModuleFingerprint(module_id, &fingerprint);
	if(res < 0){
		ksceKernelPrintf("sceKernelGetModuleFingerprint 0x%X\n", res);
		return res;
	}

    //SceDeci4pDfmgrForDebugger_6D26CC56
    res = module_get_import_func(KERNEL_PID, "SceDeci4pRDrfp", 0x849E3DF5, 0x6D26CC56, (uintptr_t*)&dfmgr_write_uint3);
    if (res < 0) {
        ksceKernelPrintf("module_get_import_func 0x%X\n", res);
        return res;
    }

    uint32_t offsetTo_rdrfpSendPacket, offsetTo_rdrfpFSCommandHandlerGetDeviceList_ptr, offsetTo_sceDeci4pRDrfpDriveCheck;

	switch(fingerprint){
	case 0xAD0C2C3B: // 3.200 trunk
        offsetTo_rdrfpSendPacket = 0xD0;
        offsetTo_rdrfpFSCommandHandlerGetDeviceList_ptr = 0x7ED4;
        offsetTo_sceDeci4pRDrfpDriveCheck = 0x1508;
		break;
    case 0x1746776C: //3.600.011 external
    case 0xE09101DF: //3.650.011 external
        offsetTo_rdrfpSendPacket = 0x154;
        offsetTo_rdrfpFSCommandHandlerGetDeviceList_ptr = 0x6738;
        offsetTo_sceDeci4pRDrfpDriveCheck = 0x1024;
        break;
	default:
		ksceKernelPrintf("Unknown fingerprint 0x%08X\n", fingerprint);
		return -1;
		break;
	}

    void *fptr = rdrfpFSCommandHandlerGetDeviceList_patch;
    ksceKernelDomainTextMemcpy((char*)moduleInfo.segments[0].vaddr + offsetTo_rdrfpFSCommandHandlerGetDeviceList_ptr, &fptr, sizeof(fptr));

    rdrfpSendPacket     = (void*)((uintptr_t)((char*)moduleInfo.segments[0].vaddr + offsetTo_rdrfpSendPacket) | 1);

    hookid[0] = HookOffset(module_id, offsetTo_sceDeci4pRDrfpDriveCheck, 1, sceDeci4pRDrfpDriveCheck);
	hookid[1] = HookImport("SceDeci4pRDrfp", 0xe2c40624, 0x0486f239, sceKernelSetProcessId);
	hookid[2] = HookImport("SceDeci4pRDrfp", 0xe2c40624, 0x02eedf17, sceKernelSetPermission);

	// fixed mode bug
	HookImport("SceDeci4pRDrfp", 0x40FD29C7, 0x75192972, sceIoOpen);
	HookImport("SceDeci4pRDrfp", 0x40FD29C7, 0x7F710B25, sceIoMkdir);

	// windows god eyes
	HookImport("SceDeci4pRDrfp", 0x40FD29C7, 0x20CF5FC7, sceIoDread);

	return 0;
}

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp){

	if(program_start() < 0){
		return SCE_KERNEL_START_NO_RESIDENT;
	}

	return SCE_KERNEL_START_SUCCESS;
}
