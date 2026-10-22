/*
 * esp_unlock.c - minimal UEFI application that asks the firmware's GBL
 * gbl_efi_avb protocol to unlock the DEVICE lock.
 *
 * Target: Xiaomi 18 Fold (lhasa / XRing O3), firmware GBL flavour that loads
 * BOOTAA64.EFI from the `android_esp` (efisp) partition without authenticating
 * it (see HANDOVER_2.md §2 and %TEMP%\gbl_repo\gbl\docs\gbl_efi_avb_protocol.md).
 *
 * Protocol (from gbl_efi_avb_protocol.md):
 *   GUID {6bc66b9a-d5c9-4c02-9da9-50af198d912c}
 *   vtable: +0x00 Revision, +0x08 ReadPartitionAttributes, +0x10 ReadDeviceStatus,
 *           +0x18 ValidateVbmetaPublicKey, +0x20 ReadRollbackIndex,
 *           +0x28 WriteRollbackIndex, +0x30 ReadPersistentValue,
 *           +0x38 WritePersistentValue, +0x40 HandleVerificationResult,
 *           +0x48 WriteLockState, +0x50 FactoryDataReset
 *   EFI_STATUS WriteLockState(Self, UINT8 Type, UINT8 State)
 *     Type : 0 = GBL_EFI_AVB_LOCK_TYPE_DEVICE, 1 = ..._CRITICAL
 *     State: 0 = GBL_EFI_AVB_LOCK_STATE_UNLOCKED, 1 = ..._LOCKED
 *
 * Build:
 *   zig cc -target aarch64-uefi -nostdlib -o BOOTAA64.EFI esp_unlock.c
 * (zig expects the entry symbol to be EfiMain; AAPCS64 == EFIAPI on aarch64)
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef struct {
    u32 a;
    u16 b;
    u16 c;
    u8 d[8];
} efi_guid;

static efi_guid g_avb_guid = {
    0x6bc66b9a, 0xd5c9, 0x4c02, { 0x9d, 0xa9, 0x50, 0xaf, 0x19, 0x8d, 0x91, 0x2c }
};

typedef int (*efi_locate_protocol)(efi_guid *guid, void *registration, void **iface);
typedef int (*efi_write_lock_state)(void *self, u8 type, u8 state);

/* UEFI: EFI_SYSTEM_TABLE.BootServices is at +0x60 on 64-bit;
 * EFI_BOOT_SERVICES.LocateProtocol is field #37 (offset 0x140). */
#define ST_BOOTSERVICES 0x60
#define BS_LOCATEPROTOCOL 0x140

#define LOCK_TYPE_DEVICE 0
#define LOCK_STATE_UNLOCKED 0
#define LOCK_STATE_LOCKED 1

int EfiMain(void *image_handle, void *system_table)
{
    (void)image_handle;
    if (!system_table)
        return 1;

    u8 *bs = *(u8 **)((u8 *)system_table + ST_BOOTSERVICES);
    if (!bs)
        return 2;

    efi_locate_protocol locate = *(efi_locate_protocol *)(bs + BS_LOCATEPROTOCOL);
    if (!locate)
        return 3;

    void *iface = 0;
    int status = locate(&g_avb_guid, 0, &iface);
    if (status != 0 || !iface)
        return 4;

    u64 *vt = *(u64 **)iface;
    if (!vt || !vt[9])
        return 5;

    efi_write_lock_state wls = (efi_write_lock_state)vt[9];

    /* Unlock the DEVICE lock.  If the firmware refuses (EFI_ACCESS_DENIED when
     * the device is not unlockable) we still try to flip CRITICAL off, which is
     * harmless and tells us how far we got. */
    int r = wls(iface, LOCK_TYPE_DEVICE, LOCK_STATE_UNLOCKED);
    if (r != 0)
        r = wls(iface, 0 /*CRITICAL*/, LOCK_STATE_UNLOCKED);

    return r == 0 ? 0 : 6;
}
