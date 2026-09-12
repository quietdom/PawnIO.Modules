// ProcessMemory - Cross-process memory inspection module for PawnIO
// Copyright (C) 2026
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <pawnio.inc>

// Kernel function addresses (resolved once)
static VAProc:g_pPsLookupProcessByProcessId;
static VAProc:g_pObfDereferenceObject;
static VAProc:g_pKeStackAttachProcess;
static VAProc:g_pKeUnstackDetachProcess;
static VAProc:g_pPsGetProcessId;
static VAProc:g_pPsGetProcessPeb;
static VAProc:g_pMmCopyVirtualMemory;

// Target process state
static g_target_pid;
static VA:g_target_eprocess;
static VA:g_apc_state[14]; // KAPC_STATE: size 0x70 bytes = 14 qwords

// PEPROCESS_KPROCESS_OFFSET: KPROCESS is embedded at start of EPROCESS
// On Win10+ x64, KPROCESS.UniqueProcessId (ULONG) is at offset 0x474
// but we use PsGetProcessId exported function instead
const EPROCESS_UNIQUEPROCESS_OFFSET = 0x474;

// Resolve kernel function addresses, returns STATUS_SUCCESS or STATUS_PROCEDURE_NOT_FOUND
resolve_kernel_functions() {
    g_pPsLookupProcessByProcessId = get_proc_address("PsLookupProcessByProcessId");
    if (g_pPsLookupProcessByProcessId == VAProc:NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    g_pObfDereferenceObject = get_proc_address("ObfDereferenceObject");
    if (g_pObfDereferenceObject == VAProc:NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    g_pKeStackAttachProcess = get_proc_address("KeStackAttachProcess");
    if (g_pKeStackAttachProcess == VAProc:NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    g_pKeUnstackDetachProcess = get_proc_address("KeUnstackDetachProcess");
    if (g_pKeUnstackDetachProcess == VAProc:NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    g_pPsGetProcessId = get_proc_address("PsGetProcessId");
    if (g_pPsGetProcessId == VAProc:NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    g_pPsGetProcessPeb = get_proc_address("PsGetProcessPeb");
    if (g_pPsGetProcessPeb == VAProc:NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    g_pMmCopyVirtualMemory = get_proc_address("MmCopyVirtualMemory");
    if (g_pMmCopyVirtualMemory == VAProc:NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    return STATUS_SUCCESS;
}

// Attach to target process address space via KeStackAttachProcess
// apc_state must be a buffer of at least 14 qwords (0x70 bytes)
NTSTATUS:attach_to_process(VA:apc_state) {
    new dummy;
    return invoke(g_pKeStackAttachProcess, dummy, _:g_target_eprocess, _:apc_state);
}

// Detach from target process address space
NTSTATUS:detach_from_process(VA:apc_state) {
    new dummy;
    return invoke(g_pKeUnstackDetachProcess, dummy, _:apc_state);
}

// Read virtual memory from attached process using MmCopyVirtualMemory
// source_process = current process ( PsGetCurrentProcess )
// target_process = g_target_eprocess
NTSTATUS:read_target_memory(VA:target_address, VA:buffer, size) {
    new dummy;
    // MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, PreviousMode, &BytesCopied)
    // We read FROM target INTO our buffer
    // SourceProcess = g_target_eprocess, TargetProcess = PsGetCurrentProcess()
    new VAProc:pPsGetCurrentProcess = get_proc_address("PsGetCurrentProcess");
    if (pPsGetCurrentProcess == VAProc:NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    new VA:current_process;
    invoke(pPsGetCurrentProcess, current_process);

    new bytes_copied;
    return invoke(
        g_pMmCopyVirtualMemory,
        bytes_copied,
        _:g_target_eprocess,     // SourceProcess (target)
        _:target_address,        // SourceAddress
        _:current_process,       // TargetProcess (us)
        _:buffer,                // TargetAddress
        size,                    // BufferSize
        0,                       // PreviousMode (KernelMode)
        _:bytes_copied           // BytesCopied (output)
    );
}

// Initialize module: resolve functions and attach to target process
// in[0] = process ID
NTSTATUS:initialize(target_pid) {
    if (target_pid == 0)
        return STATUS_INVALID_PARAMETER;

    // Resolve kernel functions (cached after first call)
    new status = resolve_kernel_functions();
    if (!NT_SUCCESS(status))
        return status;

    // Look up EPROCESS by PID
    new eprocess;
    status = invoke(
        g_pPsLookupProcessByProcessId,
        eprocess,
        target_pid,     // ProcessId
        _:eprocess      // ProcessObject (output)
    );
    if (!NT_SUCCESS(status))
        return status;

    g_target_eprocess = VA:eprocess;
    g_target_pid = target_pid;

    // Zero out APC state
    for (new i = 0; i < 14; i++)
        g_apc_state[i] = 0;

    return STATUS_SUCCESS;
}

// Cleanup: dereference EPROCESS
cleanup() {
    if (g_target_eprocess != VA:0) {
        new dummy;
        invoke(g_pObfDereferenceObject, dummy, _:g_target_eprocess);
        g_target_eprocess = VA:0;
    }
    g_target_pid = 0;
}

// Module entry point
public NTSTATUS:main() {
    g_target_eprocess = VA:0;
    g_target_pid = 0;
    return STATUS_SUCCESS;
}

// Module unload
public NTSTATUS:unload() {
    cleanup();
    return STATUS_SUCCESS;
}

// ============================================================
// IOCTL handlers
// ============================================================

// Initialize with target process ID
// in[0] = process ID
DEFINE_IOCTL(ioctl_init) {
    if (in_size < 1)
        return STATUS_INVALID_PARAMETER;

    new status = initialize(in[0]);
    return status;
}

// Read memory from target process
// in[0] = virtual address, in[1] = size in bytes
// out[0..N] = data (packed as qwords)
DEFINE_IOCTL(ioctl_read) {
    if (in_size < 2)
        return STATUS_INVALID_PARAMETER;
    if (g_target_eprocess == VA:0)
        return STATUS_NOT_INITIALIZED;

    new address = in[0];
    new size = in[1];

    if (address == 0 || size == 0 || size > 0x1000)
        return STATUS_INVALID_PARAMETER;

    // Round up to qword boundary
    new qword_count = (size + 7) / 8;

    // Allocate temporary buffer in kernel
    new VA:kernel_buf = virtual_alloc(qword_count * 8);
    if (kernel_buf == NULL)
        return STATUS_NO_MEMORY;

    // Attach to target process
    new status = attach_to_process(VA:g_apc_state);
    if (!NT_SUCCESS(status)) {
        virtual_free(kernel_buf);
        return status;
    }

    // Read memory
    status = read_target_memory(VA:address, kernel_buf, size);

    // Detach
    detach_from_process(VA:g_apc_state);

    if (!NT_SUCCESS(status)) {
        virtual_free(kernel_buf);
        return status;
    }

    // Copy to output buffer
    new temp;
    for (new i = 0; i < qword_count && i < out_size; i++) {
        virtual_read_qword(VA:kernel_buf + i * 8, temp);
        out[i] = temp;
    }

    virtual_free(kernel_buf);
    return STATUS_SUCCESS;
}

// Get PEB address of target process
// out[0] = PEB address
DEFINE_IOCTL(ioctl_get_peb) {
    if (out_size < 1)
        return STATUS_INVALID_PARAMETER;
    if (g_target_eprocess == VA:0)
        return STATUS_NOT_INITIALIZED;

    new peb;
    new dummy;
    new status = invoke(g_pPsGetProcessPeb, peb, _:g_target_eprocess);
    if (!NT_SUCCESS(status))
        return status;

    out[0] = peb;
    return STATUS_SUCCESS;
}

// Get CR3 (DirectoryTableBase) of target process
// out[0] = CR3 value
DEFINE_IOCTL(ioctl_get_cr3) {
    if (out_size < 1)
        return STATUS_INVALID_PARAMETER;
    if (g_target_eprocess == VA:0)
        return STATUS_NOT_INITIALIZED;

    // DirectoryTableBase is at offset 0x28 in KPROCESS (start of EPROCESS)
    // This is stable across all Win10/11 x64 builds
    new cr3;
    virtual_read_qword(VA:g_target_eprocess + 0x28, cr3);
    out[0] = cr3;
    return STATUS_SUCCESS;
}

// Get image base of target process (PEB->ImageBaseAddress)
// out[0] = image base address
DEFINE_IOCTL(ioctl_get_image_base) {
    if (out_size < 1)
        return STATUS_INVALID_PARAMETER;
    if (g_target_eprocess == VA:0)
        return STATUS_NOT_INITIALIZED;

    // Get PEB first
    new peb;
    new dummy;
    new status = invoke(g_pPsGetProcessPeb, peb, _:g_target_eprocess);
    if (!NT_SUCCESS(status))
        return status;

    if (peb == 0)
        return STATUS_UNSUCCESSFUL;

    // PEB->ImageBaseAddress is at offset 0x10 on x64
    // Attach to read it
    status = attach_to_process(VA:g_apc_state);
    if (!NT_SUCCESS(status))
        return status;

    new image_base;
    virtual_read_qword(VA:peb + 0x10, image_base);

    detach_from_process(VA:g_apc_state);

    out[0] = image_base;
    return STATUS_SUCCESS;
}

// Version check
DEFINE_IOCTL(ioctl_version) {
    if (out_size < 1)
        return STATUS_INVALID_PARAMETER;
    out[0] = 1; // Module version 1
    return STATUS_SUCCESS;
}
