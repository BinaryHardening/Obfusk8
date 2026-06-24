#pragma once

#include <intrin.h>
#include <windows.h>

#include "../transform/AES8.hpp"

NOOPT

    namespace k8_antiemu {

        struct _CpuInfo {
            int data[4];
        };

        K8_FORCEINLINE void _cpuid(int leaf, int out[4]) {
            __cpuidex(out, leaf, 0);
        }

        K8_FORCEINLINE uint64_t _rdtsc() {
            return __rdtsc();
        }

        K8_FORCEINLINE bool check_rdtsc_delta() {
            uint64_t t1 = _rdtsc();
            uint64_t t2 = _rdtsc();
            uint64_t t3 = _rdtsc();
            uint64_t d1 = t2 - t1;
            uint64_t d2 = t3 - t2;
            if (d1 == 0 || d2 == 0) return false;
            if (d1 > 10000ULL || d2 > 10000ULL) return true;
            return true;
        }

        K8_FORCEINLINE bool check_cpu_cores() {
            _CpuInfo info;
            _cpuid(1, info.data);
            uint32_t core_count = (uint32_t)((info.data[1] >> 16) & 0xFF);
            return core_count >= 2;
        }

        K8_FORCEINLINE bool check_debugger_peb() {
            uintptr_t teb = __readgsqword(0x30);
            uintptr_t peb = *(uintptr_t*)(teb + 0x60);
            uint8_t being_debugged = *(uint8_t*)(peb + 2);
            return being_debugged == 0;
        }

        K8_FORCEINLINE bool check_ntglobalflag() {
            uintptr_t teb = __readgsqword(0x30);
            uintptr_t peb = *(uintptr_t*)(teb + 0x60);
            uintptr_t ldr = *(uintptr_t*)(peb + 0x18);
            uint32_t nt_global_flag = *(uint32_t*)(ldr + 0x8);
            return (nt_global_flag & 0x00000070) == 0;
        }

        K8_FORCEINLINE bool check_hardware_breakpoints() {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            typedef NTSTATUS(NTAPI* _NtGetContextThread)(HANDLE, PCONTEXT);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll) return true;
            auto pNtGetContextThread = (_NtGetContextThread)GetProcAddress(hNtdll, "NtGetContextThread");
            if (!pNtGetContextThread) return true;
            HANDLE hCurrent = GetCurrentThread();
            if (pNtGetContextThread(hCurrent, &ctx) >= 0) {
                if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return false;
            }
            return true;
        }

        K8_FORCEINLINE bool check_debug_port() {
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll) return true;
            typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            auto pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            if (!pNtQueryInformationProcess) return true;
            ULONG_PTR debugPort = 0;
            ULONG retLen = 0;
            if (pNtQueryInformationProcess(GetCurrentProcess(), 0x7, &debugPort, sizeof(debugPort), &retLen) >= 0) {
                if (debugPort != 0) return false;
            }
            return true;
        }

        K8_FORCEINLINE bool is_safe_environment() {
            if (!check_rdtsc_delta()) return false;
            if (!check_cpu_cores()) return false;
            if (!check_debugger_peb()) return false;
            if (!check_ntglobalflag()) return false;
            if (!check_hardware_breakpoints()) return false;
            if (!check_debug_port()) return false;
            return true;
        }

    }

    SECTION_ATTR_SEC(PICK_SECTION(9)) static uint64_t _decoy_a[] = {
        0xDEADBEEF, 0xCAFEBABE, 0xBAADF00D, 0xFEEDFACE,
        0x8BADF00D, 0xDEFEC8ED, 0xD15EA5E, 0x0D15EA5E,
        0xDECAFBAD, 0xFEEDBEEF, 0xDEADDEAD, 0xDEADC0DE,
        0xB16B00B5, 0xC0FFEE, 0x5AFEC0DE, 0x0B00B135,
        0xBADF00D, 0xDEAD2BAD, 0xFEEDABEE, 0xBADDCAFE,
        0xCAFED00D, 0xDEAD10CC, 0x1BADB002, 0xFEEDC0DE,
    };

    SECTION_ATTR_SEC(PICK_SECTION(11)) static uint32_t _decoy_b[] = {
        0x12345678, 0x9ABCDEF0, 0x0FEDCBA9, 0x87654321,
        0xDEADBEEF, 0xCAFEBABE, 0xBAADF00D, 0xFEEDFACE,
        0x8BADF00D, 0xDEFEC8ED, 0xD15EA5E0, 0x0D15EA5E,
    };

    SECTION_ATTR_SEC(PICK_SECTION(5)) static uint32_t _decoy_c[] = {
        0xA5A5A5A5, 0x5A5A5A5A, 0xAAAAAAAA, 0x55555555,
        0xDEADBEEF, 0xCAFEBABE, 0xBAADF00D, 0xFEEDFACE,
    };

    SECTION_ATTR_SEC(PICK_SECTION(13)) static uint8_t _decoy_d[] = {
        0x90, 0x90, 0x90, 0x90, 0xEB, 0xFE, 0xCC, 0xCC,
        0x90, 0x90, 0x90, 0x90, 0xEB, 0xFE, 0xCC, 0xCC,
        0x90, 0x90, 0x90, 0x90, 0xEB, 0xFE, 0xCC, 0xCC,
        0x90, 0x90, 0x90, 0x90, 0xEB, 0xFE, 0xCC, 0xCC,
        0x90, 0x90, 0x90, 0x90, 0xEB, 0xFE, 0xCC, 0xCC,
        0x90, 0x90, 0x90, 0x90, 0xEB, 0xFE, 0xCC, 0xCC,
        0x90, 0x90, 0x90, 0x90, 0xEB, 0xFE, 0xCC, 0xCC,
        0x90, 0x90, 0x90, 0x90, 0xEB, 0xFE, 0xCC, 0xCC,
    };

OPT