#ifndef DEF_NTAPI
#define DEF_NTAPI

#include "Struct.h"


NTSTATUS
NTAPI
NtClose
(
	HANDLE Handle
);
 
  
NTSTATUS
NTAPI
NtContinue
(

	IN PCONTEXT             ThreadContext,
	IN BOOLEAN              RaiseAlert
); 

NTSTATUS
NTAPI
NtQueryInformationProcess
(
     HANDLE               ProcessHandle,
     PROCESSINFOCLASS ProcessInformationClass,
     PVOID               ProcessInformation,
     ULONG                ProcessInformationLength,
     PULONG              ReturnLength
);

NTSTATUS
NTAPI
NtQueryObject
(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

NTSTATUS
NTAPI
NtSetInformationObject
(
    HANDLE               ObjectHandle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID                ObjectInformation,
    ULONG                Length
);

NTSTATUS
NTAPI
NtRemoveProcessDebug
(
    HANDLE               ProcessHandle,
    HANDLE               DebugObjectHandle
);

NTSTATUS
NTAPI
NtSetInformationThread
(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength
);

NTSTATUS
NTAPI
NtQueryInformationThread
(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength
);

NTSTATUS
NTAPI
NtCreateThreadEx
(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);
NTSTATUS
NTAPI
NtGetContextThread
(
    HANDLE ThreadHandle,
    PCONTEXT Context
);
NTSTATUS
NTAPI
NtSetContextThread
(
    HANDLE ThreadHandle,
    PCONTEXT Context
);

NTSTATUS
NTAPI
NtSetInformationProcess
(
    IN HANDLE               ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID                ProcessInformation,
    IN ULONG                ProcessInformationLength
);

NTSTATUS
NTAPI
NtDuplicateObject
(

    HANDLE               SourceProcessHandle,
    HANDLE               SourceHandle,
    HANDLE               TargetProcessHandle,
    PHANDLE              TargetHandle,
    ACCESS_MASK          DesiredAccess,
    ULONG               InheritHandle,
    ULONG                Options
);


NTSTATUS
NTAPI
NtCreateDebugObject
(
    PHANDLE DebugObjectHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Flags
);

NTSTATUS
NTAPI
NtQueryObject
(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

NTSTATUS
NTAPI
NtQuerySystemInformation
(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID               SystemInformation,
    IN ULONG                SystemInformationLength,
    OUT PULONG              ReturnLength OPTIONAL
);

NTSTATUS
NTAPI
NtContinue
( 
    IN PCONTEXT             ThreadContext,
    IN BOOLEAN              RaiseAlert
);


#endif // !DEF_NTAPI
