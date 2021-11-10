#pragma once

typedef struct _Message_Init
{
	ULONG_PTR DbgkpWakeTarget;
	ULONG_PTR PsResumeThread;
	ULONG_PTR PsSuspendThread;
	ULONG_PTR PsGetNextProcessThread;
	ULONG_PTR DbgkpSectionToFileHandle;
	ULONG_PTR MmGetFileNameForAddress;
	ULONG_PTR KiDispatchException;
	ULONG_PTR DbgkForwardException;
	ULONG_PTR DbgkpSuspendProcess;
	ULONG_PTR KeThawAllThreads;
	ULONG_PTR DbgkCreateThread;
	ULONG_PTR DbgkMapViewOfSection;
	ULONG_PTR DbgkUnMapViewOfSection;
	ULONG_PTR NtCreateUserProcess;
	ULONG_PTR DbgkpMarkProcessPeb;
	ULONG_PTR DbgkpSuppressDbgMsg;

	ULONG_PTR DbgkDebugObjectType;
	ULONG_PTR PsSystemDllBase;
}Message_Init, * PMessage_Init;


#ifdef _AMD64_
#else
typedef struct _UNICODE_STRING64
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG Resave;//wow64¶ÔÆë
	ULONG64 Buffer;
} UNICODE_STRING64, * PUNICODE_STRING64;
#pragma pack(1)
typedef struct _OBJECT_ATTRIBUTES64
{
	ULONG Length;
	ULONG Resave1;//wow64¶ÔÆë
	ULONG64 RootDirectory;//HANDLE RootDirectory;
	ULONG64 ObjectName;//PUNICODE_STRING ObjectName;
	ULONG Attributes;
	ULONG Resave2;//wow64¶ÔÆë
	ULONG64 SecurityDescriptor;//PVOID SecurityDescriptor;        // SECURITY_DESCRIPTOR
	ULONG64 SecurityQualityOfService;//PVOID SecurityQualityOfService;  // SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES64;
typedef OBJECT_ATTRIBUTES64* POBJECT_ATTRIBUTES64;

#pragma pack(1)
typedef struct _Message_NewNtCreateDebugObject64
{
	ULONG64 DebugObjectHandle;
	ACCESS_MASK DesiredAccess;
	ULONG64 ObjectAttributes;//POBJECT_ATTRIBUTES64 ObjectAttributes;
	ULONG Flags;
}Message_NewNtCreateDebugObject64;

#pragma pack(1)
typedef struct Message_NewNtDebugActiveProcess64
{
	ULONG64 ProcessId;
	ULONG64 ProcessHandle;
	ULONG64 DebugObjectHandle;
}_Message_NewNtDebugActiveProcess64;


#pragma pack(1)
typedef struct Message_NewNtWaitForDebugEvent64
{
	ULONG64 DebugObjectHandle;
	BOOLEAN Alertable;
	ULONG64 Timeout;//PLARGE_INTEGER Timeout;
	ULONG64 WaitStateChange;	//PDBGUI_WAIT_STATE_CHANGE WaitStateChange;
}_Message_NewNtWaitForDebugEvent64;
#endif // _AMD64_


#pragma pack(1)
typedef struct _Message_NtReadWriteVirtualMemory
{
	HANDLE ProcessId;
	HANDLE ProcessHandle;
	PVOID BaseAddress;
	PVOID Buffer;
	SIZE_T BufferBytes;
	PSIZE_T ReturnBytes;
	BOOL Read;
}Message_NtReadWriteVirtualMemory;

#pragma pack(1)
typedef struct _Message_NtProtectVirtualMemory
{
	HANDLE ProcessHandle;
	PVOID* BaseAddress;
	PSIZE_T RegionSize;
	ULONG NewProtect;
	PULONG OldProtect;
}Message_NtProtectVirtualMemory;

#pragma pack(1)
typedef struct _Message_NewNtOpenProcess
{
	PHANDLE ProcessHandle;
	ACCESS_MASK DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	PCLIENT_ID ClientId;
}Message_NewNtOpenProcess;

#pragma pack(1)
typedef struct _Message_NewNtDebugActiveProcess
{
	HANDLE ProcessId;
	HANDLE ProcessHandle;
	HANDLE DebugObjectHandle;
}Message_NewNtDebugActiveProcess;


#pragma pack(1)
typedef struct _Message_NewNtCreateDebugObject
{
	PHANDLE DebugObjectHandle;
	ACCESS_MASK DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes;
	ULONG Flags;
}Message_NewNtCreateDebugObject;

#pragma pack(1)
typedef struct _Message_NewNtRemoveProcessDebug
{
	HANDLE ProcessId;
	HANDLE ProcessHandle;
	HANDLE DebugObjectHandle;
}Message_NewNtRemoveProcessDebug;

//#pragma pack(1)
//struct Message_NewNtWaitForDebugEvent
//{
//	HANDLE DebugObjectHandle;
//	BOOLEAN Alertable;
//	PLARGE_INTEGER Timeout;
//	void *WaitStateChange;
//	//PDBGUI_WAIT_STATE_CHANGE WaitStateChange;
//};



#if _KERNEL_MODE	
#endif

#define IO_Init CTL_CODE(FILE_DEVICE_UNKNOWN,0x7100,METHOD_BUFFERED ,FILE_ANY_ACCESS)

#define IO_NtReadWriteVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN,0x7101,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define IO_NtProtectVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN,0x7102,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define IO_NtOpenProcess CTL_CODE(FILE_DEVICE_UNKNOWN,0x7103,METHOD_BUFFERED ,FILE_ANY_ACCESS)


#define IO_NtCreateDebugObject CTL_CODE(FILE_DEVICE_UNKNOWN,0x7104,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define IO_NtDebugActiveProcess CTL_CODE(FILE_DEVICE_UNKNOWN,0x7105,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define IO_NtRemoveProcessDebug CTL_CODE(FILE_DEVICE_UNKNOWN,0x7106,METHOD_BUFFERED ,FILE_ANY_ACCESS)

#define TEST_2 CTL_CODE(FILE_DEVICE_UNKNOWN,0x8101,METHOD_BUFFERED ,FILE_ANY_ACCESS)



