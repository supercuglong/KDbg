#pragma once


#include "PEStructs.h"
#include "NativeMessage.h"
#include "NtSysAPI_Func.h"
#include "hk.h"
#include "vector.h"


typedef struct _HookContext {
	ULONG_PTR TargetFunction;
	ULONG_PTR NewFunction;
	ULONG_PTR OriginalFunction;
}HookContext, * PHookContext;

BOOL HookContextHook(PHookContext pctx);

NTSTATUS HookContextUnhook(PHookContext pctx);

typedef struct _DebugInfomation
{
	HANDLE SourceProcessId;
	HANDLE TargetProcessId;
	HANDLE DebugObjectHandle;
	DEBUG_OBJECT* DebugObject;
}DebugInfomation, * PDebugInfomation;


typedef struct _NewFunc
{
	HookContext NewKiDispatchExceptionHookInfo;
	HookContext NewDbgkForwardExceptionHookInfo;
	HookContext NewDbgkCreateThreadHookInfo;
	HookContext NewDbgkMapViewOfSectionHookInfo;
	HookContext NewDbgkUnMapViewOfSectionHookInfo;
	HookContext NewNtCreateUserProcessHookInfo;

	_NtProtectVirtualMemory NtProtectVirtualMemory;
	_DbgkpWakeTarget DbgkpWakeTarget;
	_PsResumeThread PsResumeThread;
	_PsSuspendThread PsSuspendThread;
	//_NtCreateDebugObject NtCreateDebugObject ;
	_PsGetNextProcessThread PsGetNextProcessThread;
	//_PsQuitNextProcessThread PsQuitNextProcessThread ;
	_DbgkpSectionToFileHandle DbgkpSectionToFileHandle;
	_MmGetFileNameForAddress MmGetFileNameForAddress;
	_KiDispatchException KiDispatchException;
	_DbgkForwardException DbgkForwardException;
	_DbgkpSuspendProcess DbgkpSuspendProcess;//不需要实现 没有什么特殊的地方
	_KeThawAllThreads KeThawAllThreads;
	_DbgkCreateThread DbgkCreateThread;
	_DbgkMapViewOfSection DbgkMapViewOfSection;
	_DbgkUnMapViewOfSection DbgkUnMapViewOfSection;
	//_PspCreateProcess PspCreateProcess ;废案
	_NtCreateUserProcess NtCreateUserProcess;
	_DbgkpMarkProcessPeb DbgkpMarkProcessPeb;
	_DbgkpSuppressDbgMsg DbgkpSuppressDbgMsg;
	POBJECT_TYPE* _DbgkDebugObjectType;
	PVOID _PsSystemDllBase;

	Vector* DebugInfomationVector;
	HANDLE _Io_Handle;
	BOOL _Init;

}NewFunc, * PNewFunc;

extern PNewFunc gNewFuntionInstance;

NTSTATUS InitNewFunc(PMessage_Init message);

NTSTATUS NTAPI NewNtReadWriteVirtualMemory(Message_NtReadWriteVirtualMemory* message);
NTSTATUS NTAPI NewNtProtectVirtualMemory(Message_NtProtectVirtualMemory* message);
NTSTATUS NTAPI NewNtOpenProcess(Message_NewNtOpenProcess* message);
NTSTATUS NTAPI NewNtCreateDebugObject(Message_NewNtCreateDebugObject* message);
NTSTATUS NTAPI NewNtDebugActiveProcess(Message_NewNtDebugActiveProcess* message);
NTSTATUS NTAPI NewNtRemoveProcessDebug(Message_NewNtRemoveProcessDebug* message);

NTSTATUS NTAPI PrivateDbgkpPostFakeProcessCreateMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD* pLastThread);
NTSTATUS NTAPI PrivateDbgkpPostFakeThreadMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD StartThread,
	OUT PETHREAD* pFirstThread,
	OUT PETHREAD* pLastThread);
NTSTATUS NTAPI PrivateDbgkpQueueMessage(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject);
NTSTATUS NTAPI PrivateDbgkpPostFakeModuleMessages(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PDEBUG_OBJECT DebugObject);
NTSTATUS NTAPI PrivateDbgkpSetProcessDebugObject(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread);
NTSTATUS NTAPI PrivateDbgkpSendApiMessage(
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN BOOLEAN SuspendProcess);

#ifdef _AMD64_
static VOID NTAPI NewKiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance);
#else
static VOID NTAPI NewKiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN void* ExceptionFrame,
	IN void* TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance);
#endif // _AMD64_


static BOOLEAN NTAPI NewDbgkForwardException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugException,
	IN BOOLEAN SecondChance);
static VOID NTAPI NewDbgkCreateThread(PETHREAD Thread, PVOID StartAddress);
#ifdef _AMD64_
static VOID NTAPI NewDbgkMapViewOfSection(
	PEPROCESS Process,
	void* SectionObject,
	void* BaseAddress,
	unsigned int SectionOffset,
	unsigned __int64 ViewSize);
#else
static VOID NTAPI NewDbgkMapViewOfSection(
	IN HANDLE SectionHandle,
	IN PVOID BaseAddress,
	IN ULONG SectionOffset,
	IN ULONG_PTR ViewSize);
#endif // _AMD64_
static VOID NTAPI NewDbgkUnMapViewOfSection(IN PVOID BaseAddress);
/*static NTSTATUS NTAPI NewPspCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess OPTIONAL,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN ULONG JobMemberLevel);*/
static NTSTATUS NTAPI NewNtCreateUserProcess(
	PHANDLE ProcessHandle,
	PETHREAD ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	OBJECT_ATTRIBUTES* ProcessObjectAttributes,
	OBJECT_ATTRIBUTES* ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	RTL_USER_PROCESS_PARAMETERS* ProcessParameters,
	void* CreateInfo,
	void* AttributeList);

static BOOL IS_SYSTEM_THREAD(PETHREAD Thread)
{
	return ((*(ULONG*)((char*)Thread + NtSysAPI_ETHREAD_CrossThreadFlags_X64_Win7) & PS_CROSS_THREAD_FLAGS_SYSTEM) != 0);
}
static ULONG PrivateGetThreadCrossThreadFlags(PETHREAD Thread)
{
	return *(ULONG*)((char*)Thread + NtSysAPI_ETHREAD_CrossThreadFlags_X64_Win7);
}
static ULONG* PrivateGetThreadCrossThreadFlagsPoint(PETHREAD Thread)
{
	return (ULONG*)((char*)Thread + NtSysAPI_ETHREAD_CrossThreadFlags_X64_Win7);
}
static void* PrivateGetThreadStartAddress(PETHREAD Thread)
{
	return (void*)((char*)Thread + NtSysAPI_ETHREAD_StartAddress_X64_Win7);
}
static PEX_RUNDOWN_REF PrivateGetThreadRundownProtect(PETHREAD Thread)
{
	return (PEX_RUNDOWN_REF)((char*)Thread + NtSysAPI_ETHREAD_RundownProtect_X64_Win7);
}
static PKTIMER PrivateGetThreadTimer(PETHREAD Thread)
{
	return (PKTIMER)((char*)Thread + NtSysAPI_KTHREAD_Timer_X64_Win7);
}

static PULONG PrivateGetProcessFlags(PEPROCESS Process)
{
	return (ULONG*)((char*)Process + NtSysAPI_EPROCESS_Flags_X64_Win7);
}
static PWOW64_PROCESS PrivateGetProcessWow64Process(PEPROCESS Process)
{
	return (PWOW64_PROCESS)((char*)Process + NtSysAPI_EPROCESS_Wow64Process_X64_Win7);
}
static PVOID PrivateGetProcessSectionObject(PEPROCESS Process)
{
	return (void*)((char*)Process + NtSysAPI_EPROCESS_SectionObject_X64_Win7);
}
static PVOID PrivateGetProcessSectionBaseAddress(PEPROCESS Process)
{
	return (PVOID)((char*)Process + NtSysAPI_EPROCESS_SectionBaseAddress_X64_Win7);
}
static PEX_RUNDOWN_REF PrivateGetProcessRundownProtect(PEPROCESS Process)
{
	return (PEX_RUNDOWN_REF)((char*)Process + NtSysAPI_EPROCESS_RundownProtect_X64_Win7);
}
static ULONG PrivateGetProcessUserTime(PEPROCESS Process)
{
	return *(ULONG*)((char*)Process + NtSysAPI_KPROCESS_UserTime_X64_Win7);
}
static PULONG_PTR PrivateGetProcessDebugPort(PEPROCESS Process)
{
	return (PULONG_PTR)((CHAR*)Process + NtSysAPI_EPROCESS_DebugPort_X64_Win7);
}


#define ProbeForWriteHandle(Address) {                                       \
    if ((Address) >= (HANDLE * const)MM_USER_PROBE_ADDRESS) {                \
        *(volatile HANDLE * const)MM_USER_PROBE_ADDRESS = 0;                 \
    }                                                                        \
                                                                             \
    *(volatile HANDLE *)(Address) = *(volatile HANDLE *)(Address);           \
}

#define PS_SET_BITS(Flags, Flag) \
    RtlInterlockedSetBitsDiscardReturn (Flags, Flag)

#define PS_TEST_SET_BITS(Flags, Flag) \
    RtlInterlockedSetBits (Flags, Flag)

#define ProbeForReadSmallStructure ProbeForRead

#define DBGKM_MSG_OVERHEAD 8

#define DBGKM_API_MSG_LENGTH(TypeSize) \
            sizeof(DBGKM_APIMSG)<<16 | (DBGKM_MSG_OVERHEAD + (TypeSize))

#define DBGKM_FORMAT_API_MSG(m,Number,TypeSize)             \
    (m).h.u1.Length = DBGKM_API_MSG_LENGTH((TypeSize));     \
    (m).h.u2.ZeroInit = LPC_DEBUG_EVENT;                    \
    (m).ApiNumber = (Number)

#define NTDLL_PATH_NAME L"\\SystemRoot\\System32\\ntdll.dll"

extern const UNICODE_STRING PsNtDllPathName;

#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
            ((hdrs)->OptionalHeader.##field)