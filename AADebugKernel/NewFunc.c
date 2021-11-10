#include "NewFunc.h"
#include "Get_SSDT.h"


BOOL HookContextHook(PHookContext pctx) {
	return HkDetourFunction((PVOID)pctx->TargetFunction, (PVOID)pctx->NewFunction, 20, (PVOID*)&pctx->OriginalFunction);
}

NTSTATUS HookContextUnhook(PHookContext pctx) {
	return HkRestoreFunction((PVOID)pctx->NewFunction, (PVOID)pctx->OriginalFunction);
}

const UNICODE_STRING PsNtDllPathName = {
	sizeof(NTDLL_PATH_NAME) - sizeof(UNICODE_NULL),
	sizeof(NTDLL_PATH_NAME),
	NTDLL_PATH_NAME
};


extern PNewFunc gNewFuntionInstance = NULL;


NTSTATUS InitNewFunc(PMessage_Init message) {

	if (gNewFuntionInstance->_Init == TRUE)
	{
		return TRUE;
	}

	//init array
	vector_setup(gNewFuntionInstance->DebugInfomationVector, 800, sizeof(DebugInfomation));

	//初始化SSDT函数
	gNewFuntionInstance->NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetSSDTFuncCurAddrByIndex(NtSysAPI_SSDT_NtProtectVirtualMemory);
	if (gNewFuntionInstance->NtProtectVirtualMemory == NULL)
	{
		return FALSE;
	}

	//初始化符号函数
	gNewFuntionInstance->DbgkpWakeTarget = (_DbgkpWakeTarget)message->DbgkpWakeTarget;
	gNewFuntionInstance->PsResumeThread = (_PsResumeThread)message->PsResumeThread;
	gNewFuntionInstance->PsSuspendThread = (_PsSuspendThread)message->PsSuspendThread;
	gNewFuntionInstance->PsGetNextProcessThread = (_PsGetNextProcessThread)message->PsGetNextProcessThread;
	gNewFuntionInstance->DbgkpSectionToFileHandle = (_DbgkpSectionToFileHandle)message->DbgkpSectionToFileHandle;
	gNewFuntionInstance->MmGetFileNameForAddress = (_MmGetFileNameForAddress)message->MmGetFileNameForAddress;
	gNewFuntionInstance->KiDispatchException = (_KiDispatchException)message->KiDispatchException;
	gNewFuntionInstance->DbgkForwardException = (_DbgkForwardException)message->DbgkForwardException;
	gNewFuntionInstance->DbgkpSuspendProcess = (_DbgkpSuspendProcess)message->DbgkpSuspendProcess;
	gNewFuntionInstance->KeThawAllThreads = (_KeThawAllThreads)message->KeThawAllThreads;
	gNewFuntionInstance->DbgkCreateThread = (_DbgkCreateThread)message->DbgkCreateThread;
	gNewFuntionInstance->DbgkMapViewOfSection = (_DbgkMapViewOfSection)message->DbgkMapViewOfSection;
	gNewFuntionInstance->DbgkUnMapViewOfSection = (_DbgkUnMapViewOfSection)message->DbgkUnMapViewOfSection;
	gNewFuntionInstance->NtCreateUserProcess = (_NtCreateUserProcess)message->NtCreateUserProcess;
	gNewFuntionInstance->DbgkpMarkProcessPeb = (_DbgkpMarkProcessPeb)message->DbgkpMarkProcessPeb;
	gNewFuntionInstance->DbgkpSuppressDbgMsg = (_DbgkpSuppressDbgMsg)message->DbgkpSuppressDbgMsg;

	//全局变量 双重指针
	gNewFuntionInstance->_DbgkDebugObjectType = (POBJECT_TYPE*)message->DbgkDebugObjectType;
	//ntdll sysdll sysload的时候就固定位置了 直接从R3拿一个上来
	gNewFuntionInstance->_PsSystemDllBase = (void*)message->PsSystemDllBase;

	gNewFuntionInstance->NewKiDispatchExceptionHookInfo.TargetFunction = (ULONG_PTR)gNewFuntionInstance->KiDispatchException;
	gNewFuntionInstance->NewKiDispatchExceptionHookInfo.NewFunction = (ULONG_PTR)NewKiDispatchException;
	if (HookContextHook(&gNewFuntionInstance->NewKiDispatchExceptionHookInfo))
	{
		return FALSE;
	}

	gNewFuntionInstance->NewDbgkForwardExceptionHookInfo.TargetFunction = (ULONG_PTR)gNewFuntionInstance->DbgkForwardException;
	gNewFuntionInstance->NewDbgkForwardExceptionHookInfo.NewFunction = (ULONG_PTR)NewDbgkForwardException;
	if (HookContextHook(&gNewFuntionInstance->NewDbgkForwardExceptionHookInfo))
	{
		return FALSE;
	}

	gNewFuntionInstance->NewDbgkCreateThreadHookInfo.TargetFunction = (ULONG_PTR)gNewFuntionInstance->DbgkCreateThread;
	gNewFuntionInstance->NewDbgkCreateThreadHookInfo.NewFunction = (ULONG_PTR)NewDbgkCreateThread;
	if (HookContextHook(&gNewFuntionInstance->NewDbgkCreateThreadHookInfo))
	{
		return FALSE;
	}

	gNewFuntionInstance->NewDbgkMapViewOfSectionHookInfo.TargetFunction = (ULONG_PTR)gNewFuntionInstance->DbgkMapViewOfSection;
	gNewFuntionInstance->NewDbgkMapViewOfSectionHookInfo.NewFunction = (ULONG_PTR)NewDbgkMapViewOfSection;
	if (HookContextHook(&gNewFuntionInstance->NewDbgkMapViewOfSectionHookInfo))
	{
		return FALSE;
	}

	gNewFuntionInstance->NewDbgkUnMapViewOfSectionHookInfo.TargetFunction = (ULONG_PTR)gNewFuntionInstance->DbgkUnMapViewOfSection;
	gNewFuntionInstance->NewDbgkUnMapViewOfSectionHookInfo.NewFunction = (ULONG_PTR)NewDbgkUnMapViewOfSection;
	if (HookContextHook(&gNewFuntionInstance->NewDbgkUnMapViewOfSectionHookInfo))
	{
		return FALSE;
	}

	gNewFuntionInstance->NewNtCreateUserProcessHookInfo.TargetFunction = (ULONG_PTR)gNewFuntionInstance->NtCreateUserProcess;
	gNewFuntionInstance->NewNtCreateUserProcessHookInfo.NewFunction = (ULONG_PTR)NewNtCreateUserProcess;
	if (HookContextHook(&gNewFuntionInstance->NewNtCreateUserProcessHookInfo))
	{
		return FALSE;
	}
	gNewFuntionInstance->_Init = TRUE;
	return TRUE;
}

NTSTATUS NewNtReadWriteVirtualMemory(Message_NtReadWriteVirtualMemory* message)
{
	HANDLE ProcessHandle = message->ProcessHandle;
	PVOID BaseAddress = message->BaseAddress;
	void* Buffer = message->Buffer;
	SIZE_T BufferSize = message->BufferBytes;
	PSIZE_T NumberOfBytesWritten = message->ReturnBytes;

	SIZE_T BytesCopied;
	KPROCESSOR_MODE PreviousMode;
	PEPROCESS Process;
	NTSTATUS Status;
	PETHREAD CurrentThread;

	PAGED_CODE();

	CurrentThread = PsGetCurrentThread();
	PreviousMode = KeGetPreviousMode();
	if (PreviousMode != KernelMode)
	{

		if (((PCHAR)BaseAddress + BufferSize < (PCHAR)BaseAddress) ||
			((PCHAR)Buffer + BufferSize < (PCHAR)Buffer) ||
			((PVOID)((PCHAR)BaseAddress + BufferSize) > MM_HIGHEST_USER_ADDRESS) ||
			((PVOID)((PCHAR)Buffer + BufferSize) > MM_HIGHEST_USER_ADDRESS))
		{
			return STATUS_ACCESS_VIOLATION;
		}

		if (ARGUMENT_PRESENT(NumberOfBytesWritten))
		{
			__try
			{
				ProbeForWrite(NumberOfBytesWritten, sizeof(PSIZE_T), sizeof(ULONG));
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}
	}

	BytesCopied = 0;
	Status = STATUS_SUCCESS;
	if (BufferSize != 0)
	{
		do
		{
			PEPROCESS temp_process;
			Status = PsLookupProcessByProcessId((HANDLE)message->ProcessId, &temp_process);
			if (!NT_SUCCESS(Status))
			{
				break;
			}
			if (message->Read)
			{
				Status = MmCopyVirtualMemory(temp_process, (PVOID)message->BaseAddress, PsGetCurrentProcess(),
					message->Buffer, message->BufferBytes, PreviousMode, &BytesCopied);
			}
			else
			{
				Status = MmCopyVirtualMemory(PsGetCurrentProcess(), message->Buffer, temp_process,
					(PVOID)message->BaseAddress, message->BufferBytes, PreviousMode, &BytesCopied);
			}
			ObDereferenceObject(temp_process);
		} while (FALSE);
	}

	if (ARGUMENT_PRESENT(NumberOfBytesWritten))
	{
		__try
		{
			*NumberOfBytesWritten = BytesCopied;

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			NOTHING;
		}
	}

	return Status;
}

NTSTATUS NewNtProtectVirtualMemory(Message_NtProtectVirtualMemory* message)
{
	NTSTATUS status = 0;
	status = gNewFuntionInstance->NtProtectVirtualMemory(message->ProcessHandle, message->BaseAddress, message->RegionSize, message->NewProtect, message->OldProtect);
	return status;
}

NTSTATUS NewNtOpenProcess(Message_NewNtOpenProcess* message)
{
	PHANDLE ProcessHandle = message->ProcessHandle;
	ACCESS_MASK DesiredAccess = message->DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes = message->ObjectAttributes;
	PCLIENT_ID ClientId = message->ClientId;

	HANDLE Handle;
	KPROCESSOR_MODE PreviousMode;
	NTSTATUS Status;
	PEPROCESS Process;
	PETHREAD Thread;
	CLIENT_ID CapturedCid = { 0 };
	BOOLEAN ObjectNamePresent;
	BOOLEAN ClientIdPresent;
	ACCESS_STATE AccessState;
	AUX_ACCESS_DATA AuxData;
	ULONG Attributes;


	PEPROCESS temp_process;
	Status = PsLookupProcessByProcessId((HANDLE)message->ClientId->UniqueProcess, &temp_process);
	if (!NT_SUCCESS(Status))
	{
		return STATUS_UNSUCCESSFUL;
	}
	ObDereferenceObject(temp_process);


	PreviousMode = KeGetPreviousMode();
	if (PreviousMode != KernelMode)
	{
		__try
		{
			ProbeForWriteHandle(ProcessHandle);

			ProbeForRead(ObjectAttributes,
				sizeof(OBJECT_ATTRIBUTES),
				sizeof(ULONG));
			ObjectNamePresent = (BOOLEAN)ARGUMENT_PRESENT(ObjectAttributes->ObjectName);
			Attributes = ObjectAttributes->Attributes;

			if (ARGUMENT_PRESENT(ClientId))
			{
				//ProbeForReadSmallStructure(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
				CapturedCid = *ClientId;
				ClientIdPresent = TRUE;
			}
			else
			{
				ClientIdPresent = FALSE;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}
	else
	{
		ObjectNamePresent = (BOOLEAN)ARGUMENT_PRESENT(ObjectAttributes->ObjectName);
		Attributes = ObjectAttributes->Attributes;
		if (ARGUMENT_PRESENT(ClientId))
		{
			CapturedCid = *ClientId;
			ClientIdPresent = TRUE;
		}
		else
		{
			ClientIdPresent = FALSE;
		}
	}

	if (ObjectNamePresent && ClientIdPresent)
	{
		return STATUS_INVALID_PARAMETER_MIX;
	}

	Status = SeCreateAccessState(
		&AccessState,
		&AuxData,
		DesiredAccess,
		&(*PsProcessType)->TypeInfo.GenericMapping);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//http://www.rohitab.com/discuss/topic/39981-kernel-hack-hooking-sesingleprivilegecheck-to-bypass-privilege-checks/
	AccessState.PreviouslyGrantedAccess |= PROCESS_ALL_ACCESS;//直接给最高权限
	/*if (SeSinglePrivilegeCheck(SeDebugPrivilege, PreviousMode))
	{
		if (AccessState.RemainingDesiredAccess & MAXIMUM_ALLOWED)
		{
			AccessState.PreviouslyGrantedAccess |= PROCESS_ALL_ACCESS;
		}
		else
		{
			AccessState.PreviouslyGrantedAccess |= (AccessState.RemainingDesiredAccess);
		}
		AccessState.RemainingDesiredAccess = 0;
	}*/

	if (ObjectNamePresent)
	{
		Status = ObOpenObjectByName(
			ObjectAttributes,
			*PsProcessType,
			PreviousMode,
			&AccessState,
			0,
			NULL,
			&Handle);//打不开只能改句柄表 类BE循环去权限的无解 不改句柄表可能会不支持CE搜索
		SeDeleteAccessState(&AccessState);
		if (NT_SUCCESS(Status))
		{
			__try
			{
				*ProcessHandle = Handle;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		return Status;
	}

	if (ClientIdPresent)
	{
		Thread = NULL;
		if (CapturedCid.UniqueThread)
		{
			Status = PsLookupProcessThreadByCid(&CapturedCid, &Process, &Thread);
			if (!NT_SUCCESS(Status))
			{
				SeDeleteAccessState(&AccessState);
				return Status;
			}
		}
		else
		{
			Status = PsLookupProcessByProcessId(CapturedCid.UniqueProcess, &Process);
			if (!NT_SUCCESS(Status)) {
				SeDeleteAccessState(&AccessState);
				return Status;
			}
		}
		Status = ObOpenObjectByPointer(
			Process,
			Attributes,
			&AccessState,
			0,
			*PsProcessType,
			PreviousMode,
			&Handle
		);
		SeDeleteAccessState(&AccessState);
		if (Thread)
		{
			ObDereferenceObject(Thread);
		}
		ObDereferenceObject(Process);
		if (NT_SUCCESS(Status))
		{
			__try
			{
				*ProcessHandle = Handle;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}
		return Status;
	}
	return STATUS_INVALID_PARAMETER_MIX;
}

NTSTATUS NewNtCreateDebugObject(Message_NewNtCreateDebugObject* message)
{
	PHANDLE DebugObjectHandle = message->DebugObjectHandle;
	ACCESS_MASK DesiredAccess = message->DesiredAccess;
	POBJECT_ATTRIBUTES ObjectAttributes = message->ObjectAttributes;
	ULONG Flags = message->Flags;

	NTSTATUS Status;
	HANDLE Handle = NULL;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject = NULL;

	PreviousMode = KeGetPreviousMode();

	__try
	{
		if (PreviousMode != KernelMode)
		{
			ProbeForWriteHandle(DebugObjectHandle);
		}
		*DebugObjectHandle = NULL;//判断内存是否可写 实际上不返回 不需要内存也行
	}
	__except (1) //ExSystemExceptionFilter()
	{ // If previous mode is kernel then don't handle the exception
		return GetExceptionCode();
	}

	if (Flags & ~DEBUG_KILL_ON_CLOSE)
	{
		return STATUS_INVALID_PARAMETER;
	}

	Status = ObCreateObject(PreviousMode,
		*gNewFuntionInstance->_DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE)
	{
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	}
	else
	{
		DebugObject->Flags = 0;
	}

	Status = ObInsertObject(DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//__try 
	//{
	//	*DebugObjectHandle = Handle;
	//} __except(ExSystemExceptionFilter()) 
	//{
	//	//创建时不返回句柄对象 句柄对象是无效的
	//	Status = GetExceptionCode();
	//}
	*message->DebugObjectHandle = Handle;//返回句柄

	PDebugInfomation temp_debuginfo = __malloc(sizeof(DebugInfomation));
	temp_debuginfo->SourceProcessId = PsGetCurrentProcessId();
	temp_debuginfo->DebugObject = DebugObject;
	temp_debuginfo->DebugObjectHandle = Handle;

	vector_push_back(gNewFuntionInstance->DebugInfomationVector, temp_debuginfo);

	return Status;
}

NTSTATUS NewNtDebugActiveProcess(Message_NewNtDebugActiveProcess* message)
{
	HANDLE ProcessHandle = message->ProcessHandle;
	HANDLE DebugObjectHandle = message->DebugObjectHandle;

	NTSTATUS Status;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject = NULL;
	PEPROCESS Process;
	PETHREAD LastThread = NULL;

	PreviousMode = KeGetPreviousMode();

	Status = PsLookupProcessByProcessId((HANDLE)message->ProcessId, &Process);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	if (Process == PsGetCurrentProcess() || Process == PsInitialSystemProcess)
	{
		ObDereferenceObject(Process);
		return STATUS_ACCESS_DENIED;
	}

	HANDLE temp_pid = PsGetCurrentProcessId();
	VECTOR_FOR_EACH(gNewFuntionInstance->DebugInfomationVector, i) {
		PDebugInfomation x = ITERATOR_GET_AS(PDebugInfomation, &i);
		if (x->SourceProcessId == temp_pid)
		{
			x->TargetProcessId = message->ProcessId;
			DebugObject = x->DebugObject;
		}
	}

	if (NT_SUCCESS(Status))
	{
		if (ExAcquireRundownProtection(PrivateGetProcessRundownProtect(Process)))
		{
			Status = PrivateDbgkpPostFakeProcessCreateMessages(Process, DebugObject, &LastThread);
			Status = PrivateDbgkpSetProcessDebugObject(Process, DebugObject, Status, LastThread);
			ExReleaseRundownProtection(PrivateGetProcessRundownProtect(Process));
		}
		else
		{
			Status = STATUS_PROCESS_IS_TERMINATING;
		}
		//ObDereferenceObject(DebugObject);//不需要解引用
	}
	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS NTAPI NewNtRemoveProcessDebug(Message_NewNtRemoveProcessDebug* message)
{
	return STATUS_SUCCESS;
}
//---------------


//---------------
NTSTATUS NTAPI PrivateDbgkpPostFakeProcessCreateMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD* pLastThread)
{
	NTSTATUS Status;
	KAPC_STATE ApcState;
	PETHREAD Thread;
	PETHREAD LastThread;

	PAGED_CODE();

	KeStackAttachProcess((PKPROCESS)Process, &ApcState);
	Status = PrivateDbgkpPostFakeThreadMessages(Process, DebugObject, NULL, &Thread, &LastThread);
	if (NT_SUCCESS(Status))
	{
		Status = PrivateDbgkpPostFakeModuleMessages(Process, Thread, DebugObject);
		if (!NT_SUCCESS(Status))
		{
			ObDereferenceObject(LastThread);
			LastThread = NULL;
		}
		ObDereferenceObject(Thread);
	}
	else
	{
		LastThread = NULL;
	}
	KeUnstackDetachProcess(&ApcState);
	*pLastThread = LastThread;
	return Status;
}

NTSTATUS NTAPI PrivateDbgkpPostFakeThreadMessages(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD StartThread,
	OUT PETHREAD* pFirstThread,
	OUT PETHREAD* pLastThread)
{
	NTSTATUS Status;
	PETHREAD Thread, FirstThread, LastThread;
	DBGKM_APIMSG ApiMsg;
	BOOLEAN First = TRUE;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG Flags;
	NTSTATUS Status1;

	PAGED_CODE();

	LastThread = FirstThread = NULL;
	Status = STATUS_UNSUCCESSFUL;

	if (StartThread != NULL)
	{
		First = FALSE;
		FirstThread = StartThread;
		ObReferenceObject(FirstThread);
	}
	else
	{
		StartThread = gNewFuntionInstance->PsGetNextProcessThread(Process, NULL);
		First = TRUE;
	}

	for (Thread = StartThread; Thread != NULL; Thread = gNewFuntionInstance->PsGetNextProcessThread(Process, Thread))
	{
		Flags = DEBUG_EVENT_NOWAIT;
		if (LastThread != NULL)
		{
			ObDereferenceObject(LastThread);
		}
		LastThread = Thread;
		ObReferenceObject(LastThread);

		if (ExAcquireRundownProtection(PrivateGetThreadRundownProtect(Thread)))
		{
			Flags |= DEBUG_EVENT_RELEASE;
			if (!IS_SYSTEM_THREAD(Thread))
			{
				Status1 = gNewFuntionInstance->PsSuspendThread(Thread, NULL);
				if (NT_SUCCESS(Status1))
				{
					Flags |= DEBUG_EVENT_SUSPEND;
				}
			}
		}
		else
		{
			Flags |= DEBUG_EVENT_PROTECT_FAILED;
		}

		RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));
		if (First)
		{
			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
			if (PrivateGetProcessSectionObject(Process) != NULL)
			{ // system process doesn't have one of these!
				ApiMsg.u.CreateProcessInfo.FileHandle = gNewFuntionInstance->DbgkpSectionToFileHandle(PrivateGetProcessSectionObject(Process));
			}
			else
			{
				ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
			}
			ApiMsg.u.CreateProcessInfo.BaseOfImage = PsGetProcessSectionBaseAddress(Process);
			__try
			{
				NtHeaders = (PIMAGE_NT_HEADERS)RtlImageNtHeader(PsGetProcessSectionBaseAddress(Process));
				if (NtHeaders)
				{
					ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL; // Filling this in breaks MSDEV!
																				  //                        (PVOID)(NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);
					ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.CreateProcessInfo.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
				ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
				ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
			}
		}
		else
		{
			ApiMsg.ApiNumber = DbgKmCreateThreadApi;
			ApiMsg.u.CreateThread.StartAddress = PrivateGetThreadStartAddress(Thread);
		}

		Status = PrivateDbgkpQueueMessage(Process, Thread, &ApiMsg, Flags, DebugObject);

		if (!NT_SUCCESS(Status))
		{
			if (Flags & DEBUG_EVENT_SUSPEND)
			{
				gNewFuntionInstance->PsResumeThread(Thread, NULL);
			}
			if (Flags & DEBUG_EVENT_RELEASE)
			{
				ExReleaseRundownProtection(PrivateGetThreadRundownProtect(Thread));
			}
			if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL)
			{
				ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
			}
			//PsQuitNextProcessThread(Thread);
			ObDereferenceObject(Thread);
			break;
		}
		else if (First)
		{
			First = FALSE;
			ObReferenceObject(Thread);
			FirstThread = Thread;
		}
	}

	if (!NT_SUCCESS(Status))
	{
		if (FirstThread)
		{
			ObDereferenceObject(FirstThread);
		}
		if (LastThread != NULL)
		{
			ObDereferenceObject(LastThread);
		}
	}
	else
	{
		if (FirstThread)
		{
			*pFirstThread = FirstThread;
			*pLastThread = LastThread;
		}
		else
		{
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	return Status;
}

NTSTATUS NTAPI PrivateDbgkpSetProcessDebugObject(
	IN PEPROCESS Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread)
{
	NTSTATUS Status;
	PETHREAD ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First = TRUE;
	PETHREAD Thread;
	BOOLEAN GlobalHeld;
	PETHREAD FirstThread;

	ThisThread = PsGetCurrentThread();
	InitializeListHead(&TempList);
	First = TRUE;
	GlobalHeld = FALSE;
	if (!NT_SUCCESS(MsgStatus))
	{
		LastThread = NULL;
		Status = MsgStatus;
	}
	else
	{
		Status = STATUS_SUCCESS;
	}

	if (NT_SUCCESS(Status))
	{
		while (TRUE)
		{
			GlobalHeld = TRUE;
			ObReferenceObject(LastThread);
			Thread = gNewFuntionInstance->PsGetNextProcessThread(Process, LastThread);
			if (Thread != NULL)
			{
				GlobalHeld = FALSE;
				ObDereferenceObject(LastThread);
				Status = PrivateDbgkpPostFakeThreadMessages(Process,
					DebugObject,
					Thread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status))
				{
					LastThread = NULL;
					break;
				}
				ObDereferenceObject(FirstThread);
			}
			else
			{
				break;
			}
		}
	}

	ExAcquireFastMutex(&DebugObject->Mutex);
	if (NT_SUCCESS(Status))
	{
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0)
		{
			//PS_SET_BITS(PrivateGetProcessFlags(Process), PS_PROCESS_FLAGS_NO_DEBUG_INHERIT);
			ObReferenceObject(DebugObject);
		}
		else
		{
			//Process->DebugPort = NULL;
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	for (Entry = DebugObject->EventList.Flink; Entry != &DebugObject->EventList;)
	{
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;
		if ((DebugEvent->Flags & DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread)
		{
			Thread = DebugEvent->Thread;
			/*if (NT_SUCCESS(Status)
				&& Thread->GrantedAccess != 0
				&& !((ULONG)((*(char*)Thread) + NtSysAPI_ETHREAD_CrossThreadFlags_X64_Win7 & PS_CROSS_THREAD_FLAGS_SYSTEM) != 0))*/
			if (NT_SUCCESS(Status) && !IS_SYSTEM_THREAD(Thread))
			{
				if ((DebugEvent->Flags & DEBUG_EVENT_PROTECT_FAILED) != 0)
				{
					PS_SET_BITS(PrivateGetThreadCrossThreadFlagsPoint(Thread), PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else
				{
					if (First)
					{
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}
					DebugEvent->BackoutThread = NULL;
					PS_SET_BITS(PrivateGetThreadCrossThreadFlagsPoint(Thread), PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);
				}
			}
			else
			{
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			if (DebugEvent->Flags & DEBUG_EVENT_RELEASE)
			{
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
				ExReleaseRundownProtection(PrivateGetThreadRundownProtect(Thread));
			}

		}
	}
	ExReleaseFastMutex(&DebugObject->Mutex);
	if (LastThread != NULL)
	{
		ObDereferenceObject(LastThread);
	}

	while (!IsListEmpty(&TempList))
	{
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		gNewFuntionInstance->DbgkpWakeTarget(DebugEvent);
	}
	return Status;
}

NTSTATUS PrivateDbgkpQueueMessage(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject)
{
	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT StaticDebugEvent;
	PDEBUG_OBJECT DebugObject = NULL;
	NTSTATUS Status;

	PAGED_CODE();

	if (Flags & DEBUG_EVENT_NOWAIT)
	{
		DebugEvent = (PDEBUG_EVENT)ExAllocatePoolWithQuotaTag(
			(POOL_TYPE)(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE),
			sizeof(*DebugEvent), 'EgbD');

		if (DebugEvent == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;
		ObReferenceObject(Process);
		ObReferenceObject(Thread);
		DebugEvent->BackoutThread = PsGetCurrentThread();
		DebugObject = TargetDebugObject;
	}
	else
	{
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;

		/*ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
		DebugObject = Process->DebugPort;*/
		HANDLE temp_pid = PsGetCurrentProcessId();

		VECTOR_FOR_EACH(gNewFuntionInstance->DebugInfomationVector, i) {
			PDebugInfomation x = ITERATOR_GET_AS(PDebugInfomation, &i);
			if (x->SourceProcessId == temp_pid || x->TargetProcessId == temp_pid)//可能只需要目标id
			{
				DebugObject = x->DebugObject;
				break;
			}
		}




		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi || ApiMsg->ApiNumber == DbgKmCreateProcessApi)
		{
			if (PrivateGetThreadCrossThreadFlags(Thread) & PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG)//待debug
			{
				DebugObject = NULL;
			}
		}
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi || ApiMsg->ApiNumber == DbgKmExitProcessApi)
		{
			if (PrivateGetThreadCrossThreadFlags(Thread) & PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG)
			{
				DebugObject = NULL;
			}
		}
	}

	KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	CLIENT_ID clid = {
		.UniqueProcess = PsGetThreadProcessId(Thread) ,
		.UniqueThread = PsGetThreadId(Thread)
	};
	DebugEvent->ClientId = clid;

	if (DebugObject == NULL)
	{
		Status = STATUS_PORT_NOT_SET;
	}
	else
	{
		ExAcquireFastMutex(&DebugObject->Mutex);
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0)
		{
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);
			if ((Flags & DEBUG_EVENT_NOWAIT) == 0)
			{
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
			}
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_DEBUGGER_INACTIVE;
		}
		ExReleaseFastMutex(&DebugObject->Mutex);
	}


	if ((Flags & DEBUG_EVENT_NOWAIT) == 0)
	{
		if (NT_SUCCESS(Status))
		{
			KeWaitForSingleObject(&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			Status = DebugEvent->Status;
			*ApiMsg = DebugEvent->ApiMsg;
		}
	}
	else
	{
		if (!NT_SUCCESS(Status))
		{
			ObDereferenceObject(Process);
			ObDereferenceObject(Thread);
			ExFreePool(DebugEvent);
		}
	}
	return Status;
}

NTSTATUS NTAPI PrivateDbgkpPostFakeModuleMessages(
	IN PEPROCESS Process,
	IN PETHREAD Thread,
	IN PDEBUG_OBJECT DebugObject)
{
	PPEB Peb = PsGetProcessPeb(Process);
	if (Peb == NULL)
	{
		return STATUS_SUCCESS;
	}

	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY LdrHead, LdrNext;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	DBGKM_APIMSG ApiMsg;
	ULONG i;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING Name;
	PIMAGE_NT_HEADERS NtHeaders;
	NTSTATUS Status;
	IO_STATUS_BLOCK iosb;

	PAGED_CODE();

	__try
	{
		Ldr = Peb->Ldr;
		LdrHead = &Ldr->InLoadOrderModuleList;
		ProbeForReadSmallStructure(LdrHead, sizeof(LIST_ENTRY), sizeof(UCHAR));

		for (LdrNext = LdrHead->Flink, i = 0; LdrNext != LdrHead && i < 500; LdrNext = LdrNext->Flink, i++)
		{
			if (i > 0)
			{
				RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

				LdrEntry = CONTAINING_RECORD(LdrNext, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				ProbeForReadSmallStructure(LdrEntry, sizeof(LDR_DATA_TABLE_ENTRY), sizeof(UCHAR));

				ApiMsg.ApiNumber = DbgKmLoadDllApi;
				ApiMsg.u.LoadDll.BaseOfDll = LdrEntry->DllBase;

				ProbeForReadSmallStructure(ApiMsg.u.LoadDll.BaseOfDll, sizeof(IMAGE_DOS_HEADER), sizeof(UCHAR));

				NtHeaders = RtlImageNtHeader(ApiMsg.u.LoadDll.BaseOfDll);
				if (NtHeaders)
				{
					ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
				Status = gNewFuntionInstance->MmGetFileNameForAddress(NtHeaders, &Name);
				if (NT_SUCCESS(Status))
				{
					InitializeObjectAttributes(&oa,
						&Name,
						OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
						NULL,
						NULL);

					Status = ZwOpenFile(&ApiMsg.u.LoadDll.FileHandle,
						GENERIC_READ | SYNCHRONIZE,
						&oa,
						&iosb,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						FILE_SYNCHRONOUS_IO_NONALERT);
					if (!NT_SUCCESS(Status))
					{
						ApiMsg.u.LoadDll.FileHandle = NULL;
					}
					ExFreePool(Name.Buffer);
				}
				Status = PrivateDbgkpQueueMessage(Process,
					Thread,
					&ApiMsg,
					DEBUG_EVENT_NOWAIT,
					DebugObject);
				if (!NT_SUCCESS(Status) && ApiMsg.u.LoadDll.FileHandle != NULL)
				{
					ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
				}

			}
			ProbeForReadSmallStructure(LdrNext, sizeof(LIST_ENTRY), sizeof(UCHAR));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

#if defined(_WIN64)
	if (PrivateGetProcessWow64Process(Process) != NULL && PrivateGetProcessWow64Process(Process)->Wow64 != NULL)
	{
		PPEB32 Peb32;
		PPEB_LDR_DATA32 Ldr32;
		PLIST_ENTRY32 LdrHead32, LdrNext32;
		PLDR_DATA_TABLE_ENTRY32 LdrEntry32;
		PWCHAR pSys;

		Peb32 = (PPEB32)PrivateGetProcessWow64Process(Process)->Wow64;

		__try
		{
			Ldr32 = (PPEB_LDR_DATA32)UlongToPtr(Peb32->Ldr);

			LdrHead32 = &Ldr32->InLoadOrderModuleList;

			ProbeForReadSmallStructure(LdrHead32, sizeof(LIST_ENTRY32), sizeof(UCHAR));
			for (LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrHead32->Flink), i = 0;
				LdrNext32 != LdrHead32 && i < 500;
				LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrNext32->Flink), i++)
			{

				if (i > 0)
				{
					RtlZeroMemory(&ApiMsg, sizeof(ApiMsg));

					LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
					ProbeForReadSmallStructure(LdrEntry32, sizeof(LDR_DATA_TABLE_ENTRY32), sizeof(UCHAR));

					ApiMsg.ApiNumber = DbgKmLoadDllApi;
					ApiMsg.u.LoadDll.BaseOfDll = (PVOID)UlongToPtr(LdrEntry32->DllBase);

					ProbeForReadSmallStructure(ApiMsg.u.LoadDll.BaseOfDll, sizeof(IMAGE_DOS_HEADER), sizeof(UCHAR));

					NtHeaders = RtlImageNtHeader(ApiMsg.u.LoadDll.BaseOfDll);
					if (NtHeaders) {
						ApiMsg.u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
						ApiMsg.u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
					}

					Status = gNewFuntionInstance->MmGetFileNameForAddress(NtHeaders, &Name);
					if (NT_SUCCESS(Status))
					{
						//ASSERT(sizeof(L"SYSTEM32") == sizeof(WOW64_SYSTEM_DIRECTORY_U));
						pSys = wcsstr(Name.Buffer, L"\\SYSTEM32\\");
						if (pSys != NULL)
						{
							RtlCopyMemory(pSys + 1, L"SysWOW64", sizeof(L"SysWOW64") - sizeof(UNICODE_NULL));
						}

						InitializeObjectAttributes(&oa,
							&Name,
							OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
							NULL,
							NULL);

						Status = ZwOpenFile(&ApiMsg.u.LoadDll.FileHandle,
							GENERIC_READ | SYNCHRONIZE,
							&oa,
							&iosb,
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
							FILE_SYNCHRONOUS_IO_NONALERT);
						if (!NT_SUCCESS(Status)) {
							ApiMsg.u.LoadDll.FileHandle = NULL;
						}
						ExFreePool(Name.Buffer);
					}

					Status = PrivateDbgkpQueueMessage(Process, Thread, &ApiMsg, DEBUG_EVENT_NOWAIT, DebugObject);
					if (!NT_SUCCESS(Status) && ApiMsg.u.LoadDll.FileHandle != NULL)
					{
						ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
					}
				}

				ProbeForReadSmallStructure(LdrNext32, sizeof(LIST_ENTRY32), sizeof(UCHAR));
			}

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}

#endif
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI PrivateDbgkpSendApiMessage(
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN BOOLEAN SuspendProcess)
{
	NTSTATUS st;
	PEPROCESS Process;
	PAGED_CODE();
	if (SuspendProcess)
	{
		SuspendProcess = gNewFuntionInstance->DbgkpSuspendProcess();
	}
	ApiMsg->ReturnedStatus = STATUS_PENDING;
	Process = PsGetCurrentProcess();
	PS_SET_BITS(PrivateGetProcessFlags(Process), PS_PROCESS_FLAGS_CREATE_REPORTED);
	st = PrivateDbgkpQueueMessage(Process, PsGetCurrentThread(), ApiMsg, 0, NULL);
	ZwFlushInstructionCache(NtCurrentProcess(), NULL, 0);
	if (SuspendProcess)
	{
		gNewFuntionInstance->KeThawAllThreads();
	}
	return st;
}
//----------




//---------------
#ifdef _AMD64_
VOID NTAPI NewKiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance)
#else
VOID NTAPI NewKiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN void* ExceptionFrame,
	IN void* TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance)
#endif // _AMD64_
{
	if (PreviousMode == KernelMode)
	{
	}
	else
	{
		//用户模式也有一次进入KiDebugRoutine的机会.
		//Kernel

		//User
		//if (FirstChance == TRUE)
		{
			HANDLE temp_pid = PsGetCurrentProcessId();



			VECTOR_FOR_EACH(gNewFuntionInstance->DebugInfomationVector, i) {
				PDebugInfomation x = ITERATOR_GET_AS(PDebugInfomation, &i);

				if (x->TargetProcessId == temp_pid)
				{

					/*if ((gNewFuntionInstance->PrivateGetProcessWow64Process(PsGetCurrentProcess()) != NULL) &&
						(ExceptionRecord->ExceptionCode == STATUS_DATATYPE_MISALIGNMENT) &&
						((TrapFrame->EFlags & EFLAGS_AC_MASK) != 0))
					{
						TrapFrame->EFlags &= ~EFLAGS_AC_MASK;
						break;
					}*/

					if ((TrapFrame->SegCs & 0xfff8) == KGDT64_R3_CMCODE)
					{
						switch (ExceptionRecord->ExceptionCode)
						{
						case STATUS_BREAKPOINT:
							ExceptionRecord->ExceptionCode = STATUS_WX86_BREAKPOINT;
							break;
						case STATUS_SINGLE_STEP:
							ExceptionRecord->ExceptionCode = STATUS_WX86_SINGLE_STEP;
							break;
						}
					}

					//忽略ExceptionForwarded判断(debugobj
					//debugobject为空时,该函数不会被直接 所以捕获目标进程后直接转发过去
					if (NewDbgkForwardException(ExceptionRecord, TRUE, FALSE))
					{
						//如果调试器处理成功 直接返回 不继续处理了 仅只给一次机会.
						//return; 不返回模式专治各种主动制造异常
					}

					if ((TrapFrame->SegCs & 0xfff8) == KGDT64_R3_CMCODE)
					{
						switch (ExceptionRecord->ExceptionCode)
						{
						case STATUS_WX86_BREAKPOINT:
							ExceptionRecord->ExceptionCode = STATUS_BREAKPOINT;
							break;
						case STATUS_WX86_SINGLE_STEP:
							ExceptionRecord->ExceptionCode = STATUS_SINGLE_STEP;
							break;
						}
					}
					break;
				}
			}
		}
	}



	_KiDispatchException func = (_KiDispatchException)gNewFuntionInstance->NewKiDispatchExceptionHookInfo.OriginalFunction;
	if (!func)
	{
		DbgBreakPoint();//必死无疑
	}
	//失败或正常进入 则再次执行
	return func(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);
}

BOOLEAN NTAPI NewDbgkForwardException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugException,
	IN BOOLEAN SecondChance)
{
	PDBGKM_EXCEPTION args;
	DBGKM_APIMSG m;
	NTSTATUS st;
	HANDLE temp_pid = PsGetCurrentProcessId();
	VECTOR_FOR_EACH(gNewFuntionInstance->DebugInfomationVector, i) {
		PDebugInfomation x = ITERATOR_GET_AS(PDebugInfomation, &i);
		if (x->TargetProcessId == temp_pid)
		{
			//捕获并确定为目标进程
			//忽略PS_CROSS_THREAD_FLAGS_HIDEFROMDBG
			//忽略Process->DebugPort
			//忽略LpcPort = FALSE;
			if (DebugException == FALSE)
			{
				DbgBreakPoint();//出现问题 该参数不应该为FALSE
			}
			//发送消息

			args = &m.u.Exception;

			DBGKM_FORMAT_API_MSG(m, DbgKmExceptionApi, sizeof(*args));

			args->ExceptionRecord = *ExceptionRecord;
			args->FirstChance = !SecondChance;

			st = PrivateDbgkpSendApiMessage(&m, DebugException);
			if (!NT_SUCCESS(st) || ((DebugException) &&
				(m.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED || !NT_SUCCESS(m.ReturnedStatus))))
			{
				return FALSE;//处理失败
			}
			return TRUE;//未出现问题 直接返回 不继续往下调用
		}
	}

	_DbgkForwardException func = (_DbgkForwardException)gNewFuntionInstance->NewDbgkForwardExceptionHookInfo.OriginalFunction;
	if (!func)
	{
		DbgBreakPoint();//等死吧...
	}
	//非目标进程 正常执行函数
	return func(ExceptionRecord, DebugException, SecondChance);
}

VOID NTAPI NewDbgkCreateThread(PETHREAD Thread, PVOID StartAddress)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_CREATE_THREAD CreateThreadArgs;
	PDBGKM_CREATE_PROCESS CreateProcessArgs;
	PEPROCESS Process = PsGetCurrentProcess();
	HANDLE ProcessId = PsGetCurrentProcessId();
	PDBGKM_LOAD_DLL LoadDllArgs;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	PIMAGE_NT_HEADERS NtHeaders;
	PTEB Teb;

	PAGED_CODE();



	VECTOR_FOR_EACH(gNewFuntionInstance->DebugInfomationVector, i) {
		PDebugInfomation x = ITERATOR_GET_AS(PDebugInfomation, &i);

		if (x->TargetProcessId == ProcessId)
		{
			//跳过PsCallImageNotifyRoutines 此过程和调试无关
			//忽略DebugPort
			//if (gNewFuntionInstance->PrivateGetProcessUserTime(Process))
			{
				//PS_SET_BITS(gNewFuntionInstance->PrivateGetProcessFlags(Process), PS_PROCESS_FLAGS_CREATE_REPORTED | PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE);
			}

			auto temp_result = PS_TEST_SET_BITS(PrivateGetProcessFlags(Process), 0x400001);

			if ((temp_result & PS_PROCESS_FLAGS_CREATE_REPORTED) == 0)
				//if (*gNewFuntionInstance->PrivateGetProcessFlags(Process) & PS_PROCESS_FLAGS_CREATE_REPORTED)
			{
				CreateThreadArgs = &m.u.CreateProcessInfo.InitialThread;
				CreateThreadArgs->SubSystemKey = 0;

				CreateProcessArgs = &m.u.CreateProcessInfo;
				CreateProcessArgs->SubSystemKey = 0;
				CreateProcessArgs->FileHandle = gNewFuntionInstance->DbgkpSectionToFileHandle(PrivateGetProcessSectionObject(Process));
				CreateProcessArgs->BaseOfImage = PrivateGetProcessSectionBaseAddress(Process);
				CreateThreadArgs->StartAddress = NULL;
				CreateProcessArgs->DebugInfoFileOffset = 0;
				CreateProcessArgs->DebugInfoSize = 0;

				__try
				{
					NtHeaders = RtlImageNtHeader(PrivateGetProcessSectionBaseAddress(Process));
					if (NtHeaders)
					{
						if (PrivateGetProcessWow64Process(PsGetCurrentProcess()) != NULL)
						{
							CreateThreadArgs->StartAddress = UlongToPtr(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, ImageBase) +
								DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, AddressOfEntryPoint));
						}
						else {
							CreateThreadArgs->StartAddress = (PVOID)(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, ImageBase) +
								DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, AddressOfEntryPoint));
						}
						/*CreateThreadArgs->StartAddress = (PVOID)(
							NtHeaders->OptionalHeader.ImageBase +
							NtHeaders->OptionalHeader.AddressOfEntryPoint);*/
						CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
						CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					CreateThreadArgs->StartAddress = NULL;
					CreateProcessArgs->DebugInfoFileOffset = 0;
					CreateProcessArgs->DebugInfoSize = 0;
				}

				DBGKM_FORMAT_API_MSG(m, DbgKmCreateProcessApi, sizeof(*CreateProcessArgs));
				PrivateDbgkpSendApiMessage(&m, FALSE);
				if (CreateProcessArgs->FileHandle != NULL)
				{
					ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
				}

				LoadDllArgs = &m.u.LoadDll;
				LoadDllArgs->BaseOfDll = gNewFuntionInstance->_PsSystemDllBase;
				LoadDllArgs->DebugInfoFileOffset = 0;
				LoadDllArgs->DebugInfoSize = 0;

				Teb = NULL;
				__try
				{
					NtHeaders = RtlImageNtHeader(gNewFuntionInstance->_PsSystemDllBase);
					if (NtHeaders)
					{
						LoadDllArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
						LoadDllArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
					}

					Teb = (PTEB)PsGetThreadTeb(Thread);
					if (Teb != NULL)
					{
						Teb->NtTib.ArbitraryUserPointer = Teb->StaticUnicodeBuffer;
						wcsncpy(Teb->StaticUnicodeBuffer,
							L"ntdll.dll",
							sizeof(Teb->StaticUnicodeBuffer) / sizeof(Teb->StaticUnicodeBuffer[0]));
						LoadDllArgs->NamePointer = &Teb->NtTib.ArbitraryUserPointer;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					LoadDllArgs->DebugInfoFileOffset = 0;
					LoadDllArgs->DebugInfoSize = 0;
					LoadDllArgs->NamePointer = NULL;
				}

				InitializeObjectAttributes(
					&Obja,
					(PUNICODE_STRING)&PsNtDllPathName,
					OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
					NULL,
					NULL
				);

				Status = ZwOpenFile(
					&LoadDllArgs->FileHandle,
					(ACCESS_MASK)(GENERIC_READ | SYNCHRONIZE),
					&Obja,
					&IoStatusBlock,
					FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
					FILE_SYNCHRONOUS_IO_NONALERT
				);

				if (!NT_SUCCESS(Status))
				{
					LoadDllArgs->FileHandle = NULL;
				}

				DBGKM_FORMAT_API_MSG(m, DbgKmLoadDllApi, sizeof(*LoadDllArgs));
				PrivateDbgkpSendApiMessage(&m, TRUE);

				if (LoadDllArgs->FileHandle != NULL)
				{
					ObCloseHandle(LoadDllArgs->FileHandle, KernelMode);
				}

				if (Teb != NULL)
				{
					__try
					{
						Teb->NtTib.ArbitraryUserPointer = NULL;
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {}
				}
			}
			else
			{
				CreateThreadArgs = &m.u.CreateThread;
				CreateThreadArgs->SubSystemKey = 0;
				CreateThreadArgs->StartAddress = PrivateGetThreadStartAddress(Thread);
				DBGKM_FORMAT_API_MSG(m, DbgKmCreateThreadApi, sizeof(*CreateThreadArgs));
				PrivateDbgkpSendApiMessage(&m, TRUE);
			}
			break;
		}
	}

	_DbgkCreateThread func = (_DbgkCreateThread)gNewFuntionInstance->NewDbgkCreateThreadHookInfo.OriginalFunction;
	if (!func)
	{
		DbgBreakPoint();
	}
	//不存在degport会被跳过 但加载回调需要正常执行
	return func(Thread, StartAddress);
}


#ifdef _AMD64_
VOID NTAPI NewDbgkMapViewOfSection(
	PEPROCESS Process,
	void* SectionObject,
	void* BaseAddress,
	unsigned int SectionOffset,
	unsigned __int64 ViewSize)
#else
VOID NTAPI NewDbgkMapViewOfSection(
	IN HANDLE SectionObject,
	IN PVOID BaseAddress,
	IN ULONG SectionOffset,
	IN ULONG_PTR ViewSize)
#endif // _AMD64_
{
	DBGKM_APIMSG m;
	PDBGKM_LOAD_DLL LoadDllArgs;
	PIMAGE_NT_HEADERS NtHeaders;

	PAGED_CODE();

	if (KeGetPreviousMode() == KernelMode)
	{
		return;
	}

	VECTOR_FOR_EACH(gNewFuntionInstance->DebugInfomationVector, i) {
		PDebugInfomation x = ITERATOR_GET_AS(PDebugInfomation, &i);

		if (x->TargetProcessId == PsGetCurrentProcessId())
		{
			PTEB temp_teb = (PTEB)PsGetThreadTeb(PsGetCurrentThread());
			if (temp_teb == NULL)
			{
				break;
			}

			NTSTATUS status = gNewFuntionInstance->DbgkpSuppressDbgMsg(temp_teb);
			if (!NT_SUCCESS(status))
			{
				break;
			}

			LoadDllArgs = &m.u.LoadDll;
			LoadDllArgs->FileHandle = gNewFuntionInstance->DbgkpSectionToFileHandle(SectionObject);
			LoadDllArgs->BaseOfDll = BaseAddress;
			LoadDllArgs->DebugInfoFileOffset = 0;
			LoadDllArgs->DebugInfoSize = 0;


			LoadDllArgs->NamePointer = temp_teb->NtTib.ArbitraryUserPointer;

			__try
			{
				NtHeaders = RtlImageNtHeader(BaseAddress);
				if (NtHeaders)
				{
					LoadDllArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					LoadDllArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				LoadDllArgs->DebugInfoFileOffset = 0;
				LoadDllArgs->DebugInfoSize = 0;
			}

			DBGKM_FORMAT_API_MSG(m, DbgKmLoadDllApi, sizeof(*LoadDllArgs));

			PrivateDbgkpSendApiMessage(&m, TRUE);
			if (LoadDllArgs->FileHandle != NULL)
			{
				ObCloseHandle(LoadDllArgs->FileHandle, KernelMode);
			}
			return;//以达到目的不继续往下执行了 继续执行也是直接被返回来
		}
	}

	_DbgkMapViewOfSection func = (_DbgkMapViewOfSection)gNewFuntionInstance->NewDbgkMapViewOfSectionHookInfo.OriginalFunction;
	if (!func)
	{
		DbgBreakPoint();
	}
	//非目标进程
#ifdef _AMD64_
	return func(Process, SectionObject, BaseAddress, SectionOffset, ViewSize);
#else
	return func(SectionObject, BaseAddress, SectionOffset, ViewSize);
#endif // _AMD64_
}

VOID NTAPI NewDbgkUnMapViewOfSection(IN PVOID BaseAddress)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_UNLOAD_DLL UnloadDllArgs;
	PEPROCESS Process;

	PAGED_CODE();

	Process = PsGetCurrentProcess();

	if (KeGetPreviousMode() == KernelMode)
	{
		return;//直接就判断了 别往下走了
	}

	VECTOR_FOR_EACH(gNewFuntionInstance->DebugInfomationVector, i) {
		PDebugInfomation x = ITERATOR_GET_AS(PDebugInfomation, &i);
		if (x->TargetProcessId == PsGetCurrentProcessId())
		{
			//同上忽略PS_CROSS_THREAD_FLAGS_HIDEFROMDBG
			UnloadDllArgs = &m.u.UnloadDll;
			UnloadDllArgs->BaseAddress = BaseAddress;
			DBGKM_FORMAT_API_MSG(m, DbgKmUnloadDllApi, sizeof(*UnloadDllArgs));
			PrivateDbgkpSendApiMessage(&m, TRUE);
			return;//同上返回
		}
	}

	_DbgkUnMapViewOfSection func = (_DbgkUnMapViewOfSection)gNewFuntionInstance->NewDbgkUnMapViewOfSectionHookInfo.OriginalFunction;
	if (!func)
	{
		DbgBreakPoint();
	}
	//非目标进程
	return func(BaseAddress);
}

//废案 win7后通过判断createinfo 走PspInsertProcess 但dbgport流程和PSPC大致无差别
//NTSTATUS NTAPI NewPspCreateProcess(
//	OUT PHANDLE ProcessHandle,
//	IN ACCESS_MASK DesiredAccess,
//	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
//	IN HANDLE ParentProcess OPTIONAL,
//	IN ULONG Flags,
//	IN HANDLE SectionHandle OPTIONAL,
//	IN HANDLE DebugPort OPTIONAL,
//	IN HANDLE ExceptionPort OPTIONAL,
//	IN ULONG JobMemberLevel)
NTSTATUS NTAPI NewNtCreateUserProcess(
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
	void* AttributeList)
{
	_NtCreateUserProcess func = (_NtCreateUserProcess)gNewFuntionInstance->NewNtCreateUserProcessHookInfo.OriginalFunction;
	if (!func)
	{
		DbgBreakPoint();
	}
	//执行创建过程
	NTSTATUS status = 0;
	status = func(ProcessHandle,
		ThreadHandle,
		ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		ProcessFlags,
		ThreadFlags,
		ProcessParameters,
		CreateInfo,
		AttributeList);

	if (NT_SUCCESS(status) && ProcessHandle != NULL)
	{
		VECTOR_FOR_EACH(gNewFuntionInstance->DebugInfomationVector, i) {
			PDebugInfomation x = ITERATOR_GET_AS(PDebugInfomation, &i);

			if (x->SourceProcessId == PsGetCurrentProcessId())
			{
				//PspCreateProcess太难重写了 搞点偷懒的东西进去算了
				//最偷懒的方式是不让他createprocess 强制atttach.

				//目标成功捕获 发起进程和创建debugobj是同一个进程
				//只是查询下 就怕有注册回调打不开 就别搞这种东西恶心东西了
				PEPROCESS temp_process = NULL;
				status = ObReferenceObjectByHandle(*ProcessHandle, 0x0400, *PsProcessType, KeGetPreviousMode(), (void**)&temp_process, NULL);
				if (!NT_SUCCESS(status))
				{
					return status;//这肯定有人在搞鬼 那没办法 要不就Int3大家一起死吧
				}
				//设置目标ID为后面的转发做匹配.
				HANDLE target_pid = PsGetProcessId(temp_process);
				x->TargetProcessId = target_pid;


				//干掉dbgport
				//干掉PEB
				//省略DbgkClearProcessDebugObject后面的obj和event清理 那东西不能清 清了我也用不了了
				*PrivateGetProcessDebugPort(temp_process) = 0;
				//DbgkpMarkProcessPeb自带KeStackAttachProcess
				gNewFuntionInstance->DbgkpMarkProcessPeb(temp_process);
				//win7下DbgkpMarkProcessPeb无大变化
				//debugobj和hanlde都已经到手 prot和peb也清理完成 可以放过去了
				return status;
			}
		}
	}

	//不是目标进程 直接放过
	return status;
}
