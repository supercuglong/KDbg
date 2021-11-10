#include "IO_Control.h"
#include "NtSysAPI_Func.h"

#define DEVICE_NAME L"\\Device\\AADebug"
#define LINK_NAME L"\\??\\AADebug"

extern PIOControl g_IOControl = NULL;

NTSTATUS CreateIOControl(PDEVICE_OBJECT  DeviceObject)
{
	g_IOControl->Device_Object = DeviceObject;

	NTSTATUS status = 0;
	RtlInitUnicodeString(&g_IOControl->Device_Name, DEVICE_NAME);
	status = IoCreateDevice(g_IOControl->Driver_Object, 0, &g_IOControl->Device_Name, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_IOControl->Device_Object);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create Device error!\n");
		return status;
	}

	g_IOControl->Device_Object->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&g_IOControl->Link_Name, LINK_NAME);
	status = IoCreateSymbolicLink(&g_IOControl->Link_Name, &g_IOControl->Device_Name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(g_IOControl->Device_Object);
		DbgPrint("Create Link error!\n");
		return status;
	}

	DbgPrint("Create Device and Link SUCCESS!\n");

	g_IOControl->Driver_Object->MajorFunction[IRP_MJ_CREATE] = IODefault;
	g_IOControl->Driver_Object->MajorFunction[IRP_MJ_CLOSE] = IODefault;
	g_IOControl->Driver_Object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CodeControlCenter;

	return STATUS_SUCCESS;
}

NTSTATUS DeleteIOControl()
{
	IoDeleteSymbolicLink(&g_IOControl->Link_Name);
	IoDeleteDevice(g_IOControl->Device_Object);
	DbgPrint("Link_Unload\n");
	return STATUS_SUCCESS;
}

NTSTATUS IODefault(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CodeControlCenter(PDEVICE_OBJECT  DeviceObject, PIRP pIrp)
{
	PIO_STACK_LOCATION irp = IoGetCurrentIrpStackLocation(pIrp);
	ULONG Io_Control_Code = irp->Parameters.DeviceIoControl.IoControlCode;
	ULONG Input_Lenght = irp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG Output_Lenght = irp->Parameters.DeviceIoControl.OutputBufferLength;
	PMessage_Init Input_Output_Buffer = (PMessage_Init)pIrp->AssociatedIrp.SystemBuffer;

	NTSTATUS status = 0;

	do
	{
		if (Io_Control_Code == IO_Init)
		{
			if (g_IOControl->InitFlag == TRUE)
			{
				break;
			}
			if (Input_Output_Buffer != NULL && Input_Lenght != 0 && Output_Lenght != 0)
			{
				if (!InitNewFunc(Input_Output_Buffer))
				{
					g_IOControl->InitFlag = TRUE;
				}
			}
			break;
		}

		if (g_IOControl->InitFlag == FALSE)
		{
			break;
		}

		if (Io_Control_Code == IO_NtReadWriteVirtualMemory)
		{
			if (Input_Output_Buffer != NULL && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = NewNtReadWriteVirtualMemory((Message_NtReadWriteVirtualMemory*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NtReadWriteVirtualMemory);
			break;
		}


		if (Io_Control_Code == IO_NtProtectVirtualMemory)
		{
			if (Input_Output_Buffer != NULL && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = NewNtProtectVirtualMemory((Message_NtProtectVirtualMemory*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NtProtectVirtualMemory);
			break;
		}

		if (Io_Control_Code == IO_NtOpenProcess)
		{
			if (Input_Output_Buffer != NULL && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = NewNtOpenProcess((Message_NewNtOpenProcess*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}

			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NewNtOpenProcess);
			break;
		}

		if (Io_Control_Code == IO_NtCreateDebugObject)
		{
			if (Input_Output_Buffer != NULL && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = NewNtCreateDebugObject((Message_NewNtCreateDebugObject*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NewNtCreateDebugObject);
			break;
		}

		if (Io_Control_Code == IO_NtDebugActiveProcess)
		{
			if (Input_Output_Buffer != NULL && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = NewNtDebugActiveProcess((Message_NewNtDebugActiveProcess*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NewNtDebugActiveProcess);
			break;
		}

		if (Io_Control_Code == IO_NtRemoveProcessDebug)
		{
			if (Input_Output_Buffer != NULL && Input_Lenght != 0 && Output_Lenght != 0)
			{
				status = NewNtRemoveProcessDebug((Message_NewNtRemoveProcessDebug*)Input_Output_Buffer);
			}
			else
			{
				status = STATUS_UNSUCCESSFUL;
			}
			pIrp->IoStatus.Status = status;
			pIrp->IoStatus.Information = sizeof(Message_NewNtRemoveProcessDebug);
			break;
		}


	} while (FALSE);


	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}