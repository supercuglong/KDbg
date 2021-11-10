#include "IO_Control.h"


void DriverUnload(PDRIVER_OBJECT drive_object)
{
	DbgPrint("Unload Over!\n");
	DeleteIOControl();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drive_object, PUNICODE_STRING path)
{
	drive_object->DriverUnload = DriverUnload;

	CreateIOControl(drive_object);

	return STATUS_SUCCESS;
}