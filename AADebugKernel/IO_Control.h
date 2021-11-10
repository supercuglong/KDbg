#pragma once
#include "NewFunc.h"
#include "NativeMessage.h"

typedef struct _IOControl {
	PDRIVER_OBJECT Driver_Object;
	PDEVICE_OBJECT Device_Object;
	UNICODE_STRING Device_Name;
	UNICODE_STRING Link_Name;
	PNewFunc _NewFunc;
	BOOL InitFlag;
}IOControl, * PIOControl;

extern PIOControl g_IOControl;

NTSTATUS DeinitIoControl();
NTSTATUS InitIoControl(PDRIVER_OBJECT drive_object);

NTSTATUS CreateIOControl();
NTSTATUS DeleteIOControl();
static NTSTATUS IODefault(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp);
static NTSTATUS CodeControlCenter(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp);


