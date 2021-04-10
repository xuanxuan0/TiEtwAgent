#pragma once
#include "TiEtwAgent.h"

#ifndef SERVICE_CONFIG
#define SERVICE_CONFIG
#define SERVICE_NAME  L"TiEtwAgent"
#define ETS_NAME L"TiEtwAgent"
#define DRIVER_NAME L"elam_driver.sys"

extern SERVICE_STATUS        g_ServiceStatus;
extern SERVICE_STATUS_HANDLE g_StatusHandle;
extern HANDLE                g_ServiceStopEvent;
#endif

#ifndef SERVICE_FUNC
#define SERVICE_FUNC
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
VOID WINAPI ServiceCtl(DWORD CtrlCode);
DWORD agent_service_init();
DWORD agent_worker();
#endif