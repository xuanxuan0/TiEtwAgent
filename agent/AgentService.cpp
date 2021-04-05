#include "TiMemAgent.h"
#include "AgentService.h"

SERVICE_STATUS        g_ServiceStatus{ 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    DWORD ret = 0;
    log_debug(L"TiEtwSensor: ServiceMain: Starting\n");

    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtl);
    if (g_StatusHandle == NULL)
    {
        log_debug(L"TiEtwSensor: Unable to register service control handler\n");
        return;
    }

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        ret = GetLastError();
        log_debug(L"TiEtwSensor: Unable to set service status\n", ret);
        return;
    }

    HANDLE g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL)
    {
        // Error creating event
        // Tell service controller we are stopped and exit
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        log_debug(L"TiEtwSensor: Unable to set service status\n");
        return;
    }

    // Tell the service controller we are started
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        log_debug(L"TiEtwSensor: Unable to set service status\n");
        return;
    }

    // Start a thread that will perform the main task of the service
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)agent_worker, NULL, 0, NULL);

    if (NULL == hThread) {
        log_debug(L"TiEtwSensor: Failed to start the worker thread\n");
        return;
    }
    else {
        log_debug(L"TiEtwSensor: Started worker thread\n");
        WaitForSingleObject(hThread, INFINITE);
    }

    /*
    * Perform any cleanup tasks
    */

    CloseHandle(g_ServiceStopEvent);

    // Tell the service controller we are stopped
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        log_debug(L"TiEtwSensor: Unable to set service status\n");
    }
    
}


VOID WINAPI ServiceCtl(DWORD CtrlCode)
{
    DWORD ret = 0;

    log_debug(L"TiEtwSensor: Starting ServiceCtl");
    switch (CtrlCode)
    {
    case SERVICE_CONTROL_STOP:
        log_debug(L"TiEtwSensor: Stopping the service");
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 4;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
        {
            log_debug(L"TiEtwSensor: Error stopping the service\n");
            return;
        }
        break;

    default:
        break;
    }
}


DWORD agent_service_init()
{
    DWORD ret = 0;
    SERVICE_TABLE_ENTRY serviceTable[] =
    {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher(serviceTable) == FALSE)
    {
        log_debug(L"TiEtwSensor: Error starting Service Control Dispatcher\n");
    }

    return ret;
}
