#include "TiMemAgent.h"
#include "AgentService.h"

DWORD install_elam()
{
    DWORD ret{ 0 };
    WCHAR driverName[]{ DRIVER_NAME };
    HANDLE hFile{ NULL };
    
    log_debug(L"TiEtwSensor: Opening driver file: %s\n", driverName);

    hFile = CreateFile(
        driverName,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        ret = 1;
        log_debug(L"TiEtwSensor: Unable to read driver file\n");
        return;
    }

    if (InstallELAMCertificateInfo(hFile) == FALSE) {
        ret = 1;
        log_debug(L"TiEtwSensor: Unable to install ELAM certificate\n");
        return;
    }

    log_debug(L"TiEtwSensor: ELAM driver has been installed successfully\n");
    return ret;
}

DWORD install_agent_service()
{
    DWORD ret = 0;
    SERVICE_LAUNCH_PROTECTED_INFO info;
    SC_HANDLE hService;
    SC_HANDLE hSCManager;

    DWORD SCManagerAccess = SC_MANAGER_ALL_ACCESS;
    hSCManager = OpenSCManager(NULL, NULL, SCManagerAccess);

    if (NULL == hSCManager) {
        ret = 1;
        log_debug(L"TiEtwSensor: Unable to open Service Control Manager\n");
        return ret;
    }

    wchar_t serviceCmd[MAX_BUF_SIZE]{ 0 };

    GetModuleFileName(
        NULL, 
        serviceCmd, 
        MAX_BUF_SIZE
    );

    DWORD serviceCmdLen = lstrlenW(serviceCmd);
    wcscpy_s(serviceCmd + serviceCmdLen, MAX_BUF_SIZE - serviceCmdLen, L" service");

    hService = CreateService(
        hSCManager,
        SERVICE_NAME,
        SERVICE_NAME,
        SCManagerAccess,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        serviceCmd,
        NULL,
        NULL,
        NULL,
        NULL, 
        NULL
    );

    if (NULL == hService) {
        ret = GetLastError();
        if (ret == ERROR_SERVICE_EXISTS) {
            log_debug(L"TiEtwSensor: Service '%s' already exists\n", SERVICE_NAME);
        }
        else {
            log_debug(L"TiEtwSensor: Unable to create new service: %d\n", ret);
        }
        return ret;
    }

    info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
    if (ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &info) == FALSE) {
        ret = GetLastError();
        log_debug(L"TiEtwSensor: Unable to change service config %d\n", ret);
        return ret;
    }

    log_debug(L"TiEtwSensor: Service has been installed successfully\n");
    return ret;
}


DWORD uninstall_agent_service() {
    DWORD ret = 0;
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    log_debug(L"TiEtwSensor: Uninstalling the service\n");

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (hSCManager == NULL) {
        ret = 1;
        log_debug(L"TiEtwSensor: Couldn't open Service Control Manager %d\n");
        return ret;
    }

    hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);

    if (hService == NULL) {
        ret = 1;
        log_debug(L"TiEtwSensor: Couldn't open the service\n");
        return ret;
    }

    if (!QueryServiceStatusEx(
        hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        ret = GetLastError();
        log_debug(L"TiEtwSensor: Couldn't query the service status: %d\n", ret);
        return ret;
    }

    if (ssp.dwCurrentState != SERVICE_STOPPED) {
        if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp)) {
            ret = GetLastError();
            log_debug(L"TiEtwSensor: ControlService(Stop) Error: %d\n", ret);
            return ret;
        }
        if (ssp.dwCurrentState != SERVICE_STOPPED) {
            Sleep(3000);
            if (!QueryServiceStatusEx(
                hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                ret = GetLastError();
                log_debug(L"TiEtwSensor: QueryServiceStatusEx2 Error: %d\n", ret);
                return ret;
            }
            if (ssp.dwCurrentState != SERVICE_STOPPED) {
                ret = ssp.dwCurrentState;
                log_debug(L"TiEtwSensor: Waited but service stull not stopped: %d\n", ret);
                return ret;
            }
        }
    }

    if (!DeleteService(hService)) {
        ret = GetLastError();
        log_debug(L"TiEtwSensor: DeleteService Error: %d\n", ret);
        return ret;
    }

    log_debug(L"TiEtwSensor: Deleted Service %s\n", SERVICE_NAME);

    return ret;
}

int main(INT argc, CHAR** argv)
{
    DWORD ret{ 0 };

    if (argc != 2) {
        log_debug(L"Usage: TiMemAgent.exe ( install | uninstall )\n");
        ret = 1;
    }
    else if (strcmp("install", argv[1]) == 0) {
        log_debug(L"TiEtwSensor: Installing the Early Launch Anti-Malware drivers\n");
        ret = install_elam();
        if (ret == 0) {
            log_debug(L"TiEtwSensor: Installing the agent service\n");
            ret = install_agent_service();
        }
    }
    else if (strcmp(argv[1], "service") == 0) {
        log_debug(L"TiEtwSensor: The service is starting up\n");
        ret = agent_service_init();
    }
    else if (strcmp(argv[1], "uninstall") == 0) {
        ret = uninstall_agent_service();
    }
    else {
        log_debug(L"TiEtwSensor: Unable to parse commandline\n");
        ret = 1;
    }
    return ret;
}
