#include "../packages/Microsoft.O365.Security.Krabsetw.4.1.18/lib/native/include/krabs.hpp"

#include "TiMemAgent.h"
#include "AgentService.h"
#include "DetectionLogic.h"

void log_single_detection(int evtId, map<wstring, uint64_t> evt_body) {
    std::string sDump;
    std::string sOutBody;
    char csOutBody[MAX_BUF_SIZE + MEM_STR_SIZE]{ 0 };
    DWORD dwBytesWritten{ 0 };
    
    switch (evtId) {
        case KERNEL_THREATINT_TASK_ALLOCVM_REMOTE:
            sDump = dump_memory_ascii(evt_body[L"TargetProcessId"], evt_body[L"BaseAddress"], MEM_STR_SIZE);
            sOutBody = "\n\n\n[7;31mANOMALOUS MEMORY ALLOCATION DETECTED[0m \n\n";
            sOutBody += "[+] Source:   " + get_pname(evt_body[L"CallingProcessId"]) + " (PID: " + std::to_string(evt_body[L"CallingProcessId"]) + ")\n";
            sOutBody += "[+] Target:   " + get_pname(evt_body[L"TargetProcessId"]) + + " (PID: " +std::to_string(evt_body[L"TargetProcessId"]) + ")\n";
            sOutBody += "[+] Protection:   " + std::to_string(evt_body[L"ProtectionMask"]) + "\n";
            sOutBody += "[+] Region size:  " + std::to_string(evt_body[L"RegionSize"]) + "\n";
            sOutBody += "[+] Base address: " + std::to_string(evt_body[L"BaseAddress"]) + "\n";
            sOutBody += "[+] MZ-header: ";
            if (sDump.rfind("MZ", 0) == 0) {
                sOutBody += "[31mYes[0m\n\n";
            }
            else {
                sOutBody += "[33mNo[0m\n\n";
            }
            sOutBody += "[+] Memory at location: (ASCII)\n\n";
            sOutBody += sDump;
            break;
        default:
            return;
    }

    strcpy_s(csOutBody, sOutBody.c_str());

    HANDLE hFile;
    hFile = CreateFile(LOG_FNAME,
                       FILE_APPEND_DATA,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

    if (INVALID_HANDLE_VALUE == hFile) {
        log_debug(L"Error acquiring a handle\n");
        return;
    }


    BOOL bWriteSuccess = WriteFile(hFile,
                                   csOutBody,
                                   (DWORD)strlen(csOutBody),
                                   &dwBytesWritten,
                                   NULL);

    if (FALSE == bWriteSuccess) {
        log_debug(L"Error writing to file\n");
        return;
    }

    CloseHandle(hFile);
    return;
}

// Parse KERNEL_THREATINT_TASK_ALLOCVM_REMOTE
void parse_alloc_rem_event(krabs::schema schema, krabs::parser parser) {

    map<wstring, uint64_t> allocation_fields = { {(wstring)L"CallingProcessId",0},
                                                 {(wstring)L"TargetProcessId",0},
                                                 {(wstring)L"AllocationType",0},
                                                 {(wstring)L"ProtectionMask",0},
                                                 {(wstring)L"RegionSize",0},
                                                 {(wstring)L"BaseAddress",0}
    };

    try {
        for (auto& [_, v] : allocation_fields) v = 0;
        for (krabs::property property : parser.properties()) {
            std::wstring wsPropertyName = property.name();
            if (allocation_fields.find(wsPropertyName) != allocation_fields.end()) {
                switch (property.type()) {
                    // These are the only types for fields used for ALLOCVM_REMOTE
                    // Field->Type mappings for other fields can be looked up here: 
                    // https://github.com/jdu2600/Windows10EtwEvents/blob/master/manifest/Microsoft-Windows-Threat-Intelligence.tsv
                    case TDH_INTYPE_UINT32:
                        allocation_fields[wsPropertyName] = parser.parse<std::uint32_t>(wsPropertyName);
                        break; 
                    case TDH_INTYPE_POINTER:
                        allocation_fields[wsPropertyName] = parser.parse<krabs::pointer>(wsPropertyName).address;
                        break;
                }
            }
        }
        allocvm_remote_detection(allocation_fields);
        log_debug(L"%d", allocation_fields[L"RegionSize"]);
        log_single_detection(1, allocation_fields);
        return;
    }
    catch (...) {
        log_debug(L"Error parsing the event\n");
        return;
    }
return;
}

VOID parse_single_event(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    int eid = schema.event_id();

    switch (eid) {
        case KERNEL_THREATINT_TASK_ALLOCVM_REMOTE:
            parse_alloc_rem_event(schema, parser);
            break;
        // Currently unsupported event types
        case KERNEL_THREATINT_TASK_PROTECTVM_REMOTE:
        case KERNEL_THREATINT_TASK_MAPVIEW_REMOTE:
        case KERNEL_THREATINT_TASK_QUEUEUSERAPC_REMOTE:
        case KERNEL_THREATINT_TASK_SETTHREADCONTEXT_REMOTE:
        case KERNEL_THREATINT_TASK_ALLOCVM_LOCAL:
        case KERNEL_THREATINT_TASK_PROTECTVM_LOCAL:
        case KERNEL_THREATINT_TASK_MAPVIEW_LOCAL:
        case KERNEL_THREATINT_TASK_QUEUEUSERAPC_LOCAL:
        case KERNEL_THREATINT_TASK_SETTHREADCONTEXT_LOCAL:
        case KERNEL_THREATINT_TASK_READVM_LOCAL:
        case KERNEL_THREATINT_TASK_WRITEVM_LOCAL:
        case KERNEL_THREATINT_TASK_READVM_REMOTE:
        case KERNEL_THREATINT_TASK_WRITEVM_REMOTE:
        default:
            log_debug(L"TiEtwAgent: Unable to resolve event type, or event type is not supported\n");
            break;
    }
    return;
}

DWORD agent_worker()
{
    log_debug(L"TiEtwAgent: Started the agent worker\n");
    krabs::user_trace trace(ETS_NAME);
    krabs::provider<> provider(L"Microsoft-Windows-Threat-Intelligence");
    krabs::event_filter filter(krabs::predicates::id_is((int)KERNEL_THREATINT_TASK_ALLOCVM_REMOTE));
    
    provider.add_on_event_callback(parse_single_event);
    provider.add_filter(filter);
    trace.enable(provider);

    DWORD ret{ 0 };
    try {
        trace.start();
    }
    catch (...) {
        log_debug(L"TiEtwAgent: Exception while initializing the trace. Error%d\n", ret);
        trace.stop();
    }

    ret = GetLastError();
    return ret;
}
