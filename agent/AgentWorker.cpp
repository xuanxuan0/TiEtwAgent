#include "..\packages\Microsoft.O365.Security.Krabsetw.4.1.18\lib\native\include\krabs.hpp"

#include "TiEtwAgent.h"
#include "AgentService.h"
#include "DetectionLogic.h"
#include "YaraInstance.h"

using namespace krabs;

void report_detection(int detId, GenericEvent evt) {
    using std::to_string;
    using std::string;

    string sDump;
    string sOutBody;

    string procId =           to_string(evt.fields[L"CallingProcessId"]);
    string procImage =        get_pname(evt.fields[L"CallingProcessId"]);
    string targetProcId =     to_string(evt.fields[L"TargetProcessId"]);
    string targetProcImage =  get_pname(evt.fields[L"TargetProcessId"]);
    string protMask =         itohs(evt.fields[L"ProtectionMask"]);
    string allocType =        itohs(evt.fields[L"AllocationType"]);
    string size =             to_string(evt.fields[L"RegionSize"]);
    string baseAddr =         itohs(evt.fields[L"BaseAddress"]);

    switch (detId) {
        case ALLOCVM_REMOTE_META_GENERIC:
            sDump = dump_memory_ascii(evt.fields[L"TargetProcessId"], evt.fields[L"BaseAddress"], MEM_STR_SIZE);

            sOutBody = "\n\n\n\n[7;31mANOMALOUS MEMORY ALLOCATION DETECTED[0m \n\n";
            sOutBody += "[+] Source:       " + procImage + " (PID: " + procId + ")\n";
            sOutBody += "[+] Target:       " + targetProcImage + " (PID: " + targetProcId + ")\n";
            sOutBody += "[+] Protection:   " + protMask + "\n";
            sOutBody += "[+] Allocation:   " + allocType + "\n";
            sOutBody += "[+] Region size:  " + size + "\n";
            sOutBody += "[+] Base address: " + baseAddr + "\n";
            sOutBody += "[+] MZ-header:    ";

            if (sDump.rfind("MZ", 0) == 0) {
                sOutBody += "[31mYES[0m\n\n";
            }
            else {
                sOutBody += "[33mNO[0m\n\n";
            }

            sOutBody += "[+] Memory at location: \n\n";
            sOutBody += sDump;
            break;
        case ALLOCVM_REMOTE_SIGNATURES:
        default:
            return;
    }

    if (sOutBody.empty()) {
        log_debug(L"TiMemAgent: Failed to report detection");
        return;
    }

    if (!agent_message(sOutBody)) {
        log_debug(L"TiMemAgent: Failed to send agent message");
    }
    return;
}

VOID parse_generic_event(const EVENT_RECORD& record, const trace_context& trace_context) {
    schema schema(record, trace_context.schema_locator);
    parser parser(schema);  

    GenericEvent new_event;

    new_event.type = schema.event_id();

    try {
        for (property property : parser.properties()) {
            wstring wsPropertyName = property.name();
            if (new_event.fields.find(wsPropertyName) != new_event.fields.end()) {
                switch (property.type()) {
                case TDH_INTYPE_UINT32:
                    new_event.fields[wsPropertyName] = parser.parse<uint32_t>(wsPropertyName);
                    break;
                case TDH_INTYPE_POINTER:
                    new_event.fields[wsPropertyName] = parser.parse<pointer>(wsPropertyName).address;
                    break;
                }
            }
        }
    }

    catch (...) {
        log_debug(L"Error parsing the event\n");
        return;
    }

    if (new_event.fields.empty()) {
        log_debug(L"TiEtwAgent: Failed to parse an event\n");
    }
    else {
        detect_event(new_event);
    }
    return;
}

DWORD agent_worker()
{
    DWORD ret{ 0 };
    log_debug(L"TiEtwAgent: Started the agent worker\n");

    user_trace trace(ETS_NAME);
    provider<> provider(L"Microsoft-Windows-Threat-Intelligence");
    event_filter filter(predicates::id_is((int)KERNEL_THREATINT_TASK_ALLOCVM_REMOTE));

    if (YARA_ENABLED) {
        log_debug(L"TiEtwAgent: Setting up Yara\n");
        YaraInstance yi;

        yi.load_rules(YARA_RULE_DIR);
        log_debug(L"TiEtwAgent: Yara setup complete\n");
    }

    try {
        log_debug(L"TiEtwAgent: Setting up the trace session\n");
        provider.add_on_event_callback(parse_generic_event);
        provider.add_filter(filter);
        trace.enable(provider);

        trace.start();
    }
    catch (...) {
        log_debug(L"TiEtwAgent: Failed to setup a trace session\n");
        trace.stop();
    }
   
    ret = GetLastError();
    return ret;
}
