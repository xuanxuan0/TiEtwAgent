#include "../packages/Microsoft.O365.Security.Krabsetw.4.1.18/lib/native/include/krabs.hpp"

#include "TiMemAgent.h"
#include "AgentService.h"
#include "DetectionLogic.h"

// Parse KERNEL_THREATINT_TASK_ALLOCVM_REMOTE
map<wstring, uint64_t> parse_allocvm_remote(krabs::schema schema, krabs::parser parser) {
    map<wstring, uint64_t> zero_map;
    map<wstring, uint64_t> allocation_fields = { {(wstring)L"CallingProcessId",0},
                                                 {(wstring)L"TargetProcessId",0},
                                                 {(wstring)L"AllocationType",0},
                                                 {(wstring)L"ProtectionMask",0},
                                                 {(wstring)L"RegionSize",0},
                                                 {(wstring)L"BaseAddress",0}
    };

    try {
        for (krabs::property property : parser.properties()) {
            std::wstring wsPropertyName = property.name();
            if (allocation_fields.find(wsPropertyName) != allocation_fields.end()) {
                // These are the only types of fields used for ALLOCVM_REMOTE detections
                switch (property.type()) {
                    case TDH_INTYPE_UINT32:
                        allocation_fields[wsPropertyName] = parser.parse<std::uint32_t>(wsPropertyName);
                        break; 
                    case TDH_INTYPE_POINTER:
                        allocation_fields[wsPropertyName] = parser.parse<krabs::pointer>(wsPropertyName).address;
                        break;
                }
            }
        }
        return allocation_fields;
    }
    catch (...) {
        log_debug(L"Error parsing the event\n");
        return zero_map;
    }
}

VOID parse_single_event(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    map<wstring, uint64_t> parsed_event;

    int eid = schema.event_id();

    switch (eid) {
        case KERNEL_THREATINT_TASK_ALLOCVM_REMOTE:
            parsed_event = parse_allocvm_remote(schema, parser);
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
            return;
    }
    if (parsed_event.empty()) {
        log_debug(L"TiEtwAgent: Failed to parse an event\n");
    }
    else {
        detect_event(parsed_event, eid);
    }
    return;
}

DWORD agent_worker()
{
    DWORD ret{ 0 };
    log_debug(L"TiEtwAgent: Started the agent worker\n");

    krabs::user_trace trace(ETS_NAME);
    krabs::provider<> provider(L"Microsoft-Windows-Threat-Intelligence");
    krabs::event_filter filter(krabs::predicates::id_is((int)KERNEL_THREATINT_TASK_ALLOCVM_REMOTE));

    try {
        log_debug(L"TiEtwAgent: Setting up the trace session\n");
        provider.add_on_event_callback(parse_single_event);
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
