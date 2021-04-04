#include "DetectionLogic.h"
#include "TiMemAgent.h"

void log_single_detection(int detId, map<wstring, uint64_t> evt_body) {
    std::string sDump;
    std::string sOutBody;

    switch (detId) {
        case ALLOCVM_REMOTE_META_GENERIC:
            sDump = dump_memory_ascii(evt_body[L"TargetProcessId"], evt_body[L"BaseAddress"], MEM_STR_SIZE);
            sOutBody = "\n\n\n\n[7;31mANOMALOUS MEMORY ALLOCATION DETECTED[0m \n\n";
            sOutBody += "[+] Source:       " + get_pname(evt_body[L"CallingProcessId"]) 
                      + " (PID: "            + std::to_string(evt_body[L"CallingProcessId"]) + ")\n";
            sOutBody += "[+] Target:       " + get_pname(evt_body[L"TargetProcessId"]) 
                      + " (PID: "            + std::to_string(evt_body[L"TargetProcessId"])  + ")\n";
            sOutBody += "[+] Protection:   " + itohs(evt_body[L"ProtectionMask"])            + "\n";
            sOutBody += "[+] Allocation:   " + itohs(evt_body[L"AllocationType"])            + "\n";
            sOutBody += "[+] Region size:  " + std::to_string(evt_body[L"RegionSize"])       + "\n";
            sOutBody += "[+] Base address: " + itohs(evt_body[L"BaseAddress"])               + "\n";
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

// Detection criteria for allocvm_remote_detection ( KERNEL_THREATINT_TASK_ALLOCVM_REMOTE )
const int ALLOC_PROTECTION{ PAGE_EXECUTE_READWRITE };
const int ALLOC_TYPE{ MEM_RESERVE | MEM_COMMIT };
const int MIN_REGION_SIZE{ 10240 };

// Simple detection relying solely on metadata of the allocated memory page
VOID allocvm_remote_meta_generic(std::map<std::wstring, uint64_t> alloc_event) {
    if (alloc_event[L"RegionSize"] >= MIN_REGION_SIZE) {
        if (alloc_event[L"AllocationType"] == ALLOC_TYPE) {
            if (alloc_event[L"ProtectionMask"] == ALLOC_PROTECTION) {
                log_single_detection(ALLOCVM_REMOTE_META_GENERIC, alloc_event);
            }
        }
    }
    return;
}

// Event-triggered Yara scan of the allocated memory page
VOID allocvm_remote_signatures(std::map<std::wstring, uint64_t> alloc_event) {
    log_single_detection(ALLOCVM_REMOTE_SIGNATURES, alloc_event);
    return;
}

VOID detect_event(std::map<std::wstring, uint64_t> parsed_event, int eid) {
    switch (eid) {
        case KERNEL_THREATINT_TASK_ALLOCVM_REMOTE:
            allocvm_remote_meta_generic(parsed_event);
            allocvm_remote_signatures(parsed_event);
            break;
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
            break;
    }
}
