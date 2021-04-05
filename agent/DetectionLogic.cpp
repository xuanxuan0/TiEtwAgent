#include "DetectionLogic.h"
#include "TiMemAgent.h"

// Simple detection relying on metadata of the allocated memory page
const int ALLOC_PROTECTION{ PAGE_EXECUTE_READWRITE };
const int ALLOC_TYPE{ MEM_RESERVE | MEM_COMMIT };
const int MIN_REGION_SIZE{ 10240 };

VOID allocvm_remote_meta_generic(std::map<std::wstring, uint64_t> alloc_event) {
    if (alloc_event[L"RegionSize"] >= MIN_REGION_SIZE) {
        if (alloc_event[L"AllocationType"] == ALLOC_TYPE) {
            if (alloc_event[L"ProtectionMask"] == ALLOC_PROTECTION) {
                report_detection(ALLOCVM_REMOTE_META_GENERIC, alloc_event);
            }
        }
    }
    return;
}

// Trigger Yara scan of the remotely allocated memory page
VOID allocvm_remote_signatures(std::map<std::wstring, uint64_t> alloc_event) {
    return;
}

VOID detect_event(std::map<std::wstring, uint64_t> parsed_event, int eid) {
    // Run detection functions depending on source event type
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
