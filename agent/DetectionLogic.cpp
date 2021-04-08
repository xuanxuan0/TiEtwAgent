#include "DetectionLogic.h"
#include "TiMemAgent.h"

// Simple detection relying on metadata of the allocated memory page
const int ALLOC_PROTECTION{ PAGE_EXECUTE_READWRITE };
const int ALLOC_TYPE{ MEM_RESERVE | MEM_COMMIT };
const int MIN_REGION_SIZE{ 10240 };

DWORD allocvm_remote_meta_generic(GenericEvent alloc_event) {
    if (alloc_event.fields[L"RegionSize"] >= MIN_REGION_SIZE) {
        if (alloc_event.fields[L"AllocationType"] == ALLOC_TYPE) {
            if (alloc_event.fields[L"ProtectionMask"] == ALLOC_PROTECTION) {
                report_detection(ALLOCVM_REMOTE_META_GENERIC, alloc_event);
                return TRUE;
            }
        }
    }
    return FALSE;
}

// Trigger Yara scan of the remotely allocated memory page
VOID allocvm_remote_signatures(GenericEvent alloc_event) {
    return;
}

VOID detect_event(GenericEvent evt) {
    // Run detection functions depending on source event type
    switch (evt.type) {
        case KERNEL_THREATINT_TASK_ALLOCVM_REMOTE:
            allocvm_remote_meta_generic(evt);
            allocvm_remote_signatures(evt);
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
