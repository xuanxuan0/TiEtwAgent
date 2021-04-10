#include "DetectionLogic.h"

/************************************************************************************************************
ADD NEW DETECTION RULES BELOW, BASED ON THE allocvm_remote_mega_generic EXAMPLE
FIELD DECLARATIONS FOR EACH EVENT TYPE CAN BE FOUND HERE
https://github.com/jdu2600/Windows10EtwEvents/blob/master/manifest/Microsoft-Windows-Threat-Intelligence.tsv
************************************************************************************************************/

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

VOID detect_event(GenericEvent evt) {
    // Run detection functions depending on source event type
    switch (evt.type) {
        case KERNEL_THREATINT_TASK_ALLOCVM_REMOTE:
            allocvm_remote_meta_generic(evt);
            // your custom function here
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
