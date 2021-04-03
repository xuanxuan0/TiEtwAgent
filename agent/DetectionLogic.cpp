#include "DetectionLogic.h"
#include "TiMemAgent.h"

// Detection criteria for KERNEL_THREATINT_TASK_ALLOCVM_REMOTE
int ALLOC_PROTECTION{ PAGE_EXECUTE_READWRITE };
int ALLOC_TYPE{ MEM_RESERVE | MEM_COMMIT };
int MIN_REGION_SIZE{ 10240 };

// Detection relying solely on metadata of the allocated memory page
void allocvm_remote_detection(std::map<std::wstring, uint64_t> alloc_event) {
    if (alloc_event[L"RegionSize"] >= MIN_REGION_SIZE) {
        if (alloc_event[L"AllocationType"] == ALLOC_TYPE) {
            if (alloc_event[L"ProtectionMask"] == ALLOC_PROTECTION) {
                log_single_detection(KERNEL_THREATINT_TASK_ALLOCVM_REMOTE, alloc_event);
            }
        }
    }
}


