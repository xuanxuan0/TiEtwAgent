#pragma once
#include <Windows.h>
#include <vector>
#include <iostream>
#include <map>
#include <string>

using std::vector;
using std::wstring;
using std::map;

enum TI_ETW_EVENTS {
    KERNEL_THREATINT_NO_TASK,
    KERNEL_THREATINT_TASK_ALLOCVM_REMOTE,
    KERNEL_THREATINT_TASK_PROTECTVM_REMOTE,
    KERNEL_THREATINT_TASK_MAPVIEW_REMOTE,
    KERNEL_THREATINT_TASK_QUEUEUSERAPC_REMOTE,
    KERNEL_THREATINT_TASK_SETTHREADCONTEXT_REMOTE,
    KERNEL_THREATINT_TASK_ALLOCVM_LOCAL,
    KERNEL_THREATINT_TASK_PROTECTVM_LOCAL,
    KERNEL_THREATINT_TASK_MAPVIEW_LOCAL,
    KERNEL_THREATINT_TASK_QUEUEUSERAPC_LOCAL,
    KERNEL_THREATINT_TASK_SETTHREADCONTEXT_LOCAL,
    KERNEL_THREATINT_TASK_READVM_LOCAL,
    KERNEL_THREATINT_TASK_WRITEVM_LOCAL,
    KERNEL_THREATINT_TASK_READVM_REMOTE,
    KERNEL_THREATINT_TASK_WRITEVM_REMOTE
};

enum DETECTIONS {
    NO_DETECTION,
    ALLOCVM_REMOTE_META_GENERIC,
    ALLOCVM_REMOTE_SIGNATURES
};

extern map<wstring, uint64_t> allocation_fields;

class GenericEvent {
public:
    uint8_t type;

    map<wstring, uint64_t> fields = { 
        {(wstring)L"CallingProcessId",0},
        {(wstring)L"TargetProcessId",0},
        {(wstring)L"AllocationType",0},
        {(wstring)L"ProtectionMask",0},
        {(wstring)L"RegionSize",0},
        {(wstring)L"BaseAddress",0} 
    };
};


VOID report_detection(int detId, GenericEvent evt);
VOID detect_event(GenericEvent evt);
