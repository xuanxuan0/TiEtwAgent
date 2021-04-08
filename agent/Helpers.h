#pragma once
#include "TiMemAgent.h"
#include <Windows.h>

#define MAX_BUF_SIZE 2048
#define MEM_STR_SIZE 512

#define GET_VARIABLE_NAME(Variable) (#Variable)

std::string itohs(uint64_t i);
std::string get_pname(uint64_t pid);
std::string dump_memory_ascii(uint64_t pid, uint64_t base_address, int length);
BOOL agent_message(std::string message);
VOID log_debug(const wchar_t* format, ...);