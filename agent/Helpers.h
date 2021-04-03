#pragma once
#include <Windows.h>

#define MAX_BUF_SIZE 2048
#define MEM_STR_SIZE 512

VOID log_debug(const wchar_t* format, ...);
std::string get_pname(uint64_t pid);
std::string dump_memory_ascii(uint64_t pid, uint64_t base_address, int length);