#pragma once
#include "TiEtwAgent.h"

using std::string;

#define MAX_BUF_SIZE 2048
#define MEM_STR_SIZE 512

string itohs(uint64_t i);
string ftostr(string &file_name);
string get_pname(uint64_t pid);
string dump_memory_ascii(uint64_t pid, uint64_t base_address, int length);

BOOL agent_message(string message);

VOID log_debug(const wchar_t* format, ...);