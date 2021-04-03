#include "TiMemAgent.h"

std::string dump_memory_ascii(uint64_t pid, uint64_t base_address, int length) 
{
    CHAR cstr[MAX_BUF_SIZE]{ 0 };
    size_t sizeCstr;

    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    ReadProcessMemory(hTarget, (LPVOID)base_address, cstr, length, &sizeCstr);

    // Replace null bytes and problematic chars
    for (int i = 0; i < sizeCstr; i++) 
    {
        if (!__isascii(cstr[i]) || cstr[i] < 32) 
        {
            cstr[i] = 46;
        }
    }

    // Wrap line every 32 chars
    std::string s(cstr);
    std::stringstream ss;
    ss << s[0];
    for (int i = 1; i < s.size(); i++) {
        if (i % 32 == 0) {
            ss << '\n';
        }
            ss << s[i];
    }

    return ss.str();
}

std::string get_pname(uint64_t pid) {
    std::string ret;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid 
    );

    if (hProcess)
    {
        DWORD buffSize = 1024;
        CHAR buffer[1024];
        if (QueryFullProcessImageNameA(hProcess, 0, buffer, &buffSize))
        {
            ret = buffer;
        }
        else
        {
            ret = "";
        }
        CloseHandle(hProcess);
    }
    else
    {
        ret = "";
    }
    return ret;
}

VOID log_debug(const wchar_t* format, ...)
{
    wchar_t message[MAX_BUF_SIZE];
    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnwprintf_s(message, MAX_BUF_SIZE, MAX_BUF_SIZE, format, arg_ptr);
    va_end(arg_ptr);
    OutputDebugString(message);
    wprintf(message);
}
