#include "Helpers.h"

// int to hex-string
std::string itohs(uint64_t i) {
    std::stringstream ss;
    ss << "0x" << std::hex << i;
    return ss.str();
}

std::string dump_memory_ascii(uint64_t pid, uint64_t base_address, int length) 
{
    CHAR cstr[MEM_STR_SIZE+1]{ 0 };
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

    if (hProcess) {
        DWORD buffSize = 1024;
        CHAR buffer[1024];
        if (QueryFullProcessImageNameA(hProcess, 0, buffer, &buffSize)) {
            ret = buffer;
        } else {
            ret = "";
        }
        CloseHandle(hProcess);
    } else {
        ret = "";
    }
    return ret;
}

BOOL agent_message(std::string message) {
    char csOutBody[MAX_BUF_SIZE*2]{ 0 };
    DWORD dwBytesWritten{ 0 };

    strcpy_s(csOutBody, message.c_str());

    HANDLE hFile;
    hFile = CreateFile(
        LOG_FNAME,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (INVALID_HANDLE_VALUE == hFile) {
        log_debug(L"Error acquiring a handle\n");
        return FALSE;
    }

    BOOL bWriteSuccess = WriteFile(
        hFile,
        csOutBody,
        (DWORD)strlen(csOutBody),
        &dwBytesWritten,
        NULL
    );

    if (FALSE == bWriteSuccess) {
        log_debug(L"TiMemAgent: Error writing to file\n");
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}

std::string ftostr(std::string& file_name) {
    std::ifstream f;
    std::stringstream ss;
    
    f.open(file_name);

    if (!f)
        return "";
    
    ss << f.rdbuf();
    return ss.str();
}

VOID log_debug(const wchar_t* format, ...)
{
    wchar_t message[512];
    va_list arg_ptr;
    va_start(arg_ptr, format);
    _vsnwprintf_s(message, 512, 512, format, arg_ptr);
    va_end(arg_ptr);
    OutputDebugString(message);
    wprintf(message);
}
