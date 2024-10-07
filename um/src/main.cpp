#include <iostream>

#include <Windows.h>
#include <TlHelp32.h>

static DWORD get_process_id(const wchar_t* process_name) {
    DWORD process_id = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, process_name) == 0) {
                process_id = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return process_id;
}

static std::uintptr_t get_module_base(const DWORD pid, const wchar_t* module_name) {
    uintptr_t module_base = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32W module_entry;
    module_entry.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(snapshot, &module_entry)) {
        do {
            if (_wcsicmp(module_entry.szModule, module_name) == 0) {
                module_base = reinterpret_cast<uintptr_t>(module_entry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snapshot, &module_entry));
    }

    CloseHandle(snapshot);
    return module_base;
}

namespace driver {
    namespace codes {
        constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    struct Request {
        HANDLE process_id;

        PVOID target;
        PVOID buffer;

        SIZE_T size;
        SIZE_T return_size;
    };

    bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
        Request request;
        request.process_id = reinterpret_cast<HANDLE>(pid);

        DWORD returned;
        BOOL success = DeviceIoControl(
            driver_handle,
            codes::attach,
            &request,
            sizeof(request),
            &request,
            sizeof(request),
            &returned,
            nullptr
        );

        if (!success) {
            std::cerr << "[-] Falha ao anexar ao processo." << std::endl;
            return false;
        }

        std::cout << "[+] Anexado ao processo com sucesso." << std::endl;
        return true;
    }

    template <class T>
    T read_memory(HANDLE driver_handle, const std::uintptr_t addr) {
        Request request;
        request.target = reinterpret_cast<PVOID>(addr);
        request.buffer = malloc(sizeof(T));
        request.size = sizeof(T);
        request.return_size = 0;

        DWORD returned;
        BOOL success = DeviceIoControl(
            driver_handle,
            codes::read,
            &request,
            sizeof(request),
            &request,
            sizeof(request),
            &returned,
            nullptr
        );

        if (!success || request.return_size != sizeof(T)) {
            std::cerr << "[-] Falha ao ler memória." << std::endl;
            free(request.buffer);
            return T{};
        }

        T value = *reinterpret_cast<T*>(request.buffer);
        free(request.buffer);
        return value;
    }

    template <class T>
    void write_memory(HANDLE driver_handle, const std::uintptr_t addr, const T& value) {
        Request request;
        request.target = reinterpret_cast<PVOID>(addr);
        request.buffer = (PVOID)&value;
        request.size = sizeof(T);

        DeviceIoControl(
            driver_handle,
            codes::write,
            &request,
            sizeof(request),
            &request,
            sizeof(request),
            nullptr,
            nullptr
        );
    }
}

int main() {
    const DWORD pid = get_process_id(L"notepad.exe");

    if (pid == 0) {
        std::cout << "Falha ao encontrar notepad.exe" << std::endl;
        std::cin.get();
        return 1;
    }

    const HANDLE driver = CreateFile(L"\\\\.\\drivertest", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (driver == INVALID_HANDLE_VALUE) {
        std::cout << "Falha ao criar o driver handle" << std::endl;
        std::cin.get();
        return 1;
    }

    if (driver::attach_to_process(driver, pid) == true) {
        std::cout << "Attach sucessful" << std::endl;
    }

    CloseHandle(driver);

    std::cin.get();

	return 0;
}