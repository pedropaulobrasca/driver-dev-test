#include <ntifs.h>

extern "C" { //undocumented windows internal functions (exported by ntoskrnl)
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
}

void debug_print(PCSTR text) {
#ifdef DEBUG
	UNREFERENCED_PARAMETER(text);
#endif // DEBUG
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
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

    NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS bkp_device_control(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
        ULONG control_code = irp_sp->Parameters.DeviceIoControl.IoControlCode;

        auto* request = (driver::Request*)irp->AssociatedIrp.SystemBuffer;
        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

        switch (control_code) {
        case driver::codes::attach: {
            debug_print("[+] Comando attach recebido\n");
            status = STATUS_SUCCESS;
            break;
        }
        case driver::codes::read: {
            debug_print("[+] Comando read recebido\n");
            PEPROCESS target_process;
            status = PsLookupProcessByProcessId(request->process_id, &target_process);
            if (NT_SUCCESS(status)) {
                status = MmCopyVirtualMemory(target_process, request->target, PsGetCurrentProcess(), request->buffer, request->size, UserMode, &request->return_size);
                ObDereferenceObject(target_process);
            }
            break;
        }
        case driver::codes::write: {
            debug_print("[+] Comando write recebido\n");
            PEPROCESS target_process;
            status = PsLookupProcessByProcessId(request->process_id, &target_process);
            if (NT_SUCCESS(status)) {
                status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer, target_process, request->target, request->size, UserMode, &request->return_size);
                ObDereferenceObject(target_process);
            }
            break;
        }
        default: {
            debug_print("[-] Comando inválido recebido\n");
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
        }

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = (NT_SUCCESS(status)) ? sizeof(driver::Request) : 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
}

NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);

    // Inicializando uma string Unicode para o nome do dispositivo
    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, L"\\Device\\drivertest");

    // Criando um objeto de dispositivo
    PDEVICE_OBJECT device_object = nullptr;
    NTSTATUS status = IoCreateDevice(
        driver_object,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &device_object
    );

    if (!NT_SUCCESS(status)) {
        debug_print("[-] Falha ao criar o dispositivo\n");
        return status;
    }

    debug_print("[+] Driver criado com sucesso\n");

    // Inicializando uma string Unicode para o nome do link simbólico
    UNICODE_STRING sym_link;
    RtlInitUnicodeString(&sym_link, L"\\DosDevices\\drivertest");

    // Criando um link simbólico para o dispositivo
    status = IoCreateSymbolicLink(&sym_link, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object);
        debug_print("[-] Falha ao criar o link simbólico\n");
        return status;
    }

    debug_print("[+] Driver simbolico criado com sucesso\n");

    SetFlag(device_object->Flags, DO_BUFFERED_IO);

    // Configurando as rotinas de despacho do driver
    driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

    ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

    debug_print("[+] Driver inicializado com sucesso\n");

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry() {
	debug_print("[+] peuter from the kernell!\n");

	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\drivertest");

	return IoCreateDriver(&driver_name, driver_main);
}