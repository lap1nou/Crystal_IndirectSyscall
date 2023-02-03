# Sources / references
# - https://github.com/crystal-lang/crystal/blob/b5317ace12d11f788f922a8884202dcb3b0de84b/src/crystal/system/win32/fiber.cr
# - https://crystal-lang.org/api/1.7.2/
# - Crystal community Discord
# - https://hfiref0x.github.io/NT10_syscalls.html
# - https://github.com/HavocFramework/Havoc -> has heavily inspired this code
# - https://blog.sektor7.net/#!res/2021/halosgate.md
# - https://alice.climent-pommeret.red/
# - https://github.com/reactos/reactos
# - Microsoft doc
# - Pinvoke.net
# - Ntinternals.net
# - https://www.ired.team/
# - https://github.com/cswuyg/simple_win/blob/f1acc34c57af41b617403c60dc1d56eab85a6754/get_parent_process/getparentprocess/getparentprocess.cpp

require "colorize"
require "winapi"

NUMBER_OF_SYSCALL = 494 # https://hfiref0x.github.io/NT10_syscalls.html

# Contain a syscall stub used as a template to construct other syscall stub
STUB_TEMPLATE = Bytes[ 
    0x4c, 0x8b ,0xd1 ,0xb8 ,0xff ,0x00 ,0x00 ,0x00 ,0xf6 ,0x04 ,0x25 ,0x08 ,0x03 ,0xfe ,0x7f ,0x01 ,0x75 ,0x03 ,0x0f ,0x05 ,0xc3 ,0xcd ,0x2e ,0xc3 ,0x0f ,0x1f ,0x84 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 
]

SYSCALL_ZONE_SIZE = STUB_TEMPLATE.size * NUMBER_OF_SYSCALL

# Windows API Macro defined in winternl.h
def initializeObjectAttributes(p : LibC::OBJECT_ATTRIBUTES*, n : LibC::UNICODE_STRING*, a : LibC::ULong, r : LibC::HANDLE, s : LibC::SECURITY_DESCRIPTOR*)
    p.value.length = sizeof(LibC::OBJECT_ATTRIBUTES)
    p.value.rootDirectory = r
    p.value.attributes = a
    p.value.objectName = n
    p.value.securityDescriptor = s
    p.value.securityQualityOfService = Pointer(Void).null
end

# This method init some indirect syscall used to get a handle over ntdll.dll
# For the moment static syscall id are used, but one should use something like HalosGate on the current loaded NTDLL to retrieve the first needed syscall ID dynamically
# For example, here is a better way to do it: https://github.com/HavocFramework/Havoc/blob/main/Teamserver/data/implants/Demon/Source/Core/Syscalls.c#L74
def syscallInit(memory_size : Int32) : Tuple(Hash(String, UInt32), Pointer(Void))
    puts "[*] Allocating space for all syscall stub"
    syscallZone = LibC.VirtualAlloc(nil, memory_size, LibC::MEM_COMMIT, 0x40) # Allocate space for all syscall stub

    puts "[*] Creating syscall stub for NtOpenFile with id 0x33"
    ntOpenFile = Proc(LibC::HANDLE*, LibC::DWORD, LibC::OBJECT_ATTRIBUTES*, LibC::IO_STATUS_BLOCK*, Int32, LibC::ULong, LibC::NTSTATUS).new(constructSyscallStub(0, 0x33, syscallZone), Pointer(Void).null)
    
    objectAttributes = LibC::OBJECT_ATTRIBUTES.new
    objectPath = LibC::UNICODE_STRING.new
    g = LibC::HANDLE.null

    filename = "\\??\\C:\\Windows\\System32\\ntdll.dll"

    objectPath.length = filename.size * sizeof(LibC::WCHAR)
    objectPath.maximumLength = filename.size * sizeof(LibC::WCHAR)
    objectPath.buffer = filename.to_utf16.to_unsafe

    initializeObjectAttributes(pointerof(objectAttributes), pointerof(objectPath), LibC::OBJ_CASE_INSENSITIVE, g, Pointer(LibC::SECURITY_DESCRIPTOR).null)
    hFile = LibC::HANDLE.null
    ioStatusBlock = LibC::IO_STATUS_BLOCK.new

    result = ntOpenFile.call(pointerof(hFile), LibC::FILE_READ_DATA, pointerof(objectAttributes), pointerof(ioStatusBlock), LibC::FILE_SHARE_READ, LibC::ULong.new(0x0))
 
    if result == LibC::NTSUCCESS
        puts "[+] Opening a clean ntdll.dll from disk with NtOpenFile".colorize(:green)
    end

    # Copy NtCreateSection stub
    puts "[*] Creating syscall stub for NtCreateSection with id 0x4a"
    ntCreateSection = Proc(LibC::HANDLE*, LibC::DWORD, LibC::OBJECT_ATTRIBUTES*, LibC::LARGE_INTEGER*, LibC::ULong, UInt32, LibC::HANDLE, LibC::NTSTATUS).new(constructSyscallStub(1, 0x4a, syscallZone), Pointer(Void).null)
    
    hSection = LibC::HANDLE.null

    # No idea why do I have to fill all parameter (even optional), I guess it because of stack size and alignement
    result = ntCreateSection.call(pointerof(hSection), LibC::SECTION_ALL_ACCESS, Pointer(LibC::OBJECT_ATTRIBUTES).null, Pointer(LibC::LARGE_INTEGER).null, LibC::PAGE_READONLY, LibC::SEC_COMMIT, hFile)
    
    if result == LibC::NTSUCCESS
        puts "[+] Creating a section for ntdll.dll using NtCreateSection".colorize(:green)
    end

    puts "[*] Creating syscall stub for NtMapViewOfSection with id 0x28"
    ntMapViewOfSection = Proc(LibC::HANDLE, LibC::HANDLE, Pointer(Void)*, Pointer(LibC::ULong), LibC::SizeT, Pointer(LibC::LARGE_INTEGER), LibC::SizeT*, Int32, Int32, LibC::ULong, LibC::NTSTATUS).new(constructSyscallStub(2, 0x28, syscallZone), Pointer(Void).null)
    
    pSection = Pointer(Void).null
    viewSize = LibC::SizeT.new(0)
    result = ntMapViewOfSection.call(hSection, LibC.GetCurrentProcess(), pointerof(pSection), Pointer(LibC::ULong).null, LibC::SizeT.new(0), Pointer(LibC::LARGE_INTEGER).null, pointerof(viewSize), 1, 0, LibC::PAGE_READONLY)
    
    if result == LibC::NTSUCCESS
        puts ("[+] Mapping the section for ntdll.dll using NtMapViewOfSection, the file should now be mapped in memory, here is the address: " + pSection.to_s).colorize(:green)
    end

    # https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++
    # Here we are parsing the PE file (our previously loaded clean ntdll), in order to retrieve exported functions and their addresses / names, etc...
    peOffset = pSection.as(LibC::IMAGE_DOS_HEADER*).value.e_lfanew

    imageNtHeaders = Pointer(LibC::IMAGE_NT_HEADERS).new(pSection.address + peOffset)

    dataDirectory = imageNtHeaders.value.optionalHeader.dataDirectory.as(StaticArray(LibC::IMAGE_DATA_DIRECTORY, 16))

    virtualAddress = dataDirectory[LibC::IMAGE_DIRECTORY_ENTRY_EXPORT].virtualAddress

    exportDirectory  = rvaToFileOffsetPointer(pSection, virtualAddress).as(LibC::IMAGE_EXPORT_DIRECTORY*)
    numberOfNames = exportDirectory.value.numberOfNames
    functions = rvaToFileOffsetPointer(pSection, exportDirectory.value.addressOfFunctions)
    names = rvaToFileOffsetPointer(pSection, exportDirectory.value.addressOfNames)
    ordinals = rvaToFileOffsetPointer(pSection, exportDirectory.value.addressOfNameOrdinals).as(LibC::WORD*)
    functionName = rvaToFileOffsetPointer(pSection, names[271]).as(Pointer(UInt8))

    # Constructing a hashmap with all syscall and their id, Syscall name, Syscall ID
    table = Hash(String, UInt32).new

    i = 0
    while i < numberOfNames
        functionName = rvaToFileOffsetPointer(pSection, names[i]).as(Pointer(UInt8))
        functionAddress = rvaToFileOffsetPointer(pSection, functions[ordinals[i]]).as(Pointer(UInt32))
        functionNameStr = String.new(functionName)
        
        if functionNameStr.starts_with?("Nt") || functionNameStr.starts_with?("Zw")
            table[functionNameStr] = (functionAddress+1).value
        end

        i += 1
    end

    return {table, syscallZone}
end

def constructSyscallStub(pos : UInt32, syscallID : UInt32, stubZone : Pointer(Void)) : Pointer(Void)
    STUB_TEMPLATE[4] = UInt8.new(syscallID)
    stub = IO::Memory.new(STUB_TEMPLATE)

    # Shouldn't use LLVM intrinsics here, pretty sure there is a cleaner way to do it
    puts "[*] Creating syscall stub with id " + syscallID.to_s
    Intrinsics.memcpy(stubZone + STUB_TEMPLATE.size * pos, stub.buffer, STUB_TEMPLATE.size, false)

    return stubZone + STUB_TEMPLATE.size * pos
end

# https://stackoverflow.com/questions/2975639/resolving-rvas-for-import-and-export-tables-within-a-pe-file
# The goal is to loop trough all PE section, and try to find in which section, our address belong
def rvaToFileOffsetPointer(pModule : Pointer(Void), dwRVA : LibC::DWORD) : LibC::DWORD*
    peOffset = pModule.as(LibC::IMAGE_DOS_HEADER*).value.e_lfanew
    imageNtHeaders = Pointer(LibC::IMAGE_NT_HEADERS).new(pModule.address + peOffset)

    tmp = imageNtHeaders.value.optionalHeader

    sectionHeader = imageNtHeaders.address + offsetof(LibC::IMAGE_NT_HEADERS, @optionalHeader) + imageNtHeaders.value.fileHeader.sizeOfOptionalHeader

    section = Pointer(LibC::IMAGE_SECTION_HEADER).new(sectionHeader)
    
    i = 0
    while i < imageNtHeaders.value.fileHeader.numberOfSections
        if (section[i].virtualAddress <= dwRVA) && (section[i].virtualAddress + section[i].tmp.virtualSize > dwRVA)
            dwRVA -= section[i].virtualAddress
            dwRVA += section[i].pointerToRawData
          
            return (pModule + dwRVA).as(LibC::ULong*)
        end
        i += 1
    end

    return Pointer(LibC::ULong).malloc(4)
end

tmp = syscallInit(SYSCALL_ZONE_SIZE)
table = tmp[0]
syscallZone = tmp[1]

# Now we can define all our direct syscall function pointer and use them
# "Proc()" is a Crystal object that represent a pointer of function, it take the function parameter, and the return value of the function at the end, 
# and for the parameter it take the address of the function we want to point to and another parameter for the closure that we don't use here
ntOpenProcess = Proc(LibC::HANDLE*, LibC::DWORD, LibC::OBJECT_ATTRIBUTES*, LibC::CLIENT_ID*, LibC::NTSTATUS).new(constructSyscallStub(0, table["NtOpenProcess"], syscallZone), Pointer(Void).null)
ntQueryInformationProcess = Proc(LibC::HANDLE, Int32, Pointer(Void), Int32, Pointer(LibC::DWORD), LibC::NTSTATUS).new(constructSyscallStub(1, table["NtQueryInformationProcess"], syscallZone), Pointer(Void).null)
#ntQuerySystemInformation = Proc().new(constructSyscallStub(2, table["NtQuerySystemInformation"], syscallZone), Pointer(Void).null)
#ntAllocateVirtualMemory = Proc().new(constructSyscallStub(3, table["NtAllocateVirtualMemory"], syscallZone), Pointer(Void).null)
#ntQueueApcThread = Proc().new(constructSyscallStub(4, table["NtQueueApcThread"], syscallZone), Pointer(Void).null)
#ntOpenThread = Proc().new(constructSyscallStub(5, table["NtOpenThread"], syscallZone), Pointer(Void).null)
#ntResumeThread = Proc().new(constructSyscallStub(6, table["NtResumeThread"], syscallZone), Pointer(Void).null)
#ntSuspendThread = Proc().new(constructSyscallStub(7, table["NtSuspendThread"], syscallZone), Pointer(Void).null)
#ntCreateEvent = Proc().new(constructSyscallStub(8, table["NtCreateEvent"], syscallZone), Pointer(Void).null)
#ntDuplicateObject = Proc().new(constructSyscallStub(9, table["NtDuplicateObject"], syscallZone), Pointer(Void).null)
#ntGetContextThread = Proc().new(constructSyscallStub(10, table["NtGetContextThread"], syscallZone), Pointer(Void).null)
#ntSetContextThread = Proc().new(constructSyscallStub(11, table["NtSetContextThread"], syscallZone), Pointer(Void).null)
#ntWaitForSingleObject = Proc().new(constructSyscallStub(12, table["NtWaitForSingleObject"], syscallZone), Pointer(Void).null)
#ntAlertResumeThread = Proc().new(constructSyscallStub(13, table["NtAlertResumeThread"], syscallZone), Pointer(Void).null)
#ntSignalAndWaitForSingleObject = Proc().new(constructSyscallStub(14, table["NtSignalAndWaitForSingleObject"], syscallZone), Pointer(Void).null)
#ntTestAlert = Proc().new(constructSyscallStub(15, table["NtTestAlert"], syscallZone), Pointer(Void).null)
#ntCreateThreadEx = Proc().new(constructSyscallStub(16, table["NtCreateThreadEx"], syscallZone), Pointer(Void).null)
#ntOpenProcessToken = Proc().new(constructSyscallStub(17, table["NtOpenProcessToken"], syscallZone), Pointer(Void).null)
#ntDuplicateToken = Proc().new(constructSyscallStub(18, table["NtDuplicateToken"], syscallZone), Pointer(Void).null)

size = LibC::DWORD.new(0)
pbi = Pointer(Void).malloc(sizeof(LibC::PROCESS_BASIC_INFORMATION))

# To execute our function pointer we can then use the "call()" method of the "Proc()"" object
res = ntQueryInformationProcess.call(LibC.GetCurrentProcess(), 0x0, pbi, sizeof(LibC::PROCESS_BASIC_INFORMATION), pointerof(size))

if res == LibC::NTSUCCESS
    puts ("[+] Here is the process id of the current process gathered using a direct syscall: " + pbi.as(LibC::PROCESS_BASIC_INFORMATION*).value.uniqueProcessId.address.to_s).colorize(:green)
end

gets
