# This all the struct / constant / enum that are stored accross different header file, that weren't defined in the native WinAPI C binding of Crystal
lib LibC
    alias NTSTATUS = UInt32
    alias PVOID = Pointer(Void)
    alias PDWORD = Pointer(UInt32)

    enum SHUTDOWN_ACTION
        ShutdownNoReboot
        ShutdownReboot
        ShutdownPowerOff
    end

    struct UNICODE_STRING
        length : UShort
        maximumLength : UShort
        buffer : WCHAR*
    end

    struct IMAGE_NT_HEADERS
        signature : DWORD
        fileHeader : IMAGE_FILE_HEADER
        optionalHeader : IMAGE_OPTIONAL_HEADER64
    end

    struct IMAGE_FILE_HEADER
        machine : WORD
        numberOfSections : WORD
        timeDateStamp : DWORD
        pointerToSymbolTable : DWORD
        numberOfSymbols : DWORD
        sizeOfOptionalHeader : WORD
        characteristics : WORD
    end

    struct IMAGE_OPTIONAL_HEADER64
        magic    : WORD     
        majorlinkerversion    : BYTE     
        minorlinkerversion    : BYTE     
        sizeofcode    : DWORD    
        sizeofinitializeddata    : DWORD    
        sizeofuninitializeddata    : DWORD    
        addressofentrypoint    : DWORD    
        baseofcode    : DWORD    
        imagebase    : ULongLong
        sectionalignment    : DWORD    
        filealignment    : DWORD    
        majoroperatingsystemversion    : WORD     
        minoroperatingsystemversion    : WORD     
        majorimageversion    : WORD     
        minorimageversion    : WORD     
        majorsubsystemversion    : WORD     
        minorsubsystemversion    : WORD     
        win32versionvalue    : DWORD    
        sizeofimage    : DWORD    
        sizeofheaders    : DWORD    
        checksum    : DWORD    
        subsystem    : WORD     
        dllcharacteristics    : WORD     
        sizeofstackreserve    : ULongLong
        sizeofstackcommit    : ULongLong
        sizeofheapreserve    : ULongLong
        sizeofheapcommit    : ULongLong
        loaderflags    : DWORD    
        numberofrvaandsizes    : DWORD    
        dataDirectory : IMAGE_DATA_DIRECTORY[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]
    end

    struct IMAGE_DATA_DIRECTORY
        virtualAddress : DWORD
        size : DWORD
    end

    struct IMAGE_DOS_HEADER
        e_magic : WORD
        e_cblp : WORD
        e_cp : WORD
        e_crlc : WORD
        e_cparhdr : WORD
        e_minalloc : WORD
        e_maxalloc : WORD
        e_ss : WORD
        e_sp : WORD
        e_csum : WORD
        e_ip : WORD
        e_cs : WORD
        e_lfarlc : WORD
        e_ovno : WORD
        e_res : WORD[4]
        e_oemid : WORD
        e_oeminfo : WORD
        e_res2 : WORD[10]
        e_lfanew : LONG
    end

    struct IMAGE_SECTION_HEADER
        name : BYTE[IMAGE_SIZEOF_SHORT_NAME];
        tmp : Misc
        virtualAddress : DWORD 
        sizeOfRawData : DWORD 
        pointerToRawData : DWORD 
        pointerToRelocations : DWORD 
        pointerToLinenumbers : DWORD 
        numberOfRelocations : WORD  
        numberOfLinenumbers : WORD  
        characteristics : DWORD 
    end

    union Misc
        physicalAddress : DWORD
        virtualSize : DWORD
    end

    struct IMAGE_EXPORT_DIRECTORY
        characteristics : DWORD   
        timeDateStamp : DWORD   
        majorVersion : WORD    
        minorVersion : WORD    
        name : DWORD   
        base : DWORD   
        numberOfFunctions : DWORD   
        numberOfNames : DWORD   
        addressOfFunctions : DWORD   
        addressOfNames : DWORD   
        addressOfNameOrdinals : DWORD   
    end

    union IO_STATUS_BLOCK_UNION
        status : NTSTATUS
        pointer : PVOID
    end

    struct IO_STATUS_BLOCK
        tmp : IO_STATUS_BLOCK_UNION
        information : ULong*
    end

    struct OBJECT_ATTRIBUTES
        length : ULong
        rootDirectory : HANDLE
        objectName : UNICODE_STRING*
        attributes : ULong
        securityDescriptor : SECURITY_DESCRIPTOR*
        securityQualityOfService : PVOID
    end

    alias SECURITY_DESCRIPTOR_CONTROL = WORD

    struct ACL
        aclRevision : BYTE
        sbz1 : BYTE
        aclSize : WORD
        aceCount : WORD
        sbz2 : WORD
    end

    struct SID_IDENTIFIER_AUTHORITY
        value : BYTE[6]
    end

    struct SID
        revision : BYTE
        subAuthorityCount : BYTE
        identifierAuthority : SID_IDENTIFIER_AUTHORITY
        subAuthority : DWORD[1]
    end

    struct SECURITY_DESCRIPTOR
        revision : BYTE
        sbz1 : BYTE
        control : SECURITY_DESCRIPTOR_CONTROL
        owner : SID*
        group : SID*
        sacl : ACL*
        dacl : ACL*
    end

    struct CLIENT_ID
        uniqueProcess : HANDLE
        uniqueThread : HANDLE
    end

    struct PROCESS_BASIC_INFORMATION
        exitStatus : NTSTATUS
        pebBaseAddress : Pointer(Int32)
        affinityMask : Pointer(UInt32)
        basePriority : Int32
        uniqueProcessId : Pointer(UInt32)
        inheritedFromUniqueProcessId : Pointer(UInt32)
    end


    fun GetCurrentProcess() : LibC::HANDLE
    fun VirtualProtect(lpAddress : Void*, dwSize : SizeT, flNewProtect : DWORD, lpflOldProtect : PDWORD) : BOOL

    SECTION_ALL_ACCESS = DWORD.new(0xF001F)
    SECTION_MAP_READ = DWORD.new(0x0004)
    SECTION_MAP_WRITE = DWORD.new(0x0002)
    SECTION_MAP_EXECUTE = DWORD.new(0x0008)
    PAGE_READONLY = ULong.new(0x2)
    SEC_COMMIT = ULong.new(0x8000000)
    FILE_READ_DATA = DWORD.new(0x1)
    FILE_ANY_ACCESS = DWORD.new(0x00000000)
    FILE_EXECUTE = DWORD.new(0x00000020)
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
    IMAGE_DIRECTORY_ENTRY_EXPORT = 0
    IMAGE_SIZEOF_SHORT_NAME = 8
    OBJ_CASE_INSENSITIVE = LibC::ULong.new(0x00000040)
    NTSUCCESS = 0
end
