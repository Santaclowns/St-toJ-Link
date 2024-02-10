typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void *HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void *PVOID;

typedef ulong DWORD;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef ushort WORD;

typedef BYTE *LPBYTE;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _STARTUPINFOW *LPSTARTUPINFOW;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT *PCONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
};

typedef struct _iobuf FILE;

typedef char *va_list;

typedef uint uintptr_t;

typedef struct lconv lconv, *Plconv;

struct lconv {
    char *decimal_point;
    char *thousands_sep;
    char *grouping;
    char *int_curr_symbol;
    char *currency_symbol;
    char *mon_decimal_point;
    char *mon_thousands_sep;
    char *mon_grouping;
    char *positive_sign;
    char *negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t *_W_decimal_point;
    wchar_t *_W_thousands_sep;
    wchar_t *_W_int_curr_symbol;
    wchar_t *_W_currency_symbol;
    wchar_t *_W_mon_decimal_point;
    wchar_t *_W_mon_thousands_sep;
    wchar_t *_W_positive_sign;
    wchar_t *_W_negative_sign;
};

typedef ushort wint_t;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct *pthreadlocinfo;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

struct localerefcount {
    char *locale;
    wchar_t *wlocale;
    int *refcount;
    int *wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int *lconv_intl_refcount;
    int *lconv_num_refcount;
    int *lconv_mon_refcount;
    struct lconv *lconv;
    int *ctype1_refcount;
    ushort *ctype1;
    ushort *pctype;
    uchar *pclmap;
    uchar *pcumap;
    struct __lc_time_data *lc_time_curr;
    wchar_t *locale_name[6];
};

struct __lc_time_data {
    char *wday_abbr[7];
    char *wday[7];
    char *month_abbr[12];
    char *month[12];
    char *ampm[2];
    char *ww_sdatefmt;
    char *ww_ldatefmt;
    char *ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t *_W_wday_abbr[7];
    wchar_t *_W_wday[7];
    wchar_t *_W_month_abbr[12];
    wchar_t *_W_month[12];
    wchar_t *_W_ampm[2];
    wchar_t *_W_ww_sdatefmt;
    wchar_t *_W_ww_ldatefmt;
    wchar_t *_W_ww_timefmt;
    wchar_t *_W_ww_locale_name;
};

typedef uint size_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct *pthreadmbcinfo;

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t *mblocalename;
};

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef size_t rsize_t;

typedef PVOID HDEVINFO;

typedef struct _SP_DEVICE_INTERFACE_DATA _SP_DEVICE_INTERFACE_DATA, *P_SP_DEVICE_INTERFACE_DATA;


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

struct _SP_DEVICE_INTERFACE_DATA {
    DWORD cbSize;
    GUID InterfaceClassGuid;
    DWORD Flags;
    ULONG_PTR Reserved;
};

typedef struct _SP_DEVICE_INTERFACE_DETAIL_DATA_A _SP_DEVICE_INTERFACE_DETAIL_DATA_A, *P_SP_DEVICE_INTERFACE_DETAIL_DATA_A;

typedef char CHAR;

struct _SP_DEVICE_INTERFACE_DETAIL_DATA_A {
    DWORD cbSize;
    CHAR DevicePath[1];
};

typedef struct _SP_DEVINFO_DATA _SP_DEVINFO_DATA, *P_SP_DEVINFO_DATA;

struct _SP_DEVINFO_DATA {
    DWORD cbSize;
    GUID ClassGuid;
    DWORD DevInst;
    ULONG_PTR Reserved;
};

typedef struct _SP_DEVICE_INTERFACE_DATA *PSP_DEVICE_INTERFACE_DATA;

typedef struct _SP_DEVICE_INTERFACE_DETAIL_DATA_A *PSP_DEVICE_INTERFACE_DETAIL_DATA_A;

typedef struct _SP_DEVINFO_DATA *PSP_DEVINFO_DATA;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_226 _union_226, *P_union_226;

union _union_226 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_226 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef enum _HEAP_INFORMATION_CLASS {
    HeapCompatibilityInformation=0,
    HeapEnableTerminationOnCorruption=1
} _HEAP_INFORMATION_CLASS;

typedef CHAR *LPCSTR;

typedef LONG *PLONG;

typedef CHAR *LPSTR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef enum _HEAP_INFORMATION_CLASS HEAP_INFORMATION_CLASS;

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef CHAR *PCSTR;

typedef CHAR *PSTR;

typedef DWORD LCID;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef DWORD *PDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef int (*FARPROC)(void);

typedef WORD *LPWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef BOOL *LPBOOL;

typedef BYTE *PBYTE;

typedef void *LPCVOID;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
};

typedef LONG LSTATUS;

typedef struct setloc_struct setloc_struct, *Psetloc_struct;

typedef struct _is_ctype_compatible _is_ctype_compatible, *P_is_ctype_compatible;

struct _is_ctype_compatible {
    ulong id;
    int is_clike;
};

struct setloc_struct {
    wchar_t *pchLanguage;
    wchar_t *pchCountry;
    int iLocState;
    int iPrimaryLen;
    BOOL bAbbrevLanguage;
    BOOL bAbbrevCountry;
    UINT _cachecp;
    wchar_t _cachein[131];
    wchar_t _cacheout[131];
    struct _is_ctype_compatible _Loc_c[5];
    wchar_t _cacheLocaleName[85];
};

typedef struct _tiddata _tiddata, *P_tiddata;

typedef struct setloc_struct _setloc_struct;

struct _tiddata {
    ulong _tid;
    uintptr_t _thandle;
    int _terrno;
    ulong _tdoserrno;
    uint _fpds;
    ulong _holdrand;
    char *_token;
    wchar_t *_wtoken;
    uchar *_mtoken;
    char *_errmsg;
    wchar_t *_werrmsg;
    char *_namebuf0;
    wchar_t *_wnamebuf0;
    char *_namebuf1;
    wchar_t *_wnamebuf1;
    char *_asctimebuf;
    wchar_t *_wasctimebuf;
    void *_gmtimebuf;
    char *_cvtbuf;
    uchar _con_ch_buf[5];
    ushort _ch_buf_used;
    void *_initaddr;
    void *_initarg;
    void *_pxcptacttab;
    void *_tpxcptinfoptrs;
    int _tfpecode;
    pthreadmbcinfo ptmbcinfo;
    pthreadlocinfo ptlocinfo;
    int _ownlocale;
    ulong _NLG_dwCode;
    void *_terminate;
    void *_unexpected;
    void *_translator;
    void *_purecall;
    void *_curexception;
    void *_curcontext;
    int _ProcessingThrow;
    void *_curexcspec;
    void *_pFrameInfoChain;
    _setloc_struct _setloc_data;
    void *_reserved1;
    void *_reserved2;
    void *_reserved3;
    void *_reserved4;
    void *_reserved5;
    int _cxxReThrow;
    ulong __initDomain;
    int _initapartment;
};

typedef struct _tiddata *_ptiddata;

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);




void __cdecl FUN_00401000(uint *param_1,uint *param_2)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  uVar4 = param_1[2];
  uVar5 = *param_1;
  uVar6 = param_1[1];
  uVar2 = param_1[3];
  *param_2 = uVar5;
  param_2[1] = uVar6;
  param_2[2] = uVar4;
  param_2[3] = uVar2;
  puVar3 = param_2 + 5;
  param_2 = &DAT_0042b614;
  do {
    uVar5 = uVar5 ^ CONCAT31(CONCAT21(CONCAT11((&DAT_0042b410)[uVar2 >> 0x10 & 0xff],
                                               (&DAT_0042b410)[uVar2 >> 8 & 0xff]),
                                      (&DAT_0042b410)[uVar2 & 0xff]),(&DAT_0042b410)[uVar2 >> 0x18])
                    ^ param_2[-1];
    uVar6 = uVar6 ^ uVar5;
    uVar4 = uVar4 ^ uVar6;
    uVar2 = uVar2 ^ uVar4;
    puVar3[-1] = uVar5;
    *puVar3 = uVar6;
    puVar3[1] = uVar4;
    puVar3[2] = uVar2;
    uVar5 = uVar5 ^ CONCAT31(CONCAT21(CONCAT11((&DAT_0042b410)[uVar2 >> 0x10 & 0xff],
                                               (&DAT_0042b410)[uVar2 >> 8 & 0xff]),
                                      (&DAT_0042b410)[uVar2 & 0xff]),(&DAT_0042b410)[uVar2 >> 0x18])
                    ^ *param_2;
    uVar6 = uVar6 ^ uVar5;
    uVar4 = uVar4 ^ uVar6;
    uVar2 = uVar2 ^ uVar4;
    puVar3[3] = uVar5;
    puVar3[4] = uVar6;
    puVar3[5] = uVar4;
    puVar3[6] = uVar2;
    uVar5 = uVar5 ^ CONCAT31(CONCAT21(CONCAT11((&DAT_0042b410)[uVar2 >> 0x10 & 0xff],
                                               (&DAT_0042b410)[uVar2 >> 8 & 0xff]),
                                      (&DAT_0042b410)[uVar2 & 0xff]),(&DAT_0042b410)[uVar2 >> 0x18])
                    ^ param_2[1];
    uVar6 = uVar6 ^ uVar5;
    uVar4 = uVar4 ^ uVar6;
    uVar2 = uVar2 ^ uVar4;
    puVar3[7] = uVar5;
    puVar3[8] = uVar6;
    puVar3[9] = uVar4;
    puVar3[10] = uVar2;
    uVar5 = uVar5 ^ CONCAT31(CONCAT21(CONCAT11((&DAT_0042b410)[uVar2 >> 0x10 & 0xff],
                                               (&DAT_0042b410)[uVar2 >> 8 & 0xff]),
                                      (&DAT_0042b410)[uVar2 & 0xff]),(&DAT_0042b410)[uVar2 >> 0x18])
                    ^ param_2[2];
    uVar6 = uVar6 ^ uVar5;
    uVar4 = uVar4 ^ uVar6;
    uVar2 = uVar2 ^ uVar4;
    puVar3[0xb] = uVar5;
    puVar3[0xc] = uVar6;
    puVar3[0xd] = uVar4;
    puVar3[0xe] = uVar2;
    puVar1 = param_2 + 3;
    param_2 = param_2 + 5;
    uVar5 = uVar5 ^ CONCAT31(CONCAT21(CONCAT11((&DAT_0042b410)[uVar2 >> 0x10 & 0xff],
                                               (&DAT_0042b410)[uVar2 >> 8 & 0xff]),
                                      (&DAT_0042b410)[uVar2 & 0xff]),(&DAT_0042b410)[uVar2 >> 0x18])
                    ^ *puVar1;
    uVar6 = uVar6 ^ uVar5;
    uVar4 = uVar4 ^ uVar6;
    uVar2 = uVar2 ^ uVar4;
    puVar3[0xf] = uVar5;
    puVar3[0x10] = uVar6;
    puVar3[0x11] = uVar4;
    puVar3[0x12] = uVar2;
    puVar3 = puVar3 + 0x14;
  } while ((int)param_2 < 0x42b63c);
  return;
}



void __cdecl FUN_0040168c(uint *param_1,uint *param_2,uint *param_3)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  undefined uVar7;
  undefined uVar8;
  undefined uVar9;
  undefined uVar10;
  undefined uVar11;
  undefined uVar12;
  uint3 uVar13;
  uint3 uVar14;
  uint3 uVar15;
  uint3 uVar16;
  uint *puVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  uint uVar24;
  uint uVar25;
  uint uVar26;
  uint *local_c;
  int local_4;
  
  uVar24 = param_1[1] ^ param_3[1];
  uVar25 = *param_1 ^ *param_3;
  uVar19 = param_1[3] ^ param_3[3];
  local_4 = 9;
  param_1 = (uint *)(param_1[2] ^ param_3[2]);
  puVar17 = param_3 + 4;
  do {
    local_c = puVar17;
    uVar13 = CONCAT21(CONCAT11((&DAT_0042b410)[uVar25 >> 0x18],
                               (&DAT_0042b410)[uVar24 >> 0x10 & 0xff]),
                      (&DAT_0042b410)[(uint)param_1 >> 8 & 0xff]);
    uVar18 = CONCAT31(uVar13,(&DAT_0042b410)[uVar19 & 0xff]);
    uVar14 = CONCAT21(CONCAT11((&DAT_0042b410)[uVar24 >> 0x18],
                               (&DAT_0042b410)[(uint)param_1 >> 0x10 & 0xff]),
                      (&DAT_0042b410)[uVar19 >> 8 & 0xff]);
    uVar21 = CONCAT31(uVar14,(&DAT_0042b410)[uVar25 & 0xff]);
    uVar15 = CONCAT21(CONCAT11((&DAT_0042b410)[(uint)param_1 >> 0x18],
                               (&DAT_0042b410)[uVar19 >> 0x10 & 0xff]),
                      (&DAT_0042b410)[uVar25 >> 8 & 0xff]);
    uVar20 = uVar25 >> 0x10;
    uVar26 = CONCAT31(uVar15,(&DAT_0042b410)[uVar24 & 0xff]);
    uVar16 = CONCAT21(CONCAT11((&DAT_0042b410)[uVar19 >> 0x18],(&DAT_0042b410)[uVar20 & 0xff]),
                      (&DAT_0042b410)[uVar24 >> 8 & 0xff]);
    uVar22 = CONCAT31(uVar16,(&DAT_0042b410)[(uint)param_1 & 0xff]);
    uVar23 = (uVar18 >> 7 & 0x1010101) * 0x1b;
    uVar25 = (uVar18 << 0x10 |
             (uint)CONCAT11((&DAT_0042b410)[uVar25 >> 0x18],(&DAT_0042b410)[uVar24 >> 0x10 & 0xff]))
             ^ ((uint)uVar13 | uVar18 << 0x18) ^
             (((uVar18 & 0xffff7f7f) * 2 ^ uVar18) << 8 ^ (uVar18 >> 7 & 0x10101) * 0x1b00 |
             ((uVar23 ^ uVar18) >> 1 ^ (uVar13 & 0x7f0000) << 8) >> 0x17) ^
             (uVar18 & 0xff7f7f7f) * 2 ^ uVar23 ^ *local_c;
    uVar18 = (uVar21 >> 7 & 0x1010101) * 0x1b;
    uVar24 = (uVar21 << 0x10 |
             (uint)CONCAT11((&DAT_0042b410)[uVar24 >> 0x18],
                            (&DAT_0042b410)[(uint)param_1 >> 0x10 & 0xff])) ^
             ((uint)uVar14 | uVar21 << 0x18) ^
             (((uVar21 & 0xffff7f7f) * 2 ^ uVar21) << 8 ^ (uVar21 >> 7 & 0x10101) * 0x1b00 |
             ((uVar18 ^ uVar21) >> 1 ^ (uVar14 & 0x7f0000) << 8) >> 0x17) ^
             (uVar21 & 0xff7f7f7f) * 2 ^ local_c[1] ^ uVar18;
    uVar18 = (uVar26 >> 7 & 0x1010101) * 0x1b;
    param_1 = (uint *)((uVar26 << 0x10 |
                       (uint)CONCAT11((&DAT_0042b410)[(uint)param_1 >> 0x18],
                                      (&DAT_0042b410)[uVar19 >> 0x10 & 0xff])) ^
                       ((uint)uVar15 | uVar26 << 0x18) ^
                       (((uVar26 & 0xffff7f7f) * 2 ^ uVar26) << 8 ^ (uVar26 >> 7 & 0x10101) * 0x1b00
                       | ((uVar18 ^ uVar26) >> 1 ^ (uVar15 & 0x7f0000) << 8) >> 0x17) ^
                       (uVar26 & 0xff7f7f7f) * 2 ^ local_c[2] ^ uVar18);
    uVar18 = (uVar22 >> 7 & 0x1010101) * 0x1b;
    uVar19 = (uVar22 << 0x10 |
             (uint)CONCAT11((&DAT_0042b410)[uVar19 >> 0x18],(&DAT_0042b410)[uVar20 & 0xff])) ^
             ((uint)uVar16 | uVar22 << 0x18) ^
             (((uVar22 & 0xffff7f7f) * 2 ^ uVar22) << 8 ^ (uVar22 >> 7 & 0x10101) * 0x1b00 |
             ((uVar18 ^ uVar22) >> 1 ^ (uVar16 & 0x7f0000) << 8) >> 0x17) ^
             (uVar22 & 0xff7f7f7f) * 2 ^ local_c[3] ^ uVar18;
    local_4 = local_4 + -1;
    puVar17 = local_c + 4;
  } while (local_4 != 0);
  uVar4 = (&DAT_0042b410)[uVar19 >> 0x10 & 0xff];
  uVar1 = (&DAT_0042b410)[(uint)param_1 >> 0x18];
  uVar5 = (&DAT_0042b410)[uVar25 >> 8 & 0xff];
  uVar6 = (&DAT_0042b410)[uVar24 & 0xff];
  uVar18 = local_c[6];
  uVar7 = (&DAT_0042b410)[uVar25 >> 0x10 & 0xff];
  uVar2 = (&DAT_0042b410)[uVar19 >> 0x18];
  uVar8 = (&DAT_0042b410)[uVar24 >> 8 & 0xff];
  uVar9 = (&DAT_0042b410)[(uint)param_1 & 0xff];
  uVar10 = (&DAT_0042b410)[uVar24 >> 0x10 & 0xff];
  uVar20 = local_c[7];
  uVar3 = (&DAT_0042b410)[uVar25 >> 0x18];
  uVar11 = (&DAT_0042b410)[(uint)param_1 >> 8 & 0xff];
  uVar12 = (&DAT_0042b410)[uVar19 & 0xff];
  uVar21 = local_c[4];
  param_2[1] = CONCAT31(CONCAT21(CONCAT11((&DAT_0042b410)[uVar24 >> 0x18],
                                          (&DAT_0042b410)[(uint)param_1 >> 0x10 & 0xff]),
                                 (&DAT_0042b410)[uVar19 >> 8 & 0xff]),(&DAT_0042b410)[uVar25 & 0xff]
                       ) ^ local_c[5];
  param_2[2] = CONCAT31(CONCAT21(CONCAT11(uVar1,uVar4),uVar5),uVar6) ^ uVar18;
  *param_2 = CONCAT31(CONCAT21(CONCAT11(uVar3,uVar10),uVar11),uVar12) ^ uVar21;
  param_2[3] = CONCAT31(CONCAT21(CONCAT11(uVar2,uVar7),uVar8),uVar9) ^ uVar20;
  return;
}



void __cdecl FUN_00401ac0(undefined *param_1,char *param_2,char *param_3,char *param_4)

{
  char cVar1;
  char *in_EAX;
  int iVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = 0;
  if (in_EAX != (char *)0x0) {
    iVar2 = 0;
    pcVar4 = in_EAX + 1;
    if (*in_EAX != '\0') {
      do {
        iVar3 = iVar2;
        cVar1 = *pcVar4;
        iVar2 = iVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      if ((iVar2 != 0) && (in_EAX[iVar3] != ':')) {
        *param_1 = 0x3a;
        iVar5 = 1;
      }
    }
    if (iVar2 != 0) {
      iVar3 = iVar5 - (int)in_EAX;
      iVar6 = iVar2;
      do {
        in_EAX[(int)(param_1 + iVar3)] = *in_EAX;
        in_EAX = in_EAX + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    iVar5 = iVar5 + iVar2;
  }
  if (param_2 != (char *)0x0) {
    cVar1 = *param_2;
    iVar2 = 0;
    pcVar4 = param_2;
    if (cVar1 != '\0') {
      do {
        iVar3 = iVar2;
        pcVar4 = pcVar4 + 1;
        iVar2 = iVar3 + 1;
      } while (*pcVar4 != '\0');
      if (iVar2 != 0) {
        if ((cVar1 != '\\') && (cVar1 != '/')) {
          param_1[iVar5] = 0x5c;
          iVar5 = iVar5 + 1;
        }
        pcVar4 = param_2;
        iVar6 = iVar2;
        do {
          (param_1 + (iVar5 - (int)param_2))[(int)pcVar4] = *pcVar4;
          pcVar4 = pcVar4 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
        iVar5 = iVar5 + iVar2;
        if ((param_2[iVar3] != '\\') && (param_2[iVar3] != '/')) {
          param_1[iVar5] = 0x5c;
          iVar5 = iVar5 + 1;
        }
        goto LAB_00401b93;
      }
    }
  }
  param_1[iVar5] = 0x5c;
  iVar5 = iVar5 + 1;
LAB_00401b93:
  if (param_3 != (char *)0x0) {
    iVar2 = 0;
    cVar1 = *param_3;
    pcVar4 = param_3;
    while (cVar1 != '\0') {
      pcVar4 = pcVar4 + 1;
      iVar2 = iVar2 + 1;
      cVar1 = *pcVar4;
    }
    if (iVar2 != 0) {
      iVar3 = iVar5 - (int)param_3;
      iVar6 = iVar2;
      do {
        param_3[(int)(param_1 + iVar3)] = *param_3;
        param_3 = param_3 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    iVar5 = iVar5 + iVar2;
  }
  if (param_4 != (char *)0x0) {
    iVar2 = 0;
    cVar1 = *param_4;
    pcVar4 = param_4;
    while (cVar1 != '\0') {
      pcVar4 = pcVar4 + 1;
      iVar2 = iVar2 + 1;
      cVar1 = *pcVar4;
    }
    if (*param_4 != '.') {
      param_1[iVar5] = 0x2e;
      iVar5 = iVar5 + 1;
    }
    if (iVar2 != 0) {
      iVar3 = iVar5 - (int)param_4;
      iVar6 = iVar2;
      do {
        param_4[(int)(param_1 + iVar3)] = *param_4;
        param_4 = param_4 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    iVar5 = iVar5 + iVar2;
  }
  param_1[iVar5] = 0;
  return;
}



void __cdecl
FUN_00401c20(char *param_1,undefined *param_2,undefined *param_3,undefined *param_4,
            undefined *param_5)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  if (param_2 != (undefined *)0x0) {
    *param_2 = 0;
  }
  if (param_3 != (undefined *)0x0) {
    *param_3 = 0;
  }
  if (param_4 != (undefined *)0x0) {
    *param_4 = 0;
  }
  if (param_5 != (undefined *)0x0) {
    *param_5 = 0;
  }
  iVar4 = 0;
  if (*param_1 != '\0') {
    do {
      iVar5 = iVar4;
      iVar4 = iVar5 + 1;
    } while (param_1[iVar4] != '\0');
    if (iVar4 != 0) {
      iVar3 = 0;
      pcVar2 = param_1 + iVar5;
      do {
        cVar1 = *pcVar2;
        if (cVar1 == '.') {
          iVar3 = iVar3 + 1;
          break;
        }
        if ((cVar1 == '\\') || (cVar1 == '/')) {
          iVar3 = 0;
          break;
        }
        pcVar2 = pcVar2 + -1;
        iVar3 = iVar3 + 1;
      } while (pcVar2 + (1 - (int)param_1) != (char *)0x0);
      iVar4 = iVar4 - iVar3;
      if (param_5 != (undefined *)0x0) {
        pcVar2 = param_1 + iVar4;
        if (iVar3 != 0) {
          iVar6 = (int)param_5 - (int)pcVar2;
          iVar5 = iVar3;
          do {
            pcVar2[iVar6] = *pcVar2;
            pcVar2 = pcVar2 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
        param_5[iVar3] = 0;
      }
      if (iVar3 != 0) {
        iVar5 = 0;
        if (iVar4 != 0) {
          pcVar2 = param_1 + iVar4 + -1;
          do {
            if ((*pcVar2 == '\\') || (*pcVar2 == '/')) break;
            pcVar2 = pcVar2 + -1;
            iVar5 = iVar5 + 1;
          } while (pcVar2 + (1 - (int)param_1) != (char *)0x0);
        }
        iVar4 = iVar4 - iVar5;
        if (param_4 != (undefined *)0x0) {
          pcVar2 = param_1 + iVar4;
          if (iVar5 != 0) {
            iVar6 = (int)param_4 - (int)pcVar2;
            iVar3 = iVar5;
            do {
              pcVar2[iVar6] = *pcVar2;
              pcVar2 = pcVar2 + 1;
              iVar3 = iVar3 + -1;
            } while (iVar3 != 0);
          }
          param_4[iVar5] = 0;
        }
      }
      iVar5 = 0;
      cVar1 = *param_1;
      while (cVar1 != ':') {
        if ((cVar1 == '\\') || (cVar1 == '/')) {
          iVar5 = 0;
          goto LAB_00401d3f;
        }
        if (cVar1 == '\0') goto LAB_00401d3f;
        iVar3 = iVar5 + 1;
        iVar5 = iVar5 + 1;
        cVar1 = param_1[iVar3];
      }
      iVar5 = iVar5 + 1;
LAB_00401d3f:
      if (param_2 != (undefined *)0x0) {
        if (iVar5 != 0) {
          pcVar2 = param_1;
          iVar3 = iVar5;
          do {
            pcVar2[(int)param_2 - (int)param_1] = *pcVar2;
            pcVar2 = pcVar2 + 1;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
        }
        param_2[iVar5] = 0;
      }
      iVar4 = iVar4 - iVar5;
      if (param_3 != (undefined *)0x0) {
        pcVar2 = param_1 + iVar5;
        if (iVar4 != 0) {
          iVar3 = (int)param_3 - (int)pcVar2;
          iVar5 = iVar4;
          do {
            pcVar2[iVar3] = *pcVar2;
            pcVar2 = pcVar2 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
        param_3[iVar4] = 0;
      }
    }
  }
  return;
}



void FUN_00401da0(void)

{
  BYTE BVar1;
  char cVar2;
  int iVar3;
  LSTATUS LVar4;
  int iVar5;
  char *pcVar6;
  int iVar7;
  DWORD local_518;
  HKEY local_514;
  undefined local_510 [4];
  undefined local_50c [256];
  BYTE local_40c [256];
  undefined local_30c [256];
  char local_20c [256];
  BYTE local_10c [260];
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  if (DAT_0043e6e0 == (HMODULE)0x0) {
    GetModuleFileNameA(DAT_0043e050,(LPSTR)local_10c,0x104);
    FUN_00401c20((char *)local_10c,local_510,local_20c,local_30c,local_50c);
    FUN_00401ac0(local_10c,local_20c,"JLinkARM","dll");
    DAT_0043e6e0 = LoadLibraryA((LPCSTR)local_10c);
    if (DAT_0043e6e0 == (HMODULE)0x0) {
      LVar4 = RegCreateKeyA((HKEY)0x80000001,"Software\\SEGGER\\J-Link",&local_514);
      if (LVar4 == 0) {
        local_518 = 0x104;
        _memset(local_10c,0,0x104);
        RegQueryValueExA(local_514,"InstallPath",(LPDWORD)0x0,(LPDWORD)0x0,local_10c,&local_518);
        if (local_10c[0] != '\0') {
          RegCloseKey(local_514);
          FUN_00401c20((char *)local_10c,local_510,local_20c,local_30c,local_50c);
          FUN_00401ac0(local_10c,local_20c,"JLinkARM","dll");
          DAT_0043e6e0 = LoadLibraryA((LPCSTR)local_10c);
        }
      }
      if (DAT_0043e6e0 == (HMODULE)0x0) {
        iVar3 = 0;
        do {
          iVar7 = iVar3;
          BVar1 = "Target DLL "[iVar7];
          local_40c[iVar7] = BVar1;
          iVar3 = iVar7 + 1;
        } while (BVar1 != '\0');
        iVar3 = 0;
        do {
          iVar5 = iVar3;
          BVar1 = local_10c[iVar5];
          local_40c[iVar7 + iVar5] = BVar1;
          iVar3 = iVar5 + 1;
        } while (BVar1 != '\0');
        pcVar6 = " not found !";
        do {
          cVar2 = *pcVar6;
          pcVar6[(int)(&stack0xffbf3a3d + iVar5 + iVar7 + 1 + -1)] = cVar2;
          pcVar6 = pcVar6 + 1;
        } while (cVar2 != '\0');
        MessageBoxA((HWND)0x0,(LPCSTR)local_40c,"J-Link ARM Error",0x42030);
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401fd0(void)

{
  int iVar1;
  char cVar2;
  FARPROC pFVar3;
  char *pcVar4;
  int iVar5;
  char *unaff_EBX;
  int iVar6;
  CHAR local_208 [512];
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  cVar2 = FUN_00401da0();
  if ((cVar2 == '\0') && (pFVar3 = GetProcAddress(DAT_0043e6e0,unaff_EBX), pFVar3 == (FARPROC)0x0))
  {
    iVar1 = 0;
    do {
      iVar5 = iVar1;
      cVar2 = "DLL function "[iVar5];
      local_208[iVar5] = cVar2;
      iVar1 = iVar5 + 1;
    } while (cVar2 != '\0');
    iVar6 = 0;
    iVar1 = iVar5 - (int)unaff_EBX;
    do {
      cVar2 = *unaff_EBX;
      unaff_EBX[(int)(local_208 + iVar1)] = cVar2;
      iVar6 = iVar6 + 1;
      unaff_EBX = unaff_EBX + 1;
    } while (cVar2 != '\0');
    pcVar4 = "(...) not found !";
    do {
      cVar2 = *pcVar4;
      pcVar4[(int)(&stack0xffbf3c15 + iVar5 + 1 + iVar6 + -2)] = cVar2;
      pcVar4 = pcVar4 + 1;
    } while (cVar2 != '\0');
    MessageBoxA((HWND)0x0,local_208,"J-Link ARM Error",0x42030);
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004020a0(void)

{
  if (DAT_0043e448 == (code *)0x0) {
    DAT_0043e448 = (code *)FUN_00401fd0();
    if (DAT_0043e448 == (code *)0x0) {
      return;
    }
  }
                    // WARNING: Could not recover jumptable at 0x004020be. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_0043e448)();
  return;
}



undefined4 FUN_004020d0(void)

{
  undefined4 uVar1;
  
  if (DAT_0043e710 == (code *)0x0) {
    DAT_0043e710 = (code *)FUN_00401fd0();
    if (DAT_0043e710 == (code *)0x0) {
      return 0;
    }
  }
                    // WARNING: Could not recover jumptable at 0x004020f2. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (*DAT_0043e710)();
  return uVar1;
}



undefined4 FUN_00402100(void)

{
  undefined4 uVar1;
  
  if (DAT_0043df90 == (code *)0x0) {
    DAT_0043df90 = (code *)FUN_00401fd0();
    if (DAT_0043df90 == (code *)0x0) {
      return 0;
    }
  }
                    // WARNING: Could not recover jumptable at 0x00402122. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (*DAT_0043df90)();
  return uVar1;
}



undefined4 FUN_00402130(void)

{
  undefined4 uVar1;
  
  if (DAT_0043e2d8 == (code *)0x0) {
    DAT_0043e2d8 = (code *)FUN_00401fd0();
    if (DAT_0043e2d8 == (code *)0x0) {
      return 0;
    }
  }
                    // WARNING: Could not recover jumptable at 0x00402152. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (*DAT_0043e2d8)();
  return uVar1;
}



undefined4 FUN_00402160(void)

{
  undefined4 uVar1;
  
  if (DAT_0043e020 == (code *)0x0) {
    DAT_0043e020 = (code *)FUN_00401fd0();
    if (DAT_0043e020 == (code *)0x0) {
      return 0;
    }
  }
                    // WARNING: Could not recover jumptable at 0x00402182. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (*DAT_0043e020)();
  return uVar1;
}



void __cdecl FUN_00402190(char *param_1)

{
  char cVar1;
  char *pcVar2;
  undefined **ppuVar3;
  char local_808 [2048];
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  if (param_1 != (char *)0x0) {
    pcVar2 = param_1;
    do {
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    if ((uint)((int)pcVar2 - (int)(param_1 + 1)) < 0x1000) {
      _vsprintf(local_808,param_1,&stack0x00000008);
      ppuVar3 = FUN_004042cc();
      _fputs(local_808,(FILE *)(ppuVar3 + 8));
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402200(char *param_1)

{
  char cVar1;
  char *pcVar2;
  undefined **ppuVar3;
  char local_808 [2048];
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  if (param_1 != (char *)0x0) {
    pcVar2 = param_1;
    do {
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    if ((uint)((int)pcVar2 - (int)(param_1 + 1)) < 0x1000) {
      _vsprintf(local_808,param_1,&stack0x00000008);
      FID_conflict__wprintf("ERROR: ");
      ppuVar3 = FUN_004042cc();
      _fputs(local_808,(FILE *)(ppuVar3 + 8));
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



char * __cdecl FUN_00402280(int *param_1)

{
  char cVar1;
  char cVar2;
  int iVar3;
  char *pcVar4;
  char **unaff_ESI;
  int iVar5;
  int local_8;
  
  pcVar4 = *unaff_ESI;
  local_8 = 0;
  iVar5 = 0;
  for (; (((cVar1 = *pcVar4, cVar1 == ' ' || (cVar1 == '\t')) || (cVar1 == '\r')) || (cVar1 == '\n')
         ); pcVar4 = pcVar4 + 1) {
  }
  *unaff_ESI = pcVar4;
  cVar1 = *pcVar4;
  if (cVar1 == '-') {
    *unaff_ESI = pcVar4 + 1;
  }
  while( true ) {
    cVar2 = **unaff_ESI;
    if ((9 < (byte)(cVar2 - 0x30U)) || (iVar3 = cVar2 + -0x30, iVar3 < 0)) break;
    local_8 = local_8 + 1;
    iVar5 = iVar3 + iVar5 * 10;
    *unaff_ESI = *unaff_ESI + 1;
  }
  if (local_8 != 0) {
    if (cVar1 == '-') {
      iVar5 = -iVar5;
    }
    *param_1 = iVar5;
    return (char *)0x0;
  }
  return "Expected a dec value";
}



void FUN_00402300(void)

{
  int unaff_EBX;
  uint uVar1;
  uint unaff_EDI;
  
  if (DAT_0047eca0 != 0) {
    FID_conflict__wprintf("> ");
    uVar1 = 0;
    if (unaff_EDI != 0) {
      do {
        FID_conflict__wprintf("%02X ",(uint)*(byte *)(uVar1 + unaff_EBX));
        uVar1 = uVar1 + 1;
      } while (uVar1 < unaff_EDI);
    }
    FID_conflict__wprintf("\n");
  }
  FUN_00403ef0(unaff_EBX,unaff_EDI);
  return;
}



void FUN_00402350(void)

{
  size_t sVar1;
  void *unaff_EBX;
  uint uVar2;
  
  sVar1 = FUN_00403f30(unaff_EBX);
  if ((-1 < (int)sVar1) && (DAT_0047eca0 != 0)) {
    FID_conflict__wprintf("< ");
    uVar2 = 0;
    if (sVar1 != 0) {
      do {
        FID_conflict__wprintf("%02X ",(uint)*(byte *)(uVar2 + (int)unaff_EBX));
        uVar2 = uVar2 + 1;
      } while (uVar2 < sVar1);
    }
    FID_conflict__wprintf("\n");
  }
  return;
}



void FUN_004023b0(undefined4 param_1,undefined4 param_2)

{
  FUN_00402190("\rPerforming firmware update...%3d%%");
  return;
}



void FUN_004023d0(void)

{
  uint uVar1;
  
  if (DAT_0047eca0 != 0) {
    FID_conflict__wprintf("> ");
    uVar1 = 0;
    do {
      FID_conflict__wprintf("%02X ",(uint)(byte)(&DAT_004275c0)[uVar1]);
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x10);
    FID_conflict__wprintf("\n");
  }
  FUN_00403ef0(&DAT_004275c0,0x10);
  FUN_00402350();
  if (DAT_0047eca0 != 0) {
    FID_conflict__wprintf("> ");
    uVar1 = 0;
    do {
      FID_conflict__wprintf("%02X ",(uint)(byte)(&DAT_004275d0)[uVar1]);
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x10);
    FID_conflict__wprintf("\n");
  }
  FUN_00403ef0(&DAT_004275d0,0x10);
  return;
}



undefined4 FUN_00402490(void)

{
  DWORD DVar1;
  int iVar2;
  DWORD DVar3;
  uint uVar4;
  char *param1;
  
  DVar1 = GetTickCount();
  do {
    if (DAT_0047eca0 != 0) {
      FID_conflict__wprintf("> ");
      uVar4 = 0;
      do {
        FID_conflict__wprintf("%02X ",(uint)(byte)(&DAT_00427570)[uVar4]);
        uVar4 = uVar4 + 1;
      } while (uVar4 < 0x10);
      FID_conflict__wprintf("\n");
    }
    iVar2 = FUN_00403ef0(&DAT_00427570,0x10);
    DVar3 = GetTickCount();
    if (4999 < DVar3 - DVar1) {
      if (iVar2 < 0) {
        param1 = "Cannot communicate with ST-LINK. Please power cycle the device and try again.\n";
        goto LAB_004026b9;
      }
      break;
    }
  } while (iVar2 < 0);
  FUN_00402350();
  if (DAT_0047eca0 != 0) {
    FID_conflict__wprintf("> ");
    uVar4 = 0;
    do {
      FID_conflict__wprintf("%02X ",(uint)(byte)(&DAT_00427580)[uVar4]);
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x10);
    FID_conflict__wprintf("\n");
  }
  FUN_00403ef0(&DAT_00427580,0x10);
  FUN_00402350();
  if (DAT_0047ecb0 == '\0') {
    if (DAT_0047ecb1 == '\x01') {
      if (DAT_0047eed8 != 0) {
        FUN_00402190("ST-LINK/V2 is in DFU bootloader mode\n");
      }
      return 0;
    }
    if (DAT_0047ecb1 == '\x02') {
      if (DAT_0047eed8 == 0) {
        return 0;
      }
      FUN_00402190("ST-LINK/V2-1 is in DFU bootloader mode\n");
      return 0;
    }
  }
  else if ((DAT_0047ecb0 == '\x01') && (DAT_0047ecb1 == '\0')) {
    if (DAT_0047ecd9 == '\0') {
      param1 = "Not in DFU mode.  Please remove and insert the USB cable to activate DFU mode.\n";
    }
    else {
      if (DAT_0047eed8 != 0) {
        FUN_00402190("Forcing ST-LINK/V2-1 into bootloader mode\n");
      }
      FUN_004023d0();
      FUN_00404030();
      if (DAT_0047eed8 != 0) {
        FUN_00402190("Waiting for enumeration of ST-LINK/V2-1\n");
      }
      Sleep(1000);
      DVar1 = GetTickCount();
      iVar2 = FUN_00403fe0();
      while( true ) {
        if (-1 < iVar2) {
          if (DAT_0047eed8 != 0) {
            FID_conflict__wprintf("Enumeration complete, ST-LINK/V2-1 is back online\n");
          }
          FUN_00404030();
          Sleep(1000);
          FUN_00403fe0();
          return 0;
        }
        DVar3 = GetTickCount();
        if (10000 < DVar3 - DVar1) break;
        if (DAT_0047eed8 != 0) {
          FUN_00402190("\r%d");
        }
        iVar2 = FUN_00403fe0();
      }
      param1 = "Timeout: ST-LINK/V2-1 did not enter DFU mode\n";
    }
    goto LAB_004026b9;
  }
  param1 = "Unknown Inquire Mode response\n";
LAB_004026b9:
  FID_conflict__wprintf("ERROR: %s",param1);
  FUN_00404030();
  return 0xffffffff;
}



void FUN_004026e0(void)

{
  uint uVar1;
  
  if (DAT_0047eca0 != 0) {
    FID_conflict__wprintf("> ");
    uVar1 = 0;
    do {
      FID_conflict__wprintf("%02X ",(uint)(byte)(&DAT_004275b0)[uVar1]);
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x10);
    FID_conflict__wprintf("\n");
  }
  FUN_00403ef0(&DAT_004275b0,0x10);
  return;
}



undefined FUN_00402740(void)

{
  uint uVar1;
  
  if (DAT_0047eca0 != 0) {
    FID_conflict__wprintf("> ");
    uVar1 = 0;
    do {
      FID_conflict__wprintf("%02X ",(uint)(byte)(&DAT_004275a0)[uVar1]);
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x10);
    FID_conflict__wprintf("\n");
  }
  FUN_00403ef0(&DAT_004275a0,0x10);
  FUN_00402350();
  return DAT_0047ecb4;
}



void __fastcall FUN_004027c0(uint param_1,uint *param_2,byte param_3)

{
  byte *pbVar1;
  short sVar2;
  short sVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint local_418 [256];
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  local_10 = 0;
  local_c = 0;
  sVar3 = 0;
  sVar2 = 0;
  uVar5 = 0;
  local_18 = CONCAT22((ushort)param_3,499);
  if (param_1 != 0) {
    do {
      pbVar1 = (byte *)((int)param_2 + uVar5);
      uVar5 = uVar5 + 1;
      sVar2 = sVar3 + (ushort)*pbVar1;
      sVar3 = sVar2;
    } while (uVar5 < param_1);
  }
  local_14 = CONCAT13((char)(param_1 >> 8),CONCAT12((char)param_1,sVar2));
  if (DAT_0047eca0 != 0) {
    FID_conflict__wprintf("> ");
    uVar5 = 0;
    do {
      FID_conflict__wprintf("%02X ",(uint)*(byte *)((int)&local_18 + uVar5));
      uVar5 = uVar5 + 1;
    } while (uVar5 < 0x10);
    FID_conflict__wprintf("\n");
  }
  FUN_00403ef0(&local_18,0x10);
  if (param_3 == 0) {
    FUN_00402300();
    local_418[0] = 0x402892;
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  if (0x400 < param_1) {
    FID_conflict__wprintf("Encryption buffer too small");
    local_418[0] = 0x4028bb;
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  if ((param_1 & 0xf) == 0) {
    if (param_1 != 0) {
      iVar4 = (int)local_418 - (int)param_2;
      iVar6 = (param_1 - 1 >> 4) + 1;
      do {
        FUN_0040168c(param_2,(uint *)(iVar4 + (int)param_2),(uint *)&DAT_0047e890);
        param_2 = param_2 + 4;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    if (DAT_0047eca0 != 0) {
      FID_conflict__wprintf("> ");
      uVar5 = 0;
      if (param_1 != 0) {
        do {
          FID_conflict__wprintf("%02X ",(uint)*(byte *)((int)local_418 + uVar5));
          uVar5 = uVar5 + 1;
        } while (uVar5 < param_1);
      }
      FID_conflict__wprintf("\n");
    }
    FUN_00403ef0(local_418,param_1);
    local_418[0] = 0x402987;
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  FID_conflict__wprintf("Encryption block size error");
  local_418[0] = 0x4028e1;
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402990(undefined4 param_1)

{
  int iVar1;
  undefined local_10;
  undefined local_f;
  undefined local_e;
  undefined local_d;
  undefined local_c;
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  local_f = (undefined)param_1;
  local_e = (undefined)((uint)param_1 >> 8);
  local_d = (undefined)((uint)param_1 >> 0x10);
  local_10 = 0x21;
  local_c = (undefined)((uint)param_1 >> 0x18);
  FUN_004027c0(5,(uint *)&local_10,0);
  do {
    iVar1 = FUN_00402740();
  } while (iVar1 == 4);
  iVar1 = FUN_00402740();
  if (iVar1 != 5) {
    FUN_00402200("Set address fail\n");
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __thiscall FUN_00402a10(void *this,int param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int local_24;
  uint *local_20;
  uint local_1c;
  undefined local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  undefined local_14;
  undefined local_10;
  undefined local_f;
  undefined local_e;
  undefined local_d;
  undefined local_c;
  uint local_8;
  
  uVar1 = param_3;
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  local_20 = param_2;
  local_24 = 0;
  if ((param_3 & 0x3ff) == 0) {
    uVar4 = param_3;
    if (param_3 != 0) {
      do {
        uVar5 = uVar4 + 0x3ff >> 10;
        uVar6 = uVar5;
        iVar3 = param_1;
        if (uVar5 < 4) goto joined_r0x00402a87;
        uVar5 = 3;
        uVar6 = uVar5;
        do {
          local_e = (undefined)((uint)iVar3 >> 8);
          local_c = (undefined)((uint)iVar3 >> 0x18);
          local_10 = 0x41;
          local_f = (undefined)iVar3;
          local_d = (undefined)((uint)iVar3 >> 0x10);
          FUN_004027c0(5,(uint *)&local_10,0);
          do {
            iVar2 = FUN_00402740();
          } while (iVar2 == 4);
          iVar2 = FUN_00402740();
          if (iVar2 != 5) {
            FID_conflict__wprintf("ERROR: %s","Erase fail");
          }
          uVar5 = uVar5 - 1;
          uVar4 = param_3;
          iVar3 = iVar3 + 0x400;
joined_r0x00402a87:
        } while (uVar5 != 0);
        local_1c = 0;
        if (uVar6 != 0) {
          do {
            local_16 = (undefined)((uint)param_1 >> 8);
            local_14 = (undefined)((uint)param_1 >> 0x18);
            local_18 = 0x21;
            local_17 = (undefined)param_1;
            local_15 = (undefined)((uint)param_1 >> 0x10);
            FUN_004027c0(5,(uint *)&local_18,0);
            do {
              iVar3 = FUN_00402740();
            } while (iVar3 == 4);
            iVar3 = FUN_00402740();
            if (iVar3 != 5) {
              FUN_00402200("Set address fail\n");
            }
            FUN_004027c0(0x400,local_20,(char)local_1c + 2);
            do {
              iVar3 = FUN_00402740();
            } while (iVar3 == 4);
            iVar3 = FUN_00402740();
            if (iVar3 != 5) {
              FUN_00402200("Program fail\n");
            }
            local_24 = local_24 + 0x400;
            local_20 = local_20 + 0x100;
            uVar4 = param_3 - 0x400;
            param_1 = param_1 + 0x400;
            if (this != (void *)0x0) {
              (*(code *)this)(local_24,uVar1);
            }
            local_1c = local_1c + 1;
            param_3 = uVar4;
          } while (local_1c < uVar6);
        }
      } while (uVar4 != 0);
    }
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  FUN_00402200("Firmware size is not a multiple of the programming block size\n");
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402bf0(void)

{
  FID_conflict__wprintf("Options:\n");
  FID_conflict__wprintf("  -h           Display help\n");
  FID_conflict__wprintf("  -q           Run silently\n");
  FID_conflict__wprintf("  -v           Verbose mode     [default]\n");
  FID_conflict__wprintf("\nAdministration options:\n");
  FID_conflict__wprintf("  -i           Identify ST-LINK through bootloader\n");
  FID_conflict__wprintf("  -r           Reflash ST-LINK/V2 original firmware\n");
  FID_conflict__wprintf("  -u           Show USB transactions\n");
  FID_conflict__wprintf("  -x           Erase firmware identification sector\n");
  FID_conflict__wprintf("  -n           Remain in DFU mode when complete\n");
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00402c60(int param_1,int param_2)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  int iVar4;
  byte *pbVar5;
  bool bVar6;
  int local_8;
  
  local_8 = 1;
  if (1 < param_1) {
    do {
      pbVar2 = *(byte **)(param_2 + local_8 * 4);
      pbVar5 = &DAT_00427aa0;
      pbVar3 = pbVar2;
      do {
        bVar1 = *pbVar3;
        bVar6 = bVar1 < *pbVar5;
        if (bVar1 != *pbVar5) {
LAB_00402cb0:
          iVar4 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
          goto LAB_00402cb5;
        }
        if (bVar1 == 0) break;
        bVar1 = pbVar3[1];
        bVar6 = bVar1 < pbVar5[1];
        if (bVar1 != pbVar5[1]) goto LAB_00402cb0;
        pbVar3 = pbVar3 + 2;
        pbVar5 = pbVar5 + 2;
      } while (bVar1 != 0);
      iVar4 = 0;
LAB_00402cb5:
      if (iVar4 == 0) {
        DAT_0047eed8 = 1;
      }
      else {
        pbVar5 = &DAT_00427a9c;
        pbVar3 = pbVar2;
        do {
          bVar1 = *pbVar3;
          bVar6 = bVar1 < *pbVar5;
          if (bVar1 != *pbVar5) {
LAB_00402cf0:
            iVar4 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
            goto LAB_00402cf5;
          }
          if (bVar1 == 0) break;
          bVar1 = pbVar3[1];
          bVar6 = bVar1 < pbVar5[1];
          if (bVar1 != pbVar5[1]) goto LAB_00402cf0;
          pbVar3 = pbVar3 + 2;
          pbVar5 = pbVar5 + 2;
        } while (bVar1 != 0);
        iVar4 = 0;
LAB_00402cf5:
        if (iVar4 == 0) {
          DAT_0047eed8 = 2;
        }
        else {
          pbVar5 = &DAT_00427a98;
          pbVar3 = pbVar2;
          do {
            bVar1 = *pbVar3;
            bVar6 = bVar1 < *pbVar5;
            if (bVar1 != *pbVar5) {
LAB_00402d30:
              iVar4 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
              goto LAB_00402d35;
            }
            if (bVar1 == 0) break;
            bVar1 = pbVar3[1];
            bVar6 = bVar1 < pbVar5[1];
            if (bVar1 != pbVar5[1]) goto LAB_00402d30;
            pbVar3 = pbVar3 + 2;
            pbVar5 = pbVar5 + 2;
          } while (bVar1 != 0);
          iVar4 = 0;
LAB_00402d35:
          if (iVar4 == 0) {
            DAT_0047eed8 = 0;
          }
          else {
            pbVar5 = &DAT_00427a94;
            pbVar3 = pbVar2;
            do {
              bVar1 = *pbVar3;
              bVar6 = bVar1 < *pbVar5;
              if (bVar1 != *pbVar5) {
LAB_00402d70:
                iVar4 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
                goto LAB_00402d75;
              }
              if (bVar1 == 0) break;
              bVar1 = pbVar3[1];
              bVar6 = bVar1 < pbVar5[1];
              if (bVar1 != pbVar5[1]) goto LAB_00402d70;
              pbVar3 = pbVar3 + 2;
              pbVar5 = pbVar5 + 2;
            } while (bVar1 != 0);
            iVar4 = 0;
LAB_00402d75:
            if (iVar4 == 0) {
              DAT_0047eca0 = 1;
              DAT_0047eed8 = 0;
            }
            else {
              pbVar5 = &DAT_00427a90;
              pbVar3 = pbVar2;
              do {
                bVar1 = *pbVar3;
                bVar6 = bVar1 < *pbVar5;
                if (bVar1 != *pbVar5) {
LAB_00402db5:
                  iVar4 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
                  goto LAB_00402dba;
                }
                if (bVar1 == 0) break;
                bVar1 = pbVar3[1];
                bVar6 = bVar1 < pbVar5[1];
                if (bVar1 != pbVar5[1]) goto LAB_00402db5;
                pbVar3 = pbVar3 + 2;
                pbVar5 = pbVar5 + 2;
              } while (bVar1 != 0);
              iVar4 = 0;
LAB_00402dba:
              if (iVar4 == 0) {
                _DAT_0047ecd0 = 1;
              }
              else {
                pbVar5 = &DAT_00427a8c;
                pbVar3 = pbVar2;
                do {
                  bVar1 = *pbVar3;
                  bVar6 = bVar1 < *pbVar5;
                  if (bVar1 != *pbVar5) {
LAB_00402df4:
                    iVar4 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
                    goto LAB_00402df9;
                  }
                  if (bVar1 == 0) break;
                  bVar1 = pbVar3[1];
                  bVar6 = bVar1 < pbVar5[1];
                  if (bVar1 != pbVar5[1]) goto LAB_00402df4;
                  pbVar3 = pbVar3 + 2;
                  pbVar5 = pbVar5 + 2;
                } while (bVar1 != 0);
                iVar4 = 0;
LAB_00402df9:
                if (iVar4 == 0) {
                  _DAT_0047eca4 = 1;
                }
                else {
                  pbVar5 = &DAT_00427a88;
                  pbVar3 = pbVar2;
                  do {
                    bVar1 = *pbVar3;
                    bVar6 = bVar1 < *pbVar5;
                    if (bVar1 != *pbVar5) {
LAB_00402e33:
                      iVar4 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
                      goto LAB_00402e38;
                    }
                    if (bVar1 == 0) break;
                    bVar1 = pbVar3[1];
                    bVar6 = bVar1 < pbVar5[1];
                    if (bVar1 != pbVar5[1]) goto LAB_00402e33;
                    pbVar3 = pbVar3 + 2;
                    pbVar5 = pbVar5 + 2;
                  } while (bVar1 != 0);
                  iVar4 = 0;
LAB_00402e38:
                  if (iVar4 == 0) {
                    _DAT_0047ecd4 = 1;
                  }
                  else {
                    pbVar5 = &DAT_00427a84;
                    pbVar3 = pbVar2;
                    do {
                      bVar1 = *pbVar3;
                      bVar6 = bVar1 < *pbVar5;
                      if (bVar1 != *pbVar5) {
LAB_00402e70:
                        iVar4 = (1 - (uint)bVar6) - (uint)(bVar6 != 0);
                        goto LAB_00402e75;
                      }
                      if (bVar1 == 0) break;
                      bVar1 = pbVar3[1];
                      bVar6 = bVar1 < pbVar5[1];
                      if (bVar1 != pbVar5[1]) goto LAB_00402e70;
                      pbVar3 = pbVar3 + 2;
                      pbVar5 = pbVar5 + 2;
                    } while (bVar1 != 0);
                    iVar4 = 0;
LAB_00402e75:
                    if (iVar4 == 0) {
                      FUN_00402bf0();
                    // WARNING: Subroutine does not return
                      _exit(0);
                    }
                    if (*pbVar2 == 0x2d) {
                      FID_conflict__wprintf("ERROR: %s","Unknown option");
                    }
                  }
                }
              }
            }
          }
        }
      }
      local_8 = local_8 + 1;
    } while (local_8 < param_1);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x004031da)
// WARNING: Removing unreachable block (ram,0x004031e2)
// WARNING: Removing unreachable block (ram,0x00403412)
// WARNING: Removing unreachable block (ram,0x004032b6)
// WARNING: Removing unreachable block (ram,0x004032ba)
// WARNING: Removing unreachable block (ram,0x004032be)
// WARNING: Removing unreachable block (ram,0x004032c2)
// WARNING: Removing unreachable block (ram,0x004032c7)
// WARNING: Removing unreachable block (ram,0x00403308)
// WARNING: Removing unreachable block (ram,0x00403340)
// WARNING: Removing unreachable block (ram,0x0040334a)
// WARNING: Removing unreachable block (ram,0x00403354)
// WARNING: Removing unreachable block (ram,0x0040321e)
// WARNING: Removing unreachable block (ram,0x00403258)
// WARNING: Removing unreachable block (ram,0x00403390)
// WARNING: Removing unreachable block (ram,0x004033b0)
// WARNING: Removing unreachable block (ram,0x004033ba)
// WARNING: Removing unreachable block (ram,0x004033c4)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00402ed0(int param_1)

{
  int iVar1;
  uint uVar2;
  char *pcVar3;
  char *pcVar4;
  uint local_30 [4];
  uint local_20 [4];
  char *local_10;
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  FID_conflict__wprintf("Preparing for FW update (can take up to 10 seconds)...",0);
  iVar1 = FUN_00403fe0();
  if (iVar1 < 1) {
    FUN_00402200("Cannot find an ST-LINK, multiple ST-LINKs plugged in, or ST-LINK is in use\n");
LAB_00402f0a:
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  iVar1 = FUN_00402490();
  if (iVar1 < 0) goto LAB_00402f0a;
  FUN_00402300();
  FUN_00402350();
  _DAT_0043e86c = _DAT_0043e87c;
  _DAT_0043e870 = DAT_0043e884;
  _DAT_0043e874 = DAT_0043e888;
  _DAT_0043e878 = DAT_0043e88c;
  FUN_00401000((uint *)&DAT_00427550,(uint *)&DAT_0047e890);
  FUN_0040168c((uint *)&DAT_0043e86c,local_20,(uint *)&DAT_0047e890);
  FUN_00401000(local_20,(uint *)&DAT_0047e890);
  if (DAT_0047eed8 != 0) {
    FID_conflict__wprintf("Unique device ID:\n ");
    uVar2 = 0;
    do {
      FUN_00402190(" %02x");
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x10);
    FID_conflict__wprintf("\n");
    FID_conflict__wprintf("Device encryption key:\n ");
    uVar2 = 0;
    do {
      FUN_00402190(" %02x");
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x10);
    FID_conflict__wprintf("\n");
  }
  FUN_00401000((uint *)&DAT_00427560,(uint *)&DAT_0047ea90);
  FUN_0040168c((uint *)&DAT_0043e86c,(uint *)&DAT_0047ec90,(uint *)&DAT_0047ea90);
  _DAT_0047ec9c = 0xa50027d3;
  if (DAT_0047eed8 != 0) {
    FID_conflict__wprintf("Encrypted label:\n ");
    uVar2 = 0;
    do {
      FUN_00402190(" %02x");
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x10);
    FID_conflict__wprintf("\n");
    FUN_0040168c((uint *)&DAT_0047ec90,local_30,(uint *)&DAT_0047e890);
    FID_conflict__wprintf("Transport-layer valid label:\n ");
    uVar2 = 0;
    do {
      FUN_00402190(" %02x");
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x10);
    FID_conflict__wprintf("\n");
  }
  switch(DAT_0043e880) {
  case 0x41:
    break;
  case 0x42:
    break;
  default:
    FUN_00402200("Unsupported ST-LINK firmware\n");
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  case 0x44:
    break;
  case 0x4a:
    break;
  case 0x4d:
    break;
  case 0x53:
  }
  if (DAT_0047eed8 != 0) {
    FUN_00402190("Installed firmware version: V%d.%d.%d - %s\n");
  }
  FID_conflict__wprintf("O.K.\n");
  FID_conflict__wprintf("Identifying ST-LINK variant...");
  DAT_0043e868 = 0xbc00;
  local_10 = "ST-LINK/V2";
  _memset(&DAT_0043e890,0xff,0x40000);
  if (param_1 == 0) {
    iVar1 = 0xae5c;
    FID_conflict__memcpy(&DAT_0043e890,&DAT_0040c278,0xae5c);
  }
  else {
    FID_conflict__memcpy(&DAT_0043e890,&DAT_0042b650,0x6510);
    iVar1 = 0x6510;
  }
  DAT_0047ecac = iVar1 + 0x3ffU & 0xfffffc00;
  iVar1 = FUN_00402740();
  if ((iVar1 == 2) || (iVar1 = FUN_00402740(), iVar1 == 5)) {
    pcVar3 = "O.K.: %s\n";
    pcVar4 = local_10;
    FUN_00402190("O.K.: %s\n");
    FID_conflict__wprintf("Performing firmware update...",pcVar3,pcVar4);
    if (DAT_0047ecac <= DAT_0043e868) {
      iVar1 = FUN_00402a10(FUN_004023b0,0x8004000,(uint *)&DAT_0043e890,DAT_0047ecac);
      if (-1 < iVar1) {
        FID_conflict__wprintf("\rPerforming firmware update...O.K.\n");
        if (DAT_0047eed8 != 0) {
          FID_conflict__wprintf("Exiting DFU mode and starting application\n");
        }
        FUN_004026e0();
        FUN_00404030();
        ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
      goto LAB_0040341f;
    }
    pcVar4 = "Internal error. Firmware too big\n";
  }
  else {
    pcVar4 = "Not in DFU idle mode\n";
  }
  FUN_00402200(pcVar4);
LAB_0040341f:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Removing unreachable block (ram,0x00403556)
// WARNING: Removing unreachable block (ram,0x0040358a)

void FUN_00403480(void)

{
  uint uVar1;
  int iVar2;
  char *param1;
  uint local_210;
  
  uVar1 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  iVar2 = FUN_00402130();
  if (iVar2 < 1) {
    param1 = "ERROR: No J-Link connected to PC.\n";
  }
  else if (iVar2 < 2) {
    if (local_210 / 10000000 == 0x4d) {
      FUN_00402160();
      iVar2 = FUN_00402100();
      if (iVar2 != 0) {
        FUN_00402200("ERROR: %s.\n");
        goto LAB_0040357b;
      }
      FID_conflict__wprintf("Switching to ST-Link bootloader...");
      FUN_004020d0();
      param1 = "ERROR: Communication error.\n";
    }
    else {
      param1 = "ERROR: The connected J-Link is not a ST-Link OB.\n";
    }
  }
  else {
    param1 = 
    "ERROR: More than 1 J-Link connected. Please make sure that only 1 J-Link is connected during the replacement process.\n"
    ;
  }
  FID_conflict__wprintf("ERROR: %s",param1);
LAB_0040357b:
  FUN_004020a0();
  ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403640(void)

{
  char cVar1;
  bool bVar2;
  FILE *pFVar3;
  char *pcVar4;
  int iVar5;
  char local_108 [256];
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  FID_conflict__wprintf
            (
            "The following terms come from SEGGER Microcontroller GmbH & Co. KG (\"SEGGER\")\nYou must agree to them in order to proceed.\n\n=============================================================================\n* IMPORTANT *\nThis utility enables You to replace the firmware of an existing ST-LINK\non-board with firmware from SEGGER that makes the ST-LINK on-board\nbehave J-Link compatible. You do this replacement at Your own risk.\nThough extremely unlikely, You are aware that the replacement process may\nresult in an unusable ST-LINK on-board. The utility and firmware from SEGGER\nare provided on an as-is basis and come without any warranty\nand without support.\nYou further agree to only use the firmware provided by SEGGER via this utility,\nwithin the bounds of the license stated on the download page:\nhttps://www.segger.com/jlink-st-link.html\nExcept as expressly set forth in this agreement,\nthe Agreement remains unchanged and continues in full force and effect.\n\n=============================================================================\n\nI hereby accept the terms provided by SEGGER.\n"
            );
  iVar5 = 0;
  while( true ) {
    FID_conflict__wprintf("(A)ccept / (D)ecline\n");
    FUN_00402190("Selection>");
    pFVar3 = (FILE *)FUN_004042cc();
    _fgets(local_108,0x100,pFVar3);
    pcVar4 = local_108;
    do {
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    for (pcVar4 = pcVar4 + (int)(local_108 + (-1 - (int)(local_108 + 1)));
        (*pcVar4 == '\n' || (*pcVar4 == '\r')); pcVar4 = pcVar4 + -1) {
      *pcVar4 = '\0';
    }
    if ((local_108[0] == 'a') || (local_108[0] == 'A')) {
      iVar5 = 1;
    }
    if ((local_108[0] == 'd') || (local_108[0] == 'D')) break;
    if (iVar5 != 0) {
LAB_004036e8:
      FID_conflict__wprintf("\n");
      if (-1 < iVar5) {
        FID_conflict__wprintf
                  (
                  "At the request of STMICROELECTRONICS (\"ST\"), the below\n\"Amendment to Evaluation Board License Agreement\" has been added\nto this utility. You must agree to this amendment in order to proceed.\n\n=============================================================================\n* IMPORTANT *\nWhen You purchased Your STMICROELECTRONICS (\"ST\") Evaluation Board, You entered\ninto an Evaluation Board License Agreement (\"Agreement\") with ST.\nYou may install the SEGGER J-Link software (\"J-Link\") onto Your ST\nEvaluation Board only if You  agree to this amendment (\"Amendment\")\nof the Agreement.\nSTMICROELECTRONICS (\"ST\") hereby authorizes You to install\nSEGGER J-Link software (\"J-Link\") onto Your ST Evaluation Board,\nas an exception to the terms and conditions of the Agreement.\nYou acknowledge and agree that J-Link is provided solely by SEGGER,\nand not by ST. You acknowledge and agree that ST does not endorse, recommend,\nnor provide any assurance or warranty, whether express\nor implied, in relation to J-Link or its use with Your ST Evaluation Board.\nYou acknowledge and agree that ST shall not be liable for any direct, indirect,\nspecial, incidental or consequential damages resulting from Your use of J-Link,\neven if advised of the possibility thereof.\nThis Amendment shall be governed, construed and enforced in accordance with the\nlaws of Switzerland.\nExcept as expressly set forth in this Amendment, the Agreement remains unchanged\nand continues in full force and effect.\n\n=============================================================================\n\nI hereby accept the amendment to the Evaluation Board License Agreement\nprovided by STMICROELECTRONICS (\"ST\")"
                  );
        bVar2 = false;
        do {
          FID_conflict__wprintf("(A)ccept / (D)ecline\n");
          FUN_00402190("Selection>");
          pFVar3 = (FILE *)FUN_004042cc();
          _fgets(local_108,0x100,pFVar3);
          pcVar4 = local_108;
          do {
            cVar1 = *pcVar4;
            pcVar4 = pcVar4 + 1;
          } while (cVar1 != '\0');
          for (pcVar4 = pcVar4 + (int)(local_108 + (-1 - (int)(local_108 + 1)));
              (*pcVar4 == '\n' || (*pcVar4 == '\r')); pcVar4 = pcVar4 + -1) {
            *pcVar4 = '\0';
          }
          if ((local_108[0] == 'a') || (local_108[0] == 'A')) {
            bVar2 = true;
          }
        } while (((local_108[0] != 'd') && (local_108[0] != 'D')) && (!bVar2));
        FID_conflict__wprintf("\n");
        ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  iVar5 = -1;
  goto LAB_004036e8;
}



void __cdecl FUN_004037c0(int param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  FILE *_File;
  char *pcVar3;
  uint uVar4;
  uint local_40c;
  char local_408 [1024];
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  FID_conflict__wprintf("\n");
  FID_conflict__wprintf("(c) 2016 SEGGER Microcontroller GmbH & Co. KG    www.segger.com\n");
  FID_conflict__wprintf("STLinkReflash compiled Aug 12 2019 10:30:05\n\n");
  iVar2 = FUN_00403640();
  if (-1 < iVar2) {
    FUN_00402c60(param_1,param_2);
    do {
      uVar4 = 0;
      do {
        FID_conflict__wprintf("[%d] %s\n",uVar4,(&PTR_DAT_004275e0)[uVar4 * 2]);
        uVar4 = uVar4 + 1;
      } while (uVar4 < 4);
      FUN_00402190("Selection>");
      _File = (FILE *)FUN_004042cc();
      _fgets(local_408,0x400,_File);
      pcVar1 = local_408;
      do {
        pcVar3 = pcVar1;
        pcVar1 = pcVar3 + 1;
      } while (*pcVar3 != '\0');
      while( true ) {
        pcVar3 = pcVar3 + -1;
        if ((*pcVar3 != '\n') && (*pcVar3 != '\r')) break;
        *pcVar3 = '\0';
      }
      local_40c = 0xffffffff;
      if ((local_408[0] != '\0') &&
         (FUN_00402280((int *)&local_40c), uVar4 = local_40c, local_40c < 4)) {
        FID_conflict__wprintf("\n");
        (**(code **)(&UNK_004275e4 + uVar4 * 8))();
        FID_conflict__wprintf("\n");
      }
    } while (DAT_0047eca8 == 0);
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403920(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  HANDLE pvVar2;
  int unaff_ESI;
  
  hModule = LoadLibraryA("winusb.dll");
  *(HMODULE *)(unaff_ESI + 0x8c) = hModule;
  pFVar1 = GetProcAddress(hModule,"WinUsb_Initialize");
  *(FARPROC *)(unaff_ESI + 0xa0) = pFVar1;
  pFVar1 = GetProcAddress(*(HMODULE *)(unaff_ESI + 0x8c),"WinUsb_Free");
  *(FARPROC *)(unaff_ESI + 0xa4) = pFVar1;
  pFVar1 = GetProcAddress(*(HMODULE *)(unaff_ESI + 0x8c),"WinUsb_QueryInterfaceSettings");
  *(FARPROC *)(unaff_ESI + 0xa8) = pFVar1;
  pFVar1 = GetProcAddress(*(HMODULE *)(unaff_ESI + 0x8c),"WinUsb_QueryPipe");
  *(FARPROC *)(unaff_ESI + 0xac) = pFVar1;
  pFVar1 = GetProcAddress(*(HMODULE *)(unaff_ESI + 0x8c),"WinUsb_ReadPipe");
  *(FARPROC *)(unaff_ESI + 0xb0) = pFVar1;
  pFVar1 = GetProcAddress(*(HMODULE *)(unaff_ESI + 0x8c),"WinUsb_WritePipe");
  *(FARPROC *)(unaff_ESI + 0xb4) = pFVar1;
  pFVar1 = GetProcAddress(*(HMODULE *)(unaff_ESI + 0x8c),"WinUsb_SetPipePolicy");
  *(FARPROC *)(unaff_ESI + 0xb8) = pFVar1;
  pFVar1 = GetProcAddress(*(HMODULE *)(unaff_ESI + 0x8c),"WinUsb_ControlTransfer");
  *(FARPROC *)(unaff_ESI + 0xbc) = pFVar1;
  pFVar1 = GetProcAddress(*(HMODULE *)(unaff_ESI + 0x8c),"WinUsb_GetOverlappedResult");
  *(FARPROC *)(unaff_ESI + 0xc0) = pFVar1;
  pvVar2 = CreateFileA(*(LPCSTR *)(unaff_ESI + 0x9c),0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,
                       0x40000080,(HANDLE)0x0);
  *(HANDLE *)(unaff_ESI + 0x88) = pvVar2;
  return;
}



void FUN_00403a10(void)

{
  undefined4 *puVar1;
  int iVar2;
  DWORD DVar3;
  int iVar4;
  int unaff_ESI;
  undefined local_20 [4];
  byte local_1c;
  int local_14;
  char local_10;
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  puVar1 = (undefined4 *)(unaff_ESI + 0x90);
  iVar2 = (**(code **)(unaff_ESI + 0xa0))(*(undefined4 *)(unaff_ESI + 0x88),puVar1);
  if (iVar2 == 0) {
    DVar3 = GetLastError();
    if (DVar3 == 6) {
      FID_conflict__wprintf("Invalid handle");
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    if (DVar3 == 8) {
      FID_conflict__wprintf("Not enough memory");
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    if (DVar3 == 0x4b0) {
      FID_conflict__wprintf("Bad device");
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    FID_conflict__wprintf("Something else");
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  iVar2 = (**(code **)(unaff_ESI + 0xa8))(*puVar1,0,local_20);
  if (iVar2 != 0) {
    iVar2 = 0;
    do {
      if ((int)(uint)local_1c <= iVar2) break;
      iVar4 = (**(code **)(unaff_ESI + 0xac))(*puVar1,0,iVar2,&local_14);
      if (local_14 == 0) {
        *(char *)(unaff_ESI + 0x94) = local_10;
      }
      else if (local_14 == 2) {
        if (local_10 < '\0') {
          if (*(char *)(unaff_ESI + 0x95) == '\0') {
            *(char *)(unaff_ESI + 0x95) = local_10;
          }
        }
        else if (*(char *)(unaff_ESI + 0x96) == '\0') {
          *(char *)(unaff_ESI + 0x96) = local_10;
        }
      }
      else if (local_14 == 3) {
        *(char *)(unaff_ESI + 0x97) = local_10;
      }
      iVar2 = iVar2 + 1;
    } while (iVar4 != 0);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



PBYTE __cdecl FUN_00403b70(HDEVINFO param_1,PSP_DEVINFO_DATA param_2)

{
  size_t PropertyBufferSize;
  PBYTE PropertyBuffer;
  BOOL BVar1;
  DWORD unaff_EBX;
  size_t local_8;
  
  local_8 = 0;
  SetupDiGetDeviceRegistryPropertyA(param_1,param_2,unaff_EBX,(PDWORD)0x0,(PBYTE)0x0,0,&local_8);
  PropertyBufferSize = local_8;
  PropertyBuffer = (PBYTE)_malloc(local_8);
  if (PropertyBufferSize != 0) {
    BVar1 = SetupDiGetDeviceRegistryPropertyA
                      (param_1,param_2,unaff_EBX,(PDWORD)0x0,PropertyBuffer,PropertyBufferSize,
                       (PDWORD)0x0);
    if (BVar1 != 0) {
      return PropertyBuffer;
    }
  }
  return (PBYTE)0x0;
}



uint FUN_00403be0(void)

{
  char *in_EAX;
  int iVar1;
  int iVar2;
  uint local_8;
  
  local_8 = 0;
  iVar2 = 4;
  do {
    iVar1 = _toupper((int)*in_EAX);
    if (iVar1 < 0x41) {
      local_8._0_2_ = (ushort)(local_8 << 4);
      local_8 = (uint)(ushort)((ushort)local_8 | (short)*in_EAX - 0x30U);
    }
    else {
      iVar1 = _toupper((int)*in_EAX);
      local_8 = local_8 << 4 | iVar1 - 0x37U;
    }
    in_EAX = in_EAX + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return local_8 & 0xffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00403c40(void *param_1)

{
  char cVar1;
  HDEVINFO DeviceInfoSet;
  BOOL BVar2;
  PSP_DEVICE_INTERFACE_DETAIL_DATA_A DeviceInterfaceDetailData;
  CHAR *pCVar3;
  size_t sVar4;
  uint *puVar5;
  void *_Dst;
  PBYTE pBVar6;
  DWORD DVar7;
  uint local_b8;
  uint local_b4;
  DWORD local_b0;
  size_t local_a8;
  _SP_DEVINFO_DATA local_a4;
  _SP_DEVICE_INTERFACE_DATA local_88;
  uint local_6c [25];
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  _memset(param_1,0,0xc4);
  *(undefined4 *)((int)param_1 + 0x88) = 0xffffffff;
  *(undefined4 *)((int)param_1 + 0x8c) = 0xffffffff;
  *(undefined4 *)((int)param_1 + 0x90) = 0xffffffff;
  *(undefined4 *)((int)param_1 + 0x80) = 0xffffffff;
  DAT_0047efa4 = 0;
  DeviceInfoSet =
       SetupDiGetClassDevsA((GUID *)&InterfaceClassGuid_00428a54,(PCSTR)0x0,(HWND)0x0,0x12);
  if (DeviceInfoSet != (HDEVINFO)0x0) {
    local_b0 = 0;
    do {
      local_88.InterfaceClassGuid.Data1 = 0;
      local_88.InterfaceClassGuid.Data2 = 0;
      local_88.InterfaceClassGuid.Data3 = 0;
      local_88.InterfaceClassGuid.Data4[0] = '\0';
      local_88.InterfaceClassGuid.Data4[1] = '\0';
      local_88.InterfaceClassGuid.Data4[2] = '\0';
      local_88.InterfaceClassGuid.Data4[3] = '\0';
      local_88.InterfaceClassGuid.Data4[4] = '\0';
      local_88.InterfaceClassGuid.Data4[5] = '\0';
      local_88.InterfaceClassGuid.Data4[6] = '\0';
      local_88.InterfaceClassGuid.Data4[7] = '\0';
      local_88.Flags = 0;
      local_88.Reserved = 0;
      local_88.cbSize = 0x1c;
      BVar2 = SetupDiEnumDeviceInterfaces
                        (DeviceInfoSet,(PSP_DEVINFO_DATA)0x0,(GUID *)&InterfaceClassGuid_00428a54,
                         local_b0,&local_88);
      if (BVar2 == 0) {
        DVar7 = GetLastError();
        if (DVar7 == 0x103) break;
      }
      else {
        local_a4.cbSize = 0x1c;
        local_a8 = 0;
        SetupDiGetDeviceInterfaceDetailA
                  (DeviceInfoSet,&local_88,(PSP_DEVICE_INTERFACE_DETAIL_DATA_A)0x0,0,&local_a8,
                   (PSP_DEVINFO_DATA)0x0);
        sVar4 = local_a8;
        DeviceInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA_A)_malloc(local_a8);
        DeviceInterfaceDetailData->cbSize = 5;
        BVar2 = SetupDiGetDeviceInterfaceDetailA
                          (DeviceInfoSet,&local_88,DeviceInterfaceDetailData,sVar4,&local_a8,
                           &local_a4);
        if (BVar2 != 0) {
          pCVar3 = DeviceInterfaceDetailData->DevicePath;
          do {
            cVar1 = *pCVar3;
            pCVar3 = pCVar3 + 1;
          } while (cVar1 != '\0');
          sVar4 = (int)pCVar3 - (int)(DeviceInterfaceDetailData + 1);
          SetupDiGetDeviceInstanceIdA(DeviceInfoSet,&local_a4,(PSTR)local_6c,100,(PDWORD)0x0);
          puVar5 = FUN_00404f50(local_6c,"VID_");
          if (puVar5 != (uint *)0x0) {
            local_b8 = FUN_00403be0();
          }
          puVar5 = FUN_00404f50(local_6c,"PID_");
          if (puVar5 != (uint *)0x0) {
            local_b4 = FUN_00403be0();
          }
          if ((local_b8 == 0x483) && ((local_b4 == 0x3748 || (local_b4 == 0x374b)))) {
            DAT_0047efa4 = DAT_0047efa4 + 1;
            _DAT_0047ef64 = 0x483;
            _DAT_0047ef66 = (undefined2)local_b4;
            _Dst = _malloc(sVar4 + 1);
            *(void **)((int)param_1 + 0x9c) = _Dst;
            FID_conflict__memcpy(_Dst,DeviceInterfaceDetailData->DevicePath,sVar4);
            *(undefined *)(sVar4 + *(int *)((int)param_1 + 0x9c)) = 0;
            _free(DeviceInterfaceDetailData);
            FUN_00403b70(DeviceInfoSet,&local_a4);
            FUN_00403b70(DeviceInfoSet,&local_a4);
            pBVar6 = FUN_00403b70(DeviceInfoSet,&local_a4);
            *(PBYTE *)((int)param_1 + 0x98) = pBVar6;
            FUN_00403b70(DeviceInfoSet,&local_a4);
            FUN_00403b70(DeviceInfoSet,&local_a4);
          }
        }
      }
      local_b0 = local_b0 + 1;
    } while ((int)local_b0 < 0x7f);
  }
  SetupDiDestroyDeviceInfoList(DeviceInfoSet);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl FUN_00403ef0(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined local_8 [4];
  
  iVar1 = (*DAT_0047ef94)(DAT_0047ef70,DAT_0047ef76,param_1,param_2,local_8,0);
  return (iVar1 != 0) - 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

size_t __cdecl FUN_00403f30(void *param_1)

{
  int iVar1;
  
LAB_00403f33:
  do {
    if (DAT_0047f0ec == 0) {
      iVar1 = (*DAT_0047efa0)(DAT_0047ef70,&DAT_0047f0d8,&DAT_0047f200,0);
      if (iVar1 == 0) goto LAB_00403f33;
      DAT_0047f0ec = 1;
    }
    else {
      _DAT_0047f0d8 = 0;
      _DAT_0047f0dc = 0;
      _DAT_0047f0e0 = 0;
      _DAT_0047f0e4 = 0;
      _DAT_0047f0e8 = 0;
      iVar1 = (*DAT_0047ef90)(DAT_0047ef70,DAT_0047ef75,&DAT_0047f0f0,0x10e,0,&DAT_0047f0d8);
      DAT_0047f0ec = 0;
    }
    if (iVar1 != 0) {
      FID_conflict__memcpy(param_1,&DAT_0047f0f0,DAT_0047f200);
      return DAT_0047f200;
    }
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00403fe0(void)

{
  undefined4 uVar1;
  
  _memset(&DAT_0047eee0,0,0xc4);
  FUN_00403c40(&DAT_0047eee0);
  if (DAT_0047efa4 != 1) {
    return 0xffffffff;
  }
  DAT_0047f0ec = 1;
  _DAT_0047efbc = 1;
  FUN_00403920();
  uVar1 = FUN_00403a10();
  return uVar1;
}



void FUN_00404030(void)

{
  if ((DAT_0047ef68 != (HANDLE)0xffffffff) && (DAT_0047ef68 != (HANDLE)0x0)) {
    CloseHandle(DAT_0047ef68);
    (*DAT_0047ef84)(DAT_0047ef70);
    FreeLibrary(DAT_0047ef6c);
  }
  _memset(&DAT_0047eee0,0,0xc4);
  return;
}



// Library Function - Single Match
//  _memset
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

void * __cdecl _memset(void *_Dst,int _Val,size_t _Size)

{
  uint uVar1;
  undefined (*pauVar2) [16];
  uint uVar3;
  size_t sVar4;
  uint *puVar5;
  
  if (_Size == 0) {
    return _Dst;
  }
  uVar1 = _Val & 0xff;
  if ((((char)_Val == '\0') && (0x7f < _Size)) && (DAT_0047ffa4 != 0)) {
    pauVar2 = __VEC_memzero((undefined (*) [16])_Dst,_Size);
    return pauVar2;
  }
  puVar5 = (uint *)_Dst;
  if (3 < _Size) {
    uVar3 = -(int)_Dst & 3;
    sVar4 = _Size;
    if (uVar3 != 0) {
      sVar4 = _Size - uVar3;
      do {
        *(char *)puVar5 = (char)_Val;
        puVar5 = (uint *)((int)puVar5 + 1);
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
    }
    uVar1 = uVar1 * 0x1010101;
    _Size = sVar4 & 3;
    uVar3 = sVar4 >> 2;
    if (uVar3 != 0) {
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        *puVar5 = uVar1;
        puVar5 = puVar5 + 1;
      }
      if (_Size == 0) {
        return _Dst;
      }
    }
  }
  do {
    *(char *)puVar5 = (char)uVar1;
    puVar5 = (uint *)((int)puVar5 + 1);
    _Size = _Size - 1;
  } while (_Size != 0);
  return _Dst;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == DAT_0043d030) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Multiple Matches With Different Base Names
//  _printf
//  _wprintf
// 
// Library: Visual Studio 2010 Release

int __cdecl FID_conflict__wprintf(char *_Format,...)

{
  int *piVar1;
  int iVar2;
  undefined **ppuVar3;
  int _Flag;
  localeinfo_struct *plVar4;
  int **ppiVar5;
  
  if (_Format == (char *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00406231();
    iVar2 = -1;
  }
  else {
    ppuVar3 = FUN_004042cc();
    __lock_file2(1,ppuVar3 + 8);
    ppuVar3 = FUN_004042cc();
    _Flag = __stbuf((FILE *)(ppuVar3 + 8));
    ppiVar5 = (int **)&stack0x00000008;
    plVar4 = (localeinfo_struct *)0x0;
    ppuVar3 = FUN_004042cc();
    iVar2 = FUN_0040549f((FILE *)(ppuVar3 + 8),(byte *)_Format,plVar4,ppiVar5);
    ppuVar3 = FUN_004042cc();
    __ftbuf(_Flag,(FILE *)(ppuVar3 + 8));
    FUN_0040419d();
  }
  return iVar2;
}



void FUN_0040419d(void)

{
  undefined **ppuVar1;
  
  ppuVar1 = FUN_004042cc();
  __unlock_file2(1,ppuVar1 + 8);
  return;
}



bool FUN_004041b0(void)

{
  return DAT_0047f204 == (DAT_0043d030 | 1);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fputs
// 
// Library: Visual Studio 2010 Release

int __cdecl _fputs(char *_Str,FILE *_File)

{
  int *piVar1;
  uint uVar2;
  size_t _Count;
  int _Flag;
  size_t sVar3;
  undefined *puVar4;
  
  if ((_Str != (char *)0x0) && (_File != (FILE *)0x0)) {
    if ((*(byte *)&_File->_flag & 0x40) != 0) {
LAB_00404269:
      _Count = _strlen(_Str);
      __lock_file(_File);
      _Flag = __stbuf(_File);
      sVar3 = __fwrite_nolock(_Str,1,_Count,_File);
      __ftbuf(_Flag,_File);
      FUN_004042c4();
      return (sVar3 == _Count) - 1;
    }
    uVar2 = __fileno(_File);
    if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
      puVar4 = &DAT_0043d440;
    }
    else {
      puVar4 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0047fea0)[(int)uVar2 >> 5]);
    }
    if ((puVar4[0x24] & 0x7f) == 0) {
      if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
        puVar4 = &DAT_0043d440;
      }
      else {
        puVar4 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0047fea0)[(int)uVar2 >> 5]);
      }
      if ((puVar4[0x24] & 0x80) == 0) goto LAB_00404269;
    }
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  FUN_00406231();
  return -1;
}



void FUN_004042c4(void)

{
  FILE *unaff_EDI;
  
  __unlock_file(unaff_EDI);
  return;
}



undefined ** FUN_004042cc(void)

{
  return &PTR_DAT_0043d038;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_0043d038) || ((FILE *)&DAT_0043d298 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x21e82]._base >> 5) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
  }
  return;
}



// Library Function - Single Match
//  __lock_file2
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    __lock(_Index + 0x10);
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) | 0x8000;
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// Library Function - Single Match
//  __unlock_file
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void __cdecl __unlock_file(FILE *_File)

{
  if (((FILE *)((int)&DAT_0043d034 + 3U) < _File) && (_File < (FILE *)0x43d299)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_00406cc5(((int)&_File[-0x21e82]._base >> 5) + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  __unlock_file2
// 
// Library: Visual Studio 2010 Release

void __cdecl __unlock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) & 0xffff7fff;
    FUN_00406cc5(_Index + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// Library Function - Single Match
//  __vsprintf_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __vsprintf_l(char *_DstBuf,char *_Format,_locale_t param_3,va_list _ArgList)

{
  int *piVar1;
  int iVar2;
  char **ppcVar3;
  FILE local_24;
  
  local_24._ptr = (char *)0x0;
  ppcVar3 = (char **)&local_24._cnt;
  for (iVar2 = 7; iVar2 != 0; iVar2 = iVar2 + -1) {
    *ppcVar3 = (char *)0x0;
    ppcVar3 = ppcVar3 + 1;
  }
  if ((_Format != (char *)0x0) && (_DstBuf != (char *)0x0)) {
    local_24._base = _DstBuf;
    local_24._ptr = _DstBuf;
    local_24._cnt = 0x7fffffff;
    local_24._flag = 0x42;
    iVar2 = FUN_0040549f(&local_24,(byte *)_Format,param_3,(int **)_ArgList);
    local_24._cnt = local_24._cnt + -1;
    if (local_24._cnt < 0) {
      __flsbuf(0,&local_24);
    }
    else {
      *local_24._ptr = '\0';
    }
    return iVar2;
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  FUN_00406231();
  return -1;
}



// Library Function - Single Match
//  _vsprintf
// 
// Library: Visual Studio 2010 Release

int __cdecl _vsprintf(char *_Dest,char *_Format,va_list _Args)

{
  int iVar1;
  
  iVar1 = __vsprintf_l(_Dest,_Format,(_locale_t)0x0,_Args);
  return iVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fgets
// 
// Library: Visual Studio 2010 Release

char * __cdecl _fgets(char *_Buf,int _MaxCount,FILE *_File)

{
  int *piVar1;
  uint uVar2;
  undefined *puVar3;
  char *pcVar4;
  char *local_20;
  
  local_20 = _Buf;
  if ((((_Buf == (char *)0x0) && (_MaxCount != 0)) || (_MaxCount < 0)) || (_File == (FILE *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00406231();
  }
  else if (_MaxCount != 0) {
    __lock_file(_File);
    if ((*(byte *)&_File->_flag & 0x40) == 0) {
      uVar2 = __fileno(_File);
      if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
        puVar3 = &DAT_0043d440;
      }
      else {
        puVar3 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0047fea0)[(int)uVar2 >> 5]);
      }
      if ((puVar3[0x24] & 0x7f) == 0) {
        if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
          puVar3 = &DAT_0043d440;
        }
        else {
          puVar3 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0047fea0)[(int)uVar2 >> 5]);
        }
        if ((puVar3[0x24] & 0x80) == 0) goto LAB_004045f7;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      FUN_00406231();
      local_20 = (char *)0x0;
    }
LAB_004045f7:
    pcVar4 = _Buf;
    if (local_20 != (char *)0x0) {
      do {
        _MaxCount = _MaxCount + -1;
        if (_MaxCount == 0) break;
        piVar1 = &_File->_cnt;
        *piVar1 = *piVar1 + -1;
        if (*piVar1 < 0) {
          uVar2 = __filbuf(_File);
        }
        else {
          uVar2 = (uint)(byte)*_File->_ptr;
          _File->_ptr = _File->_ptr + 1;
        }
        if (uVar2 == 0xffffffff) {
          if (pcVar4 == _Buf) {
            local_20 = (char *)0x0;
            goto LAB_00404637;
          }
          break;
        }
        *pcVar4 = (char)uVar2;
        pcVar4 = pcVar4 + 1;
      } while ((char)uVar2 != '\n');
      *pcVar4 = '\0';
    }
LAB_00404637:
    FUN_0040464f();
    return local_20;
  }
  return (char *)0x0;
}



void FUN_0040464f(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// Library Function - Single Match
//  ___crtCorExitProcess
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___crtCorExitProcess(int param_1)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleW(L"mscoree.dll");
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,"CorExitProcess");
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(param_1);
    }
  }
  return;
}



// Library Function - Single Match
//  ___crtExitProcess
// 
// Library: Visual Studio 2010 Release

void __cdecl ___crtExitProcess(int param_1)

{
  ___crtCorExitProcess(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_0040469a(void)

{
  __lock(8);
  return;
}



void FUN_004046a3(void)

{
  FUN_00406cc5(8);
  return;
}



// Library Function - Single Match
//  __init_pointers
// 
// Library: Visual Studio 2010 Release

void __cdecl __init_pointers(void)

{
  undefined4 uVar1;
  
  uVar1 = FUN_004072fb();
  FUN_004072c4(uVar1);
  FUN_004060a7(uVar1);
  FUN_004072b5(uVar1);
  FUN_004072a6(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_00407090();
  return;
}



// Library Function - Single Match
//  __initterm_e
// 
// Library: Visual Studio 2010 Release

void __cdecl __initterm_e(undefined **param_1,undefined **param_2)

{
  int iVar1;
  
  iVar1 = 0;
  while ((param_1 < param_2 && (iVar1 == 0))) {
    if ((code *)*param_1 != (code *)0x0) {
      iVar1 = (*(code *)*param_1)();
    }
    param_1 = (code **)param_1 + 1;
  }
  return;
}



// Library Function - Single Match
//  __cinit
// 
// Library: Visual Studio 2010 Release

int __cdecl __cinit(int param_1)

{
  BOOL BVar1;
  int iVar2;
  code **ppcVar3;
  
  if ((DAT_0047ffc0 != (code *)0x0) &&
     (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0047ffc0), BVar1 != 0)) {
    (*DAT_0047ffc0)(param_1);
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_0040c14c,(undefined **)&DAT_0040c164);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_004078cf);
    ppcVar3 = (code **)&DAT_0040c144;
    do {
      if (*ppcVar3 != (code *)0x0) {
        (**ppcVar3)();
      }
      ppcVar3 = ppcVar3 + 1;
    } while (ppcVar3 < &DAT_0040c148);
    if ((DAT_0047ffc4 != (code *)0x0) &&
       (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0047ffc4), BVar1 != 0)) {
      (*DAT_0047ffc4)(0,2,0);
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x004048cb)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _doexit
// 
// Library: Visual Studio 2010 Release

void __cdecl _doexit(int param_1,int param_2,int param_3)

{
  PVOID *ppvVar1;
  PVOID *ppvVar2;
  PVOID pvVar3;
  code *pcVar4;
  PVOID *ppvVar5;
  PVOID *ppvVar6;
  PVOID *local_34;
  PVOID *local_2c;
  PVOID *local_28;
  code **local_24;
  code **local_20;
  
  __lock(8);
  if (DAT_0047f23c != 1) {
    _DAT_0047f238 = 1;
    DAT_0047f234 = (undefined)param_3;
    if (param_2 == 0) {
      ppvVar1 = (PVOID *)DecodePointer(Ptr_0047ffb8);
      if (ppvVar1 != (PVOID *)0x0) {
        ppvVar2 = (PVOID *)DecodePointer(Ptr_0047ffb4);
        local_34 = ppvVar1;
        local_2c = ppvVar2;
        local_28 = ppvVar1;
        while (ppvVar2 = ppvVar2 + -1, ppvVar1 <= ppvVar2) {
          pvVar3 = (PVOID)FUN_004072fb();
          if (*ppvVar2 != pvVar3) {
            if (ppvVar2 < ppvVar1) break;
            pcVar4 = (code *)DecodePointer(*ppvVar2);
            pvVar3 = (PVOID)FUN_004072fb();
            *ppvVar2 = pvVar3;
            (*pcVar4)();
            ppvVar5 = (PVOID *)DecodePointer(Ptr_0047ffb8);
            ppvVar6 = (PVOID *)DecodePointer(Ptr_0047ffb4);
            if ((local_28 != ppvVar5) || (ppvVar1 = local_34, local_2c != ppvVar6)) {
              ppvVar1 = ppvVar5;
              ppvVar2 = ppvVar6;
              local_34 = ppvVar5;
              local_2c = ppvVar6;
              local_28 = ppvVar5;
            }
          }
        }
      }
      for (local_20 = (code **)&DAT_0040c168; local_20 < &DAT_0040c174; local_20 = local_20 + 1) {
        if (*local_20 != (code *)0x0) {
          (**local_20)();
        }
      }
    }
    for (local_24 = (code **)&DAT_0040c178; local_24 < &DAT_0040c17c; local_24 = local_24 + 1) {
      if (*local_24 != (code *)0x0) {
        (**local_24)();
      }
    }
  }
  FUN_004048c5();
  if (param_3 == 0) {
    DAT_0047f23c = 1;
    FUN_00406cc5(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_004048c5(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_00406cc5(8);
  }
  return;
}



// Library Function - Single Match
//  _exit
// 
// Library: Visual Studio 2010 Release

void __cdecl _exit(int _Code)

{
  _doexit(_Code,0,0);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2010 Release

void __cdecl __exit(int param_1)

{
  _doexit(param_1,1,0);
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 2010 Release

void __cdecl __cexit(void)

{
  _doexit(0,0,1);
  return;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 2010 Release

void __cdecl __amsg_exit(int param_1)

{
  code *pcVar1;
  
  __FF_MSGBANNER();
  __NMSG_WRITE(param_1);
  __exit(0xff);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  _memcpy
//  _memmove
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

void * __cdecl FID_conflict__memcpy(void *_Dst,void *_Src,size_t _Size)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if ((_Src < _Dst) && (_Dst < (void *)(_Size + (int)_Src))) {
    puVar1 = (undefined4 *)((_Size - 4) + (int)_Src);
    puVar4 = (undefined4 *)((_Size - 4) + (int)_Dst);
    if (((uint)puVar4 & 3) == 0) {
      uVar2 = _Size >> 2;
      uVar3 = _Size & 3;
      if (7 < uVar2) {
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar4 = *puVar1;
          puVar1 = puVar1 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar3) {
        case 0:
          return _Dst;
        case 2:
          goto switchD_00404b2f_caseD_2;
        case 3:
          goto switchD_00404b2f_caseD_3;
        }
        goto switchD_00404b2f_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_00404b2f_caseD_0;
      case 1:
        goto switchD_00404b2f_caseD_1;
      case 2:
        goto switchD_00404b2f_caseD_2;
      case 3:
        goto switchD_00404b2f_caseD_3;
      default:
        uVar2 = _Size - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          puVar1 = (undefined4 *)((int)puVar1 + -1);
          uVar2 = uVar2 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_00404b2f_caseD_2;
            case 3:
              goto switchD_00404b2f_caseD_3;
            }
            goto switchD_00404b2f_caseD_1;
          }
          break;
        case 2:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          puVar1 = (undefined4 *)((int)puVar1 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_00404b2f_caseD_2;
            case 3:
              goto switchD_00404b2f_caseD_3;
            }
            goto switchD_00404b2f_caseD_1;
          }
          break;
        case 3:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
          puVar1 = (undefined4 *)((int)puVar1 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_00404b2f_caseD_2;
            case 3:
              goto switchD_00404b2f_caseD_3;
            }
            goto switchD_00404b2f_caseD_1;
          }
        }
      }
    }
    switch(uVar2) {
    case 7:
      puVar4[7 - uVar2] = puVar1[7 - uVar2];
    case 6:
      puVar4[6 - uVar2] = puVar1[6 - uVar2];
    case 5:
      puVar4[5 - uVar2] = puVar1[5 - uVar2];
    case 4:
      puVar4[4 - uVar2] = puVar1[4 - uVar2];
    case 3:
      puVar4[3 - uVar2] = puVar1[3 - uVar2];
    case 2:
      puVar4[2 - uVar2] = puVar1[2 - uVar2];
    case 1:
      puVar4[1 - uVar2] = puVar1[1 - uVar2];
      puVar1 = puVar1 + -uVar2;
      puVar4 = puVar4 + -uVar2;
    }
    switch(uVar3) {
    case 1:
switchD_00404b2f_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_00404b2f_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_00404b2f_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_00404b2f_caseD_0:
    return _Dst;
  }
  if (((0x7f < _Size) && (DAT_0047ffa4 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
    puVar1 = __VEC_memcpy(_Size);
    return puVar1;
  }
  puVar1 = (undefined4 *)_Dst;
  if (((uint)_Dst & 3) == 0) {
    uVar2 = _Size >> 2;
    uVar3 = _Size & 3;
    if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar1 = *_Src;
        _Src = (undefined4 *)((int)_Src + 4);
        puVar1 = puVar1 + 1;
      }
      switch(uVar3) {
      case 0:
        return _Dst;
      case 2:
        goto switchD_004049a9_caseD_2;
      case 3:
        goto switchD_004049a9_caseD_3;
      }
      goto switchD_004049a9_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_004049a9_caseD_0;
    case 1:
      goto switchD_004049a9_caseD_1;
    case 2:
      goto switchD_004049a9_caseD_2;
    case 3:
      goto switchD_004049a9_caseD_3;
    default:
      uVar2 = (_Size - 4) + ((uint)_Dst & 3);
      switch((uint)_Dst & 3) {
      case 1:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 2) = *(undefined *)((int)_Src + 2);
        _Src = (void *)((int)_Src + 3);
        puVar1 = (undefined4 *)((int)_Dst + 3);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_004049a9_caseD_2;
          case 3:
            goto switchD_004049a9_caseD_3;
          }
          goto switchD_004049a9_caseD_1;
        }
        break;
      case 2:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        _Src = (void *)((int)_Src + 2);
        puVar1 = (undefined4 *)((int)_Dst + 2);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_004049a9_caseD_2;
          case 3:
            goto switchD_004049a9_caseD_3;
          }
          goto switchD_004049a9_caseD_1;
        }
        break;
      case 3:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        _Src = (void *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        puVar1 = (undefined4 *)((int)_Dst + 1);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_004049a9_caseD_2;
          case 3:
            goto switchD_004049a9_caseD_3;
          }
          goto switchD_004049a9_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar2) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 7] = *(undefined4 *)((int)_Src + (uVar2 - 7) * 4);
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 6] = *(undefined4 *)((int)_Src + (uVar2 - 6) * 4);
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 5] = *(undefined4 *)((int)_Src + (uVar2 - 5) * 4);
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 4] = *(undefined4 *)((int)_Src + (uVar2 - 4) * 4);
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 3] = *(undefined4 *)((int)_Src + (uVar2 - 3) * 4);
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 2] = *(undefined4 *)((int)_Src + (uVar2 - 2) * 4);
  case 4:
  case 5:
  case 6:
  case 7:
    puVar1[uVar2 - 1] = *(undefined4 *)((int)_Src + (uVar2 - 1) * 4);
    _Src = (void *)((int)_Src + uVar2 * 4);
    puVar1 = puVar1 + uVar2;
  }
  switch(uVar3) {
  case 1:
switchD_004049a9_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_004049a9_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_004049a9_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_004049a9_caseD_0:
  return _Dst;
}



// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2010 Release

void * __cdecl _malloc(size_t _Size)

{
  SIZE_T dwBytes;
  LPVOID pvVar1;
  int iVar2;
  int *piVar3;
  
  if (_Size < 0xffffffe1) {
    do {
      if (hHeap_0047fd38 == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      dwBytes = _Size;
      if (_Size == 0) {
        dwBytes = 1;
      }
      pvVar1 = HeapAlloc(hHeap_0047fd38,0,dwBytes);
      if (pvVar1 != (LPVOID)0x0) {
        return pvVar1;
      }
      if (DAT_0047fd3c == 0) {
        piVar3 = __errno();
        *piVar3 = 0xc;
        break;
      }
      iVar2 = __callnewh(_Size);
    } while (iVar2 != 0);
    piVar3 = __errno();
    *piVar3 = 0xc;
  }
  else {
    __callnewh(_Size);
    piVar3 = __errno();
    *piVar3 = 0xc;
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  public: __thiscall _LocaleUpdate::_LocaleUpdate(struct localeinfo_struct *)
// 
// Library: Visual Studio 2010 Release

_LocaleUpdate * __thiscall
_LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,localeinfo_struct *param_1)

{
  uint *puVar1;
  _ptiddata p_Var2;
  pthreadlocinfo ptVar3;
  pthreadmbcinfo ptVar4;
  
  this[0xc] = (_LocaleUpdate)0x0;
  if (param_1 == (localeinfo_struct *)0x0) {
    p_Var2 = __getptd();
    *(_ptiddata *)(this + 8) = p_Var2;
    *(pthreadlocinfo *)this = p_Var2->ptlocinfo;
    *(pthreadmbcinfo *)(this + 4) = p_Var2->ptmbcinfo;
    if ((*(undefined **)this != PTR_DAT_0043dd38) && ((p_Var2->_ownlocale & DAT_0043daf0) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != lpAddend_0043d9f8) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_0043daf0) == 0)) {
      ptVar4 = ___updatetmbcinfo();
      *(pthreadmbcinfo *)(this + 4) = ptVar4;
    }
    if ((*(byte *)(*(int *)(this + 8) + 0x70) & 2) == 0) {
      puVar1 = (uint *)(*(int *)(this + 8) + 0x70);
      *puVar1 = *puVar1 | 2;
      this[0xc] = (_LocaleUpdate)0x1;
    }
  }
  else {
    *(pthreadlocinfo *)this = param_1->locinfo;
    *(pthreadmbcinfo *)(this + 4) = param_1->mbcinfo;
  }
  return this;
}



// Library Function - Single Match
//  __toupper_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __toupper_l(int _C,_locale_t _Locale)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  CHAR CVar5;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  byte local_c;
  undefined local_b;
  CHAR local_8;
  CHAR local_7;
  undefined local_6;
  
  iVar1 = _C;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,_Locale);
  if ((uint)_C < 0x100) {
    if ((int)(local_1c.locinfo)->locale_name[3] < 2) {
      uVar2 = *(ushort *)(local_1c.locinfo[1].lc_category[0].locale + _C * 2) & 2;
    }
    else {
      uVar2 = __isctype_l(_C,2,&local_1c);
    }
    if (uVar2 == 0) {
LAB_00404e2b:
      if (local_10 == '\0') {
        return iVar1;
      }
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      return iVar1;
    }
    uVar2 = (uint)*(byte *)((int)local_1c.locinfo[1].lc_category[0].refcount + _C);
  }
  else {
    CVar5 = (CHAR)_C;
    if (((int)(local_1c.locinfo)->locale_name[3] < 2) ||
       (iVar3 = __isleadbyte_l(_C >> 8 & 0xff,&local_1c), iVar3 == 0)) {
      piVar4 = __errno();
      *piVar4 = 0x2a;
      local_7 = '\0';
      iVar3 = 1;
      local_8 = CVar5;
    }
    else {
      _C._0_1_ = (CHAR)((uint)_C >> 8);
      local_8 = (CHAR)_C;
      local_6 = 0;
      iVar3 = 2;
      local_7 = CVar5;
    }
    iVar3 = ___crtLCMapStringA(&local_1c,(local_1c.locinfo)->lc_category[0].wlocale,0x200,&local_8,
                               iVar3,(LPSTR)&local_c,3,(local_1c.locinfo)->lc_codepage,1);
    if (iVar3 == 0) goto LAB_00404e2b;
    uVar2 = (uint)local_c;
    if (iVar3 != 1) {
      uVar2 = (uint)CONCAT11(local_c,local_b);
    }
  }
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return uVar2;
}



// Library Function - Single Match
//  _toupper
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _toupper(int _C)

{
  if (DAT_0047fd5c == 0) {
    if (_C - 0x61U < 0x1a) {
      return _C + -0x20;
    }
  }
  else {
    _C = __toupper_l(_C,(_locale_t)0x0);
  }
  return _C;
}



// Library Function - Single Match
//  _free
// 
// Library: Visual Studio 2010 Release

void __cdecl _free(void *_Memory)

{
  BOOL BVar1;
  int *piVar2;
  DWORD DVar3;
  int iVar4;
  
  if (_Memory != (void *)0x0) {
    BVar1 = HeapFree(hHeap_0047fd38,0,_Memory);
    if (BVar1 == 0) {
      piVar2 = __errno();
      DVar3 = GetLastError();
      iVar4 = __get_errno_from_oserr(DVar3);
      *piVar2 = iVar4;
    }
  }
  return;
}



uint * __cdecl FUN_00404f50(uint *param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  uint *puVar4;
  uint *puVar5;
  char *pcVar6;
  
  if (*param_2 == '\0') {
    return param_1;
  }
  if (param_2[1] == '\0') {
    puVar5 = FUN_00408b26(param_1);
    return puVar5;
  }
  do {
    cVar3 = *(char *)param_1;
    do {
      while (puVar5 = param_1, param_1 = (uint *)((int)puVar5 + 1), cVar3 != *param_2) {
        if (cVar3 == '\0') {
          return (uint *)0x0;
        }
        cVar3 = *(char *)param_1;
      }
      cVar3 = *(char *)param_1;
      pcVar6 = param_2;
      puVar4 = puVar5;
    } while (cVar3 != param_2[1]);
    do {
      if (pcVar6[2] == '\0') {
        return puVar5;
      }
      if (*(char *)(uint *)((int)puVar4 + 2) != pcVar6[2]) break;
      pcVar1 = pcVar6 + 3;
      if (*pcVar1 == '\0') {
        return puVar5;
      }
      pcVar2 = (char *)((int)puVar4 + 3);
      pcVar6 = pcVar6 + 2;
      puVar4 = (uint *)((int)puVar4 + 2);
    } while (*pcVar1 == *pcVar2);
  } while( true );
}



// Library Function - Single Match
//  _fast_error_exit
// 
// Library: Visual Studio 2010 Release

void __cdecl _fast_error_exit(int param_1)

{
  if (DAT_0047f248 != 2) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040502e)
// WARNING: Removing unreachable block (ram,0x0040511b)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___tmainCRTStartup
// 
// Library: Visual Studio 2010 Release

int ___tmainCRTStartup(void)

{
  int iVar1;
  
  if (DAT_0047ffac == 0) {
    HeapSetInformation((HANDLE)0x0,HeapEnableTerminationOnCorruption,(PVOID)0x0,0);
  }
  iVar1 = __heap_init();
  if (iVar1 == 0) {
    _fast_error_exit(0x1c);
  }
  iVar1 = __mtinit();
  if (iVar1 == 0) {
    _fast_error_exit(0x10);
  }
  __RTC_Initialize();
  iVar1 = __ioinit();
  if (iVar1 < 0) {
    __amsg_exit(0x1b);
  }
  DAT_0047ffa8 = GetCommandLineA();
  DAT_0047f240 = ___crtGetEnvironmentStringsA();
  iVar1 = __setargv();
  if (iVar1 < 0) {
    __amsg_exit(8);
  }
  iVar1 = __setenvp();
  if (iVar1 < 0) {
    __amsg_exit(9);
  }
  iVar1 = __cinit(1);
  if (iVar1 != 0) {
    __amsg_exit(iVar1);
  }
  _DAT_0047f220 = DAT_0047f21c;
  iVar1 = FUN_004037c0(DAT_0047f210,DAT_0047f214);
                    // WARNING: Subroutine does not return
  _exit(iVar1);
}



void entry(void)

{
  ___security_init_cookie();
  ___tmainCRTStartup();
  return;
}



// Library Function - Single Match
//  __VEC_memzero
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

undefined (*) [16] __fastcall __VEC_memzero(undefined (*param_1) [16],uint param_2)

{
  uint uVar1;
  undefined (*pauVar2) [16];
  uint uVar3;
  
  pauVar2 = param_1;
  if (((uint)param_1 & 0xf) != 0) {
    uVar3 = 0x10 - ((uint)param_1 & 0xf);
    param_2 = param_2 - uVar3;
    for (uVar1 = uVar3 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      (*pauVar2)[0] = 0;
      pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
    }
    for (uVar3 = uVar3 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined4 *)*pauVar2 = 0;
      pauVar2 = (undefined (*) [16])(*pauVar2 + 4);
    }
  }
  for (uVar1 = param_2 >> 7; uVar1 != 0; uVar1 = uVar1 - 1) {
    *pauVar2 = (undefined  [16])0x0;
    pauVar2[1] = (undefined  [16])0x0;
    pauVar2[2] = (undefined  [16])0x0;
    pauVar2[3] = (undefined  [16])0x0;
    pauVar2[4] = (undefined  [16])0x0;
    pauVar2[5] = (undefined  [16])0x0;
    pauVar2[6] = (undefined  [16])0x0;
    pauVar2[7] = (undefined  [16])0x0;
    pauVar2 = pauVar2 + 8;
  }
  if ((param_2 & 0x7f) != 0) {
    for (uVar1 = (param_2 & 0x7f) >> 4; uVar1 != 0; uVar1 = uVar1 - 1) {
      *pauVar2 = (undefined  [16])0x0;
      pauVar2 = pauVar2 + 1;
    }
    if ((param_2 & 0xf) != 0) {
      for (uVar1 = (param_2 & 0xf) >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
        *(undefined4 *)*pauVar2 = 0;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 4);
      }
      for (uVar1 = param_2 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
        (*pauVar2)[0] = 0;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
      }
    }
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___report_gsfailure
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___report_gsfailure(void)

{
  undefined4 in_EAX;
  HANDLE hProcess;
  undefined4 in_ECX;
  undefined4 in_EDX;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined4 unaff_retaddr;
  UINT uExitCode;
  undefined4 local_32c;
  undefined4 local_328;
  
  _DAT_0047f368 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_0047f36c = &stack0x00000004;
  _DAT_0047f2a8 = 0x10001;
  _DAT_0047f250 = 0xc0000409;
  _DAT_0047f254 = 1;
  local_32c = DAT_0043d030;
  local_328 = DAT_0043d034;
  _DAT_0047f25c = unaff_retaddr;
  _DAT_0047f334 = in_GS;
  _DAT_0047f338 = in_FS;
  _DAT_0047f33c = in_ES;
  _DAT_0047f340 = in_DS;
  _DAT_0047f344 = unaff_EDI;
  _DAT_0047f348 = unaff_ESI;
  _DAT_0047f34c = unaff_EBX;
  _DAT_0047f350 = in_EDX;
  _DAT_0047f354 = in_ECX;
  _DAT_0047f358 = in_EAX;
  _DAT_0047f35c = unaff_EBP;
  DAT_0047f360 = unaff_retaddr;
  _DAT_0047f364 = in_CS;
  _DAT_0047f370 = in_SS;
  DAT_0047f2a0 = IsDebuggerPresent();
  FUN_004091de();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&ExceptionInfo_00428bac);
  if (DAT_0047f2a0 == 0) {
    FUN_004091de();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __stbuf
// 
// Library: Visual Studio 2010 Release

int __cdecl __stbuf(FILE *_File)

{
  char **ppcVar1;
  int iVar2;
  undefined **ppuVar3;
  char *pcVar4;
  
  iVar2 = __fileno(_File);
  iVar2 = __isatty(iVar2);
  if (iVar2 == 0) {
    return 0;
  }
  ppuVar3 = FUN_004042cc();
  if (_File == (FILE *)(ppuVar3 + 8)) {
    iVar2 = 0;
  }
  else {
    ppuVar3 = FUN_004042cc();
    if (_File != (FILE *)(ppuVar3 + 0x10)) {
      return 0;
    }
    iVar2 = 1;
  }
  _DAT_0047f208 = _DAT_0047f208 + 1;
  if ((_File->_flag & 0x10cU) != 0) {
    return 0;
  }
  ppcVar1 = (char **)(&DAT_0047f574 + iVar2);
  if (*ppcVar1 == (char *)0x0) {
    pcVar4 = (char *)__malloc_crt(0x1000);
    *ppcVar1 = pcVar4;
    if (pcVar4 == (char *)0x0) {
      _File->_base = (char *)&_File->_charbuf;
      _File->_ptr = (char *)&_File->_charbuf;
      _File->_bufsiz = 2;
      _File->_cnt = 2;
      goto LAB_004053c3;
    }
  }
  pcVar4 = *ppcVar1;
  _File->_base = pcVar4;
  _File->_ptr = pcVar4;
  _File->_bufsiz = 0x1000;
  _File->_cnt = 0x1000;
LAB_004053c3:
  _File->_flag = _File->_flag | 0x1102;
  return 1;
}



// Library Function - Single Match
//  __ftbuf
// 
// Library: Visual Studio 2010 Release

void __cdecl __ftbuf(int _Flag,FILE *_File)

{
  if ((_Flag != 0) && ((_File->_flag & 0x1000U) != 0)) {
    __flush(_File);
    _File->_flag = _File->_flag & 0xffffeeff;
    _File->_bufsiz = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
  }
  return;
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 2010 Release

void __fastcall _write_char(FILE *param_1)

{
  int *piVar1;
  byte in_AL;
  uint uVar2;
  int *unaff_ESI;
  
  if (((*(byte *)&param_1->_flag & 0x40) == 0) || (param_1->_base != (char *)0x0)) {
    piVar1 = &param_1->_cnt;
    *piVar1 = *piVar1 + -1;
    if (*piVar1 < 0) {
      uVar2 = __flsbuf((int)(char)in_AL,param_1);
    }
    else {
      *param_1->_ptr = in_AL;
      param_1->_ptr = param_1->_ptr + 1;
      uVar2 = (uint)in_AL;
    }
    if (uVar2 == 0xffffffff) {
      *unaff_ESI = -1;
      return;
    }
  }
  *unaff_ESI = *unaff_ESI + 1;
  return;
}



void __cdecl FUN_0040543d(undefined4 param_1,int param_2)

{
  int iVar1;
  int *in_EAX;
  FILE *unaff_EBX;
  int *unaff_EDI;
  
  iVar1 = *unaff_EDI;
  if (((*(byte *)&unaff_EBX->_flag & 0x40) == 0) || (unaff_EBX->_base != (char *)0x0)) {
    *unaff_EDI = 0;
    if (0 < param_2) {
      do {
        param_2 = param_2 + -1;
        _write_char(unaff_EBX);
        if (*in_EAX == -1) {
          if (*unaff_EDI != 0x2a) break;
          _write_char(unaff_EBX);
        }
      } while (0 < param_2);
      if (*unaff_EDI != 0) {
        return;
      }
    }
    *unaff_EDI = iVar1;
  }
  else {
    *in_EAX = *in_EAX + param_2;
  }
  return;
}



// WARNING: Type propagation algorithm not settling

void __cdecl FUN_0040549f(FILE *param_1,byte *param_2,localeinfo_struct *param_3,int **param_4)

{
  byte bVar1;
  wchar_t _WCh;
  FILE *pFVar2;
  int *piVar3;
  uint uVar4;
  undefined3 extraout_var;
  int iVar5;
  code *pcVar6;
  int *piVar7;
  char *pcVar8;
  errno_t eVar9;
  undefined *puVar10;
  int extraout_ECX;
  byte *pbVar11;
  int **ppiVar12;
  bool bVar13;
  undefined8 uVar14;
  int *piVar15;
  undefined4 uVar16;
  localeinfo_struct *plVar17;
  int *local_284;
  int *local_280;
  undefined4 local_27c;
  int local_278;
  int local_274;
  int *local_270;
  size_t local_26c;
  char *local_264;
  localeinfo_struct local_260;
  int local_258;
  char local_254;
  int local_250;
  int *local_24c;
  int local_248;
  byte *local_244;
  int local_240;
  int *local_23c;
  int local_238;
  FILE *local_234;
  undefined local_230;
  char local_22f;
  size_t local_22c;
  int local_228;
  int *local_224;
  int **local_220;
  int *local_21c;
  byte local_215;
  uint local_214;
  int local_210 [127];
  undefined4 local_11;
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  local_234 = param_1;
  local_220 = param_4;
  local_250 = 0;
  local_214 = 0;
  local_23c = (int *)0x0;
  local_21c = (int *)0x0;
  local_238 = 0;
  local_248 = 0;
  local_240 = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_260,param_3);
  local_270 = __errno();
  if (param_1 != (FILE *)0x0) {
    if ((*(byte *)&param_1->_flag & 0x40) == 0) {
      uVar4 = __fileno(param_1);
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar10 = &DAT_0043d440;
      }
      else {
        puVar10 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0047fea0)[(int)uVar4 >> 5]);
      }
      if ((puVar10[0x24] & 0x7f) == 0) {
        if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
          puVar10 = &DAT_0043d440;
        }
        else {
          puVar10 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0047fea0)[(int)uVar4 >> 5]);
        }
        if ((puVar10[0x24] & 0x80) == 0) goto LAB_004055a4;
      }
    }
    else {
LAB_004055a4:
      if (param_2 != (byte *)0x0) {
        local_215 = *param_2;
        local_228 = 0;
        local_22c = 0;
        local_24c = (int *)0x0;
        iVar5 = 0;
        ppiVar12 = local_220;
        while ((local_220 = ppiVar12, local_215 != 0 &&
               (pbVar11 = param_2 + 1, local_244 = pbVar11, -1 < local_228))) {
          if ((byte)(local_215 - 0x20) < 0x59) {
            uVar4 = (int)*(char *)((int)&PTR_DAT_00428bb0 + (int)(char)local_215) & 0xf;
          }
          else {
            uVar4 = 0;
          }
          local_278 = (int)(char)(&DAT_00428bd0)[uVar4 * 8 + iVar5] >> 4;
          switch(local_278) {
          case 0:
switchD_00405619_caseD_0:
            local_240 = 0;
            iVar5 = __isleadbyte_l((uint)local_215,&local_260);
            if (iVar5 != 0) {
              _write_char(local_234);
              local_244 = param_2 + 2;
              if (*pbVar11 == 0) goto LAB_00405515;
            }
            _write_char(local_234);
            break;
          case 1:
            local_21c = (int *)0xffffffff;
            local_27c = 0;
            local_248 = 0;
            local_23c = (int *)0x0;
            local_238 = 0;
            local_214 = 0;
            local_240 = 0;
            break;
          case 2:
            if (local_215 == 0x20) {
              local_214 = local_214 | 2;
            }
            else if (local_215 == 0x23) {
              local_214 = local_214 | 0x80;
            }
            else if (local_215 == 0x2b) {
              local_214 = local_214 | 1;
            }
            else if (local_215 == 0x2d) {
              local_214 = local_214 | 4;
            }
            else if (local_215 == 0x30) {
              local_214 = local_214 | 8;
            }
            break;
          case 3:
            if (local_215 == 0x2a) {
              local_23c = *param_4;
              local_220 = param_4 + 1;
              if ((int)local_23c < 0) {
                local_214 = local_214 | 4;
                local_23c = (int *)-(int)local_23c;
              }
            }
            else {
              local_23c = (int *)((int)local_23c * 10 + -0x30 + (int)(char)local_215);
            }
            break;
          case 4:
            local_21c = (int *)0x0;
            break;
          case 5:
            if (local_215 == 0x2a) {
              local_21c = *param_4;
              local_220 = param_4 + 1;
              if ((int)local_21c < 0) {
                local_21c = (int *)0xffffffff;
              }
            }
            else {
              local_21c = (int *)((int)local_21c * 10 + -0x30 + (int)(char)local_215);
            }
            break;
          case 6:
            if (local_215 == 0x49) {
              bVar1 = *pbVar11;
              if ((bVar1 == 0x36) && (param_2[2] == 0x34)) {
                local_214 = local_214 | 0x8000;
                local_244 = param_2 + 3;
              }
              else if ((bVar1 == 0x33) && (param_2[2] == 0x32)) {
                local_214 = local_214 & 0xffff7fff;
                local_244 = param_2 + 3;
              }
              else if (((((bVar1 != 100) && (bVar1 != 0x69)) && (bVar1 != 0x6f)) &&
                       ((bVar1 != 0x75 && (bVar1 != 0x78)))) && (bVar1 != 0x58)) {
                local_278 = 0;
                goto switchD_00405619_caseD_0;
              }
            }
            else if (local_215 == 0x68) {
              local_214 = local_214 | 0x20;
            }
            else if (local_215 == 0x6c) {
              if (*pbVar11 == 0x6c) {
                local_214 = local_214 | 0x1000;
                local_244 = param_2 + 2;
              }
              else {
                local_214 = local_214 | 0x10;
              }
            }
            else if (local_215 == 0x77) {
              local_214 = local_214 | 0x800;
            }
            break;
          case 7:
            if ((char)local_215 < 'e') {
              if (local_215 == 100) {
LAB_00405ae5:
                local_214 = local_214 | 0x40;
LAB_00405aec:
                ppiVar12 = param_4;
                local_22c = 10;
LAB_00405af6:
                if (((local_214 & 0x8000) == 0) && ((local_214 & 0x1000) == 0)) {
                  local_220 = ppiVar12 + 1;
                  if ((local_214 & 0x20) == 0) {
                    piVar3 = *ppiVar12;
                    if ((local_214 & 0x40) == 0) {
                      piVar7 = (int *)0x0;
                    }
                    else {
                      piVar7 = (int *)((int)piVar3 >> 0x1f);
                    }
                  }
                  else {
                    if ((local_214 & 0x40) == 0) {
                      piVar3 = (int *)(uint)*(ushort *)ppiVar12;
                    }
                    else {
                      piVar3 = (int *)(int)*(short *)ppiVar12;
                    }
                    piVar7 = (int *)((int)piVar3 >> 0x1f);
                  }
                }
                else {
                  piVar3 = *ppiVar12;
                  piVar7 = ppiVar12[1];
                  local_220 = ppiVar12 + 2;
                }
                if ((((local_214 & 0x40) != 0) && ((int)piVar7 < 1)) && ((int)piVar7 < 0)) {
                  bVar13 = piVar3 != (int *)0x0;
                  piVar3 = (int *)-(int)piVar3;
                  piVar7 = (int *)-(int)((int)piVar7 + (uint)bVar13);
                  local_214 = local_214 | 0x100;
                }
                uVar14 = CONCAT44(piVar7,piVar3);
                if ((local_214 & 0x9000) == 0) {
                  piVar7 = (int *)0x0;
                }
                if ((int)local_21c < 0) {
                  local_21c = (int *)0x1;
                }
                else {
                  local_214 = local_214 & 0xfffffff7;
                  if (0x200 < (int)local_21c) {
                    local_21c = (int *)0x200;
                  }
                }
                if (((uint)piVar3 | (uint)piVar7) == 0) {
                  local_238 = 0;
                }
                piVar3 = &local_11;
                while( true ) {
                  pcVar8 = (char *)uVar14;
                  piVar15 = (int *)((int)local_21c + -1);
                  if (((int)local_21c < 1) && (((uint)pcVar8 | (uint)piVar7) == 0)) break;
                  local_21c = piVar15;
                  uVar14 = __aulldvrm((uint)pcVar8,(uint)piVar7,local_22c,(int)local_22c >> 0x1f);
                  piVar7 = (int *)((ulonglong)uVar14 >> 0x20);
                  iVar5 = extraout_ECX + 0x30;
                  if (0x39 < iVar5) {
                    iVar5 = iVar5 + local_250;
                  }
                  *(char *)piVar3 = (char)iVar5;
                  piVar3 = (int *)((int)piVar3 + -1);
                  local_264 = pcVar8;
                }
                local_22c = (int)&local_11 + -(int)piVar3;
                local_224 = (int *)((int)piVar3 + 1);
                local_21c = piVar15;
                if (((local_214 & 0x200) != 0) && ((local_22c == 0 || (*(char *)local_224 != '0'))))
                {
                  *(char *)piVar3 = '0';
                  local_22c = (int)&local_11 + -(int)piVar3 + 1;
                  local_224 = piVar3;
                }
              }
              else if ((char)local_215 < 'T') {
                if (local_215 == 0x53) {
                  if ((local_214 & 0x830) == 0) {
                    local_214 = local_214 | 0x800;
                  }
                  goto LAB_004058fa;
                }
                if (local_215 == 0x41) {
LAB_004058ad:
                  local_215 = local_215 + 0x20;
                  local_27c = 1;
LAB_00405b1b:
                  local_214 = local_214 | 0x40;
                  local_264 = (char *)0x200;
                  piVar7 = local_210;
                  pcVar8 = local_264;
                  piVar3 = local_210;
                  if ((int)local_21c < 0) {
                    local_21c = (int *)0x6;
                  }
                  else if (local_21c == (int *)0x0) {
                    if (local_215 == 0x67) {
                      local_21c = (int *)0x1;
                    }
                  }
                  else {
                    if (0x200 < (int)local_21c) {
                      local_21c = (int *)0x200;
                    }
                    if (0xa3 < (int)local_21c) {
                      pcVar8 = (char *)((int)local_21c + 0x15d);
                      local_224 = local_210;
                      local_24c = (int *)__malloc_crt((size_t)pcVar8);
                      piVar7 = local_24c;
                      piVar3 = local_24c;
                      if (local_24c == (int *)0x0) {
                        local_21c = (int *)0xa3;
                        piVar7 = local_210;
                        pcVar8 = local_264;
                        piVar3 = local_224;
                      }
                    }
                  }
                  local_224 = piVar3;
                  local_264 = pcVar8;
                  local_284 = *param_4;
                  local_220 = param_4 + 2;
                  local_280 = param_4[1];
                  plVar17 = &local_260;
                  iVar5 = (int)(char)local_215;
                  ppiVar12 = &local_284;
                  piVar3 = piVar7;
                  pcVar8 = local_264;
                  piVar15 = local_21c;
                  uVar16 = local_27c;
                  pcVar6 = (code *)DecodePointer(Ptr_0043d5c0);
                  (*pcVar6)(ppiVar12,piVar3,pcVar8,iVar5,piVar15,uVar16,plVar17);
                  uVar4 = local_214 & 0x80;
                  if ((uVar4 != 0) && (local_21c == (int *)0x0)) {
                    plVar17 = &local_260;
                    piVar3 = piVar7;
                    pcVar6 = (code *)DecodePointer(Ptr_0043d5cc);
                    (*pcVar6)(piVar3,plVar17);
                  }
                  if ((local_215 == 0x67) && (uVar4 == 0)) {
                    plVar17 = &local_260;
                    piVar3 = piVar7;
                    pcVar6 = (code *)DecodePointer(Ptr_0043d5c8);
                    (*pcVar6)(piVar3,plVar17);
                  }
                  if (*(char *)piVar7 == '-') {
                    local_214 = local_214 | 0x100;
                    local_224 = (int *)((int)piVar7 + 1);
                    piVar7 = local_224;
                  }
LAB_00405a32:
                  local_22c = _strlen((char *)piVar7);
                }
                else if (local_215 == 0x43) {
                  ppiVar12 = param_4;
                  if ((local_214 & 0x830) == 0) {
                    local_214 = local_214 | 0x800;
                  }
LAB_00405973:
                  local_220 = ppiVar12 + 1;
                  if ((local_214 & 0x810) == 0) {
                    local_210[0]._0_1_ = *(char *)ppiVar12;
                    local_22c = 1;
                  }
                  else {
                    eVar9 = _wctomb_s((int *)&local_22c,(char *)local_210,0x200,*(wchar_t *)ppiVar12
                                     );
                    if (eVar9 != 0) {
                      local_248 = 1;
                    }
                  }
                  local_224 = local_210;
                }
                else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_004058ad;
              }
              else {
                if (local_215 == 0x58) goto LAB_00405c7b;
                if (local_215 == 0x5a) {
                  piVar3 = *param_4;
                  local_220 = param_4 + 1;
                  piVar7 = (int *)PTR_s__null__0043d2c4;
                  local_224 = (int *)PTR_s__null__0043d2c4;
                  if ((piVar3 == (int *)0x0) || (piVar15 = (int *)piVar3[1], piVar15 == (int *)0x0))
                  goto LAB_00405a32;
                  local_22c = (size_t)*(wchar_t *)piVar3;
                  local_224 = piVar15;
                  if ((local_214 & 0x800) == 0) {
                    local_240 = 0;
                  }
                  else {
                    local_22c = (int)local_22c / 2;
                    local_240 = 1;
                  }
                }
                else {
                  if (local_215 == 0x61) goto LAB_00405b1b;
                  if (local_215 == 99) goto LAB_00405973;
                }
              }
LAB_00405e58:
              if (local_248 == 0) {
                if ((local_214 & 0x40) != 0) {
                  if ((local_214 & 0x100) == 0) {
                    if ((local_214 & 1) == 0) {
                      if ((local_214 & 2) == 0) goto LAB_00405ea5;
                      local_230 = 0x20;
                    }
                    else {
                      local_230 = 0x2b;
                    }
                  }
                  else {
                    local_230 = 0x2d;
                  }
                  local_238 = 1;
                }
LAB_00405ea5:
                pcVar8 = (char *)((int)local_23c + (-local_238 - local_22c));
                local_264 = pcVar8;
                if ((local_214 & 0xc) == 0) {
                  do {
                    if ((int)pcVar8 < 1) break;
                    pcVar8 = pcVar8 + -1;
                    _write_char(local_234);
                  } while (local_228 != -1);
                }
                pFVar2 = local_234;
                FUN_0040543d(&local_230,local_238);
                if (((local_214 & 8) != 0) && (pcVar8 = local_264, (local_214 & 4) == 0)) {
                  do {
                    if ((int)pcVar8 < 1) break;
                    _write_char(pFVar2);
                    pcVar8 = pcVar8 + -1;
                  } while (local_228 != -1);
                }
                if ((local_240 == 0) || ((int)local_22c < 1)) {
                  FUN_0040543d(local_224,local_22c);
                }
                else {
                  local_26c = local_22c;
                  piVar3 = local_224;
                  do {
                    _WCh = *(wchar_t *)piVar3;
                    local_26c = local_26c - 1;
                    piVar3 = (int *)((int)piVar3 + 2);
                    eVar9 = _wctomb_s(&local_274,(char *)((int)&local_11 + 1),6,_WCh);
                    if ((eVar9 != 0) || (local_274 == 0)) {
                      local_228 = -1;
                      break;
                    }
                    FUN_0040543d((int)&local_11 + 1,local_274);
                  } while (local_26c != 0);
                }
                if ((-1 < local_228) && (pcVar8 = local_264, (local_214 & 4) != 0)) {
                  do {
                    if ((int)pcVar8 < 1) break;
                    _write_char(local_234);
                    pcVar8 = pcVar8 + -1;
                  } while (local_228 != -1);
                }
              }
            }
            else {
              if ('p' < (char)local_215) {
                if (local_215 == 0x73) {
LAB_004058fa:
                  piVar3 = local_21c;
                  if (local_21c == (int *)0xffffffff) {
                    piVar3 = (int *)0x7fffffff;
                  }
                  local_220 = param_4 + 1;
                  local_224 = *param_4;
                  if ((local_214 & 0x810) == 0) {
                    piVar7 = local_224;
                    if (local_224 == (int *)0x0) {
                      piVar7 = (int *)PTR_s__null__0043d2c4;
                      local_224 = (int *)PTR_s__null__0043d2c4;
                    }
                    for (; (piVar3 != (int *)0x0 &&
                           (piVar3 = (int *)((int)piVar3 + -1), *(char *)piVar7 != '\0'));
                        piVar7 = (int *)((int)piVar7 + 1)) {
                    }
                    local_22c = (int)piVar7 - (int)local_224;
                  }
                  else {
                    if (local_224 == (int *)0x0) {
                      local_224 = (int *)PTR_u__null__0043d2c8;
                    }
                    local_240 = 1;
                    for (piVar7 = local_224;
                        (piVar3 != (int *)0x0 &&
                        (piVar3 = (int *)((int)piVar3 + -1), *(wchar_t *)piVar7 != L'\0'));
                        piVar7 = (int *)((int)piVar7 + 2)) {
                    }
                    local_22c = (int)piVar7 - (int)local_224 >> 1;
                  }
                  goto LAB_00405e58;
                }
                if (local_215 == 0x75) goto LAB_00405aec;
                if (local_215 != 0x78) goto LAB_00405e58;
                local_250 = 0x27;
LAB_00405cad:
                local_22c = 0x10;
                if ((local_214 & 0x80) != 0) {
                  local_22f = (char)local_250 + 'Q';
                  local_230 = 0x30;
                  local_238 = 2;
                }
                goto LAB_00405af6;
              }
              if (local_215 == 0x70) {
                local_21c = (int *)0x8;
LAB_00405c7b:
                local_250 = 7;
                ppiVar12 = param_4;
                goto LAB_00405cad;
              }
              if ((char)local_215 < 'e') goto LAB_00405e58;
              param_4 = ppiVar12;
              if ((char)local_215 < 'h') goto LAB_00405b1b;
              if (local_215 == 0x69) goto LAB_00405ae5;
              if (local_215 != 0x6e) {
                if (local_215 != 0x6f) goto LAB_00405e58;
                local_22c = 8;
                if ((local_214 & 0x80) != 0) {
                  local_214 = local_214 | 0x200;
                }
                goto LAB_00405af6;
              }
              local_220 = ppiVar12 + 1;
              piVar3 = *ppiVar12;
              bVar13 = FUN_004041b0();
              if (CONCAT31(extraout_var,bVar13) == 0) goto LAB_00405515;
              if ((local_214 & 0x20) == 0) {
                *piVar3 = local_228;
              }
              else {
                *(wchar_t *)piVar3 = (wchar_t)local_228;
              }
              local_248 = 1;
            }
            if (local_24c != (int *)0x0) {
              _free(local_24c);
              local_24c = (int *)0x0;
            }
          }
          local_215 = *local_244;
          iVar5 = local_278;
          param_2 = local_244;
          param_4 = local_220;
          ppiVar12 = local_220;
        }
        if (local_254 != '\0') {
          *(uint *)(local_258 + 0x70) = *(uint *)(local_258 + 0x70) & 0xfffffffd;
        }
        goto LAB_00406077;
      }
    }
  }
LAB_00405515:
  piVar3 = __errno();
  *piVar3 = 0x16;
  FUN_00406231();
  if (local_254 != '\0') {
    *(uint *)(local_258 + 0x70) = *(uint *)(local_258 + 0x70) & 0xfffffffd;
  }
LAB_00406077:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004060a7(PVOID param_1)

{
  Ptr_0047f57c = param_1;
  return;
}



// Library Function - Single Match
//  __call_reportfault
// 
// Library: Visual Studio 2010 Release

void __cdecl __call_reportfault(int nDbgHookCode,DWORD dwExceptionCode,DWORD dwExceptionFlags)

{
  uint uVar1;
  BOOL BVar2;
  LONG LVar3;
  _EXCEPTION_POINTERS local_32c;
  EXCEPTION_RECORD local_324;
  undefined4 local_2d4;
  
  uVar1 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  if (nDbgHookCode != -1) {
    FUN_004091de();
  }
  local_324.ExceptionCode = 0;
  _memset(&local_324.ExceptionFlags,0,0x4c);
  local_32c.ExceptionRecord = &local_324;
  local_32c.ContextRecord = (PCONTEXT)&local_2d4;
  local_2d4 = 0x10001;
  local_324.ExceptionCode = dwExceptionCode;
  local_324.ExceptionFlags = dwExceptionFlags;
  BVar2 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter(&local_32c);
  if (((LVar3 == 0) && (BVar2 == 0)) && (nDbgHookCode != -1)) {
    FUN_004091de();
  }
  ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2010 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  HANDLE hProcess;
  UINT uExitCode;
  
  __call_reportfault(2,0xc0000417,1);
  uExitCode = 0xc0000417;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// Library Function - Single Match
//  __invalid_parameter
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void __invalid_parameter(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,
                        uintptr_t param_5)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)DecodePointer(Ptr_0047f57c);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040621a. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
                    // WARNING: Subroutine does not return
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
}



void FUN_00406231(void)

{
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return;
}



// Library Function - Single Match
//  __get_errno_from_oserr
// 
// Library: Visual Studio 2010 Release

int __cdecl __get_errno_from_oserr(ulong param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_0043d2d0)[uVar1 * 2]) {
      return (&DAT_0043d2d4)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbc) & 0xe) + 8;
}



// Library Function - Single Match
//  __errno
// 
// Library: Visual Studio 2010 Release

int * __cdecl __errno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (int *)&DAT_0043d438;
  }
  return &p_Var1->_terrno;
}



// Library Function - Single Match
//  ___doserrno
// 
// Library: Visual Studio 2010 Release

ulong * __cdecl ___doserrno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (ulong *)&DAT_0043d43c;
  }
  return &p_Var1->_tdoserrno;
}



// Library Function - Single Match
//  __dosmaperr
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __dosmaperr(ulong param_1)

{
  ulong *puVar1;
  int iVar2;
  int *piVar3;
  
  puVar1 = ___doserrno();
  *puVar1 = param_1;
  iVar2 = __get_errno_from_oserr(param_1);
  piVar3 = __errno();
  *piVar3 = iVar2;
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_2
// Library Function - Single Match
//  __SEH_prolog4
// 
// Library: Visual Studio

void __cdecl __SEH_prolog4(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_0043d030 ^ (uint)&param_2;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __SEH_epilog4
// 
// Library: Visual Studio

void __SEH_epilog4(void)

{
  undefined4 *unaff_EBP;
  undefined4 unaff_retaddr;
  
  ExceptionList = (void *)unaff_EBP[-4];
  *unaff_EBP = unaff_retaddr;
  return;
}



// Library Function - Single Match
//  __except_handler4
// 
// Library: Visual Studio 2010 Release

undefined4 __cdecl __except_handler4(PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  BOOL BVar3;
  PVOID pvVar4;
  int *piVar5;
  PEXCEPTION_RECORD local_1c;
  undefined4 local_18;
  PVOID *local_14;
  undefined4 local_10;
  PVOID local_c;
  char local_5;
  
  piVar5 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_0043d030);
  local_5 = '\0';
  local_10 = 1;
  iVar1 = (int)param_2 + 0x10;
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  pvVar4 = param_2;
  if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0) {
    *(PEXCEPTION_RECORD **)((int)param_2 + -4) = &local_1c;
    pvVar4 = *(PVOID *)((int)param_2 + 0xc);
    local_1c = param_1;
    local_18 = param_3;
    if (pvVar4 == (PVOID)0xfffffffe) {
      return local_10;
    }
    do {
      local_14 = (PVOID *)(piVar5 + (int)pvVar4 * 3 + 4);
      local_c = *local_14;
      if ((undefined *)piVar5[(int)pvVar4 * 3 + 5] != (undefined *)0x0) {
        iVar2 = __EH4_CallFilterFunc_8((undefined *)piVar5[(int)pvVar4 * 3 + 5]);
        local_5 = '\x01';
        if (iVar2 < 0) {
          local_10 = 0;
          goto LAB_004063d8;
        }
        if (0 < iVar2) {
          if (((param_1->ExceptionCode == 0xe06d7363) && (DAT_0047ffa0 != (code *)0x0)) &&
             (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0047ffa0), BVar3 != 0)) {
            (*DAT_0047ffa0)(param_1,1);
          }
          __EH4_GlobalUnwind2_8(param_2,param_1);
          if (*(PVOID *)((int)param_2 + 0xc) != pvVar4) {
            __EH4_LocalUnwind_16((int)param_2,(uint)pvVar4,iVar1,&DAT_0043d030);
          }
          *(PVOID *)((int)param_2 + 0xc) = local_c;
          if (*piVar5 != -2) {
            ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
          }
          ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          goto LAB_0040649f;
        }
      }
      pvVar4 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_0040649f:
    if (*(int *)((int)pvVar4 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)pvVar4,0xfffffffe,iVar1,&DAT_0043d030);
  }
LAB_004063d8:
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  return local_10;
}



// Library Function - Single Match
//  __fwrite_nolock
// 
// Library: Visual Studio 2010 Release

size_t __cdecl __fwrite_nolock(void *_DstBuf,size_t _Size,size_t _Count,FILE *_File)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint _Size_00;
  uint uVar5;
  uint uVar6;
  char *_Buf;
  uint local_c;
  char *local_8;
  
  if ((_Size != 0) && (_Count != 0)) {
    if ((_File != (FILE *)0x0) &&
       ((_DstBuf != (void *)0x0 && (_Count <= (uint)(0xffffffff / (ulonglong)_Size))))) {
      uVar6 = _Size * _Count;
      uVar5 = uVar6;
      if ((_File->_flag & 0x10cU) == 0) {
        local_c = 0x1000;
      }
      else {
        local_c = _File->_bufsiz;
      }
      do {
        while( true ) {
          if (uVar5 == 0) {
            return _Count;
          }
          uVar4 = _File->_flag & 0x108;
          if (uVar4 == 0) break;
          uVar3 = _File->_cnt;
          if (uVar3 == 0) break;
          if ((int)uVar3 < 0) {
            _File->_flag = _File->_flag | 0x20;
            goto LAB_00406601;
          }
          _Size_00 = uVar5;
          if (uVar3 <= uVar5) {
            _Size_00 = uVar3;
          }
          FID_conflict__memcpy(_File->_ptr,_DstBuf,_Size_00);
          _File->_cnt = _File->_cnt - _Size_00;
          _File->_ptr = _File->_ptr + _Size_00;
          uVar5 = uVar5 - _Size_00;
LAB_004065bd:
          local_8 = (char *)((int)_DstBuf + _Size_00);
          _DstBuf = local_8;
        }
        if (local_c <= uVar5) {
          if ((uVar4 != 0) && (iVar2 = __flush(_File), iVar2 != 0)) goto LAB_00406601;
          uVar4 = uVar5;
          if (local_c != 0) {
            uVar4 = uVar5 - uVar5 % local_c;
          }
          _Buf = (char *)_DstBuf;
          uVar3 = uVar4;
          iVar2 = __fileno(_File);
          uVar3 = __write(iVar2,_Buf,uVar3);
          if (uVar3 != 0xffffffff) {
            _Size_00 = uVar4;
            if (uVar3 <= uVar4) {
              _Size_00 = uVar3;
            }
            uVar5 = uVar5 - _Size_00;
            if (uVar4 <= uVar3) goto LAB_004065bd;
          }
          _File->_flag = _File->_flag | 0x20;
LAB_00406601:
          return (uVar6 - uVar5) / _Size;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = __flsbuf((int)*_DstBuf,_File);
        if (iVar2 == -1) goto LAB_00406601;
        _DstBuf = (void *)((int)_DstBuf + 1);
        local_c = _File->_bufsiz;
        uVar5 = uVar5 - 1;
        if ((int)local_c < 1) {
          local_c = 1;
        }
      } while( true );
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00406231();
  }
  return 0;
}



// Library Function - Single Match
//  _strlen
// 
// Library: Visual Studio

size_t __cdecl _strlen(char *_Str)

{
  char cVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  
  uVar2 = (uint)_Str & 3;
  puVar3 = (uint *)_Str;
  while (uVar2 != 0) {
    cVar1 = *(char *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (cVar1 == '\0') goto LAB_00406683;
    uVar2 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar4 = puVar3;
      puVar3 = puVar4 + 1;
    } while (((*puVar4 ^ 0xffffffff ^ *puVar4 + 0x7efefeff) & 0x81010100) == 0);
    uVar2 = *puVar4;
    if ((char)uVar2 == '\0') {
      return (int)puVar4 - (int)_Str;
    }
    if ((char)(uVar2 >> 8) == '\0') {
      return (size_t)((int)puVar4 + (1 - (int)_Str));
    }
    if ((uVar2 & 0xff0000) == 0) {
      return (size_t)((int)puVar4 + (2 - (int)_Str));
    }
  } while ((uVar2 & 0xff000000) != 0);
LAB_00406683:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
}



// Library Function - Single Match
//  __ioinit
// 
// Library: Visual Studio 2010 Release

int __cdecl __ioinit(void)

{
  void *pvVar1;
  int iVar2;
  DWORD DVar3;
  BOOL BVar4;
  HANDLE pvVar5;
  UINT UVar6;
  UINT UVar7;
  HANDLE *ppvVar8;
  void **ppvVar9;
  uint uVar10;
  _STARTUPINFOW local_50;
  HANDLE *local_c;
  UINT *local_8;
  
  GetStartupInfoW(&local_50);
  pvVar1 = __calloc_crt(0x20,0x40);
  if (pvVar1 == (void *)0x0) {
    iVar2 = -1;
  }
  else {
    uNumber_0047fe88 = 0x20;
    DAT_0047fea0 = pvVar1;
    if (pvVar1 < (void *)((int)pvVar1 + 0x800U)) {
      iVar2 = (int)pvVar1 + 5;
      do {
        *(undefined4 *)(iVar2 + -5) = 0xffffffff;
        *(undefined2 *)(iVar2 + -1) = 0xa00;
        *(undefined4 *)(iVar2 + 3) = 0;
        *(undefined2 *)(iVar2 + 0x1f) = 0xa00;
        *(undefined *)(iVar2 + 0x21) = 10;
        *(undefined4 *)(iVar2 + 0x33) = 0;
        *(undefined *)(iVar2 + 0x2f) = 0;
        uVar10 = iVar2 + 0x3b;
        iVar2 = iVar2 + 0x40;
      } while (uVar10 < (int)DAT_0047fea0 + 0x800U);
    }
    if ((local_50.cbReserved2 != 0) && ((UINT *)local_50.lpReserved2 != (UINT *)0x0)) {
      UVar6 = *(UINT *)local_50.lpReserved2;
      local_8 = (UINT *)((int)local_50.lpReserved2 + 4);
      local_c = (HANDLE *)((int)local_8 + UVar6);
      if (0x7ff < (int)UVar6) {
        UVar6 = 0x800;
      }
      UVar7 = UVar6;
      if ((int)uNumber_0047fe88 < (int)UVar6) {
        ppvVar9 = (void **)&DAT_0047fea4;
        do {
          pvVar1 = __calloc_crt(0x20,0x40);
          UVar7 = uNumber_0047fe88;
          if (pvVar1 == (void *)0x0) break;
          uNumber_0047fe88 = uNumber_0047fe88 + 0x20;
          *ppvVar9 = pvVar1;
          if (pvVar1 < (void *)((int)pvVar1 + 0x800U)) {
            iVar2 = (int)pvVar1 + 5;
            do {
              *(undefined4 *)(iVar2 + -5) = 0xffffffff;
              *(undefined4 *)(iVar2 + 3) = 0;
              *(byte *)(iVar2 + 0x1f) = *(byte *)(iVar2 + 0x1f) & 0x80;
              *(undefined4 *)(iVar2 + 0x33) = 0;
              *(undefined2 *)(iVar2 + -1) = 0xa00;
              *(undefined2 *)(iVar2 + 0x20) = 0xa0a;
              *(undefined *)(iVar2 + 0x2f) = 0;
              uVar10 = iVar2 + 0x3b;
              iVar2 = iVar2 + 0x40;
            } while (uVar10 < (int)*ppvVar9 + 0x800U);
          }
          ppvVar9 = ppvVar9 + 1;
          UVar7 = UVar6;
        } while ((int)uNumber_0047fe88 < (int)UVar6);
      }
      uVar10 = 0;
      if (0 < (int)UVar7) {
        do {
          pvVar5 = *local_c;
          if ((((pvVar5 != (HANDLE)0xffffffff) && (pvVar5 != (HANDLE)0xfffffffe)) &&
              ((*(byte *)local_8 & 1) != 0)) &&
             (((*(byte *)local_8 & 8) != 0 || (DVar3 = GetFileType(pvVar5), DVar3 != 0)))) {
            ppvVar8 = (HANDLE *)((uVar10 & 0x1f) * 0x40 + (int)(&DAT_0047fea0)[(int)uVar10 >> 5]);
            *ppvVar8 = *local_c;
            *(byte *)(ppvVar8 + 1) = *(byte *)local_8;
            BVar4 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
            if (BVar4 == 0) {
              return -1;
            }
            ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
          }
          local_c = local_c + 1;
          uVar10 = uVar10 + 1;
          local_8 = (UINT *)((int)local_8 + 1);
        } while ((int)uVar10 < (int)UVar7);
      }
    }
    iVar2 = 0;
    do {
      ppvVar8 = (HANDLE *)(iVar2 * 0x40 + (int)DAT_0047fea0);
      if ((*ppvVar8 == (HANDLE)0xffffffff) || (*ppvVar8 == (HANDLE)0xfffffffe)) {
        *(undefined *)(ppvVar8 + 1) = 0x81;
        if (iVar2 == 0) {
          DVar3 = 0xfffffff6;
        }
        else {
          DVar3 = 0xfffffff5 - (iVar2 != 1);
        }
        pvVar5 = GetStdHandle(DVar3);
        if (((pvVar5 == (HANDLE)0xffffffff) || (pvVar5 == (HANDLE)0x0)) ||
           (DVar3 = GetFileType(pvVar5), DVar3 == 0)) {
          *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x40;
          *ppvVar8 = (HANDLE)0xfffffffe;
        }
        else {
          *ppvVar8 = pvVar5;
          if ((DVar3 & 0xff) == 2) {
            *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x40;
          }
          else if ((DVar3 & 0xff) == 3) {
            *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 8;
          }
          BVar4 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
          if (BVar4 == 0) {
            return -1;
          }
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < 3);
    SetHandleCount(uNumber_0047fe88);
    iVar2 = 0;
  }
  return iVar2;
}



// Library Function - Single Match
//  __fileno
// 
// Library: Visual Studio 2010 Release

int __cdecl __fileno(FILE *_File)

{
  int *piVar1;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00406231();
    return -1;
  }
  return _File->_file;
}



// Library Function - Single Match
//  __malloc_crt
// 
// Library: Visual Studio 2010 Release

void * __cdecl __malloc_crt(size_t _Size)

{
  void *pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pvVar1 = _malloc(_Size);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (DAT_0047f580 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0047f580 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __calloc_crt
// 
// Library: Visual Studio 2010 Release

void * __cdecl __calloc_crt(size_t _Count,size_t _Size)

{
  LPVOID pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pvVar1 = __calloc_impl(_Count,_Size,(undefined4 *)0x0);
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
    if (DAT_0047f580 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0047f580 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __realloc_crt
// 
// Library: Visual Studio 2010 Release

void * __cdecl __realloc_crt(void *_Ptr,size_t _NewSize)

{
  void *pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  do {
    pvVar1 = _realloc(_Ptr,_NewSize);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (_NewSize == 0) {
      return (void *)0x0;
    }
    if (DAT_0047f580 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0047f580 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



void FUN_00406a88(void)

{
  FUN_00406cc5(1);
  return;
}



// Library Function - Single Match
//  __flush
// 
// Library: Visual Studio 2010 Release

int __cdecl __flush(FILE *_File)

{
  int _FileHandle;
  uint uVar1;
  int iVar2;
  uint uVar3;
  char *_Buf;
  
  iVar2 = 0;
  if ((((byte)_File->_flag & 3) == 2) && ((_File->_flag & 0x108U) != 0)) {
    _Buf = _File->_base;
    uVar3 = (int)_File->_ptr - (int)_Buf;
    if (0 < (int)uVar3) {
      uVar1 = uVar3;
      _FileHandle = __fileno(_File);
      uVar1 = __write(_FileHandle,_Buf,uVar1);
      if (uVar1 == uVar3) {
        if ((char)_File->_flag < '\0') {
          _File->_flag = _File->_flag & 0xfffffffd;
        }
      }
      else {
        _File->_flag = _File->_flag | 0x20;
        iVar2 = -1;
      }
    }
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return iVar2;
}



// Library Function - Single Match
//  __fflush_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __fflush_nolock(FILE *_File)

{
  int iVar1;
  
  if (_File == (FILE *)0x0) {
    iVar1 = _flsall(0);
  }
  else {
    iVar1 = __flush(_File);
    if (iVar1 == 0) {
      if ((_File->_flag & 0x4000U) == 0) {
        iVar1 = 0;
      }
      else {
        iVar1 = __fileno(_File);
        iVar1 = __commit(iVar1);
        iVar1 = -(uint)(iVar1 != 0);
      }
    }
    else {
      iVar1 = -1;
    }
  }
  return iVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _flsall
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _flsall(int param_1)

{
  void **ppvVar1;
  void *_File;
  FILE *_File_00;
  int iVar2;
  int _Index;
  int local_28;
  int local_20;
  
  local_20 = 0;
  local_28 = 0;
  __lock(1);
  for (_Index = 0; _Index < DAT_00480fe0; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_0047ffc8 + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_0047ffc8 + _Index * 4);
      if ((_File_00->_flag & 0x83U) != 0) {
        if (param_1 == 1) {
          iVar2 = __fflush_nolock(_File_00);
          if (iVar2 != -1) {
            local_20 = local_20 + 1;
          }
        }
        else if ((param_1 == 0) && ((_File_00->_flag & 2U) != 0)) {
          iVar2 = __fflush_nolock(_File_00);
          if (iVar2 == -1) {
            local_28 = -1;
          }
        }
      }
      FUN_00406be3();
    }
  }
  FUN_00406c12();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_00406be3(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_0047ffc8 + unaff_ESI * 4));
  return;
}



void FUN_00406c12(void)

{
  FUN_00406cc5(1);
  return;
}



// Library Function - Single Match
//  __mtinitlocks
// 
// Library: Visual Studio 2010 Release

int __cdecl __mtinitlocks(void)

{
  BOOL BVar1;
  int iVar2;
  LPCRITICAL_SECTION p_Var3;
  
  iVar2 = 0;
  p_Var3 = (LPCRITICAL_SECTION)&DAT_0047f588;
  do {
    if ((&DAT_0043d484)[iVar2 * 2] == 1) {
      (&lpCriticalSection_0043d480)[iVar2 * 2] = p_Var3;
      p_Var3 = p_Var3 + 1;
      BVar1 = InitializeCriticalSectionAndSpinCount((&lpCriticalSection_0043d480)[iVar2 * 2],4000);
      if (BVar1 == 0) {
        (&lpCriticalSection_0043d480)[iVar2 * 2] = (LPCRITICAL_SECTION)0x0;
        return 0;
      }
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x24);
  return 1;
}



// Library Function - Single Match
//  __mtdeletelocks
// 
// Library: Visual Studio 2010 Release

void __cdecl __mtdeletelocks(void)

{
  LPCRITICAL_SECTION lpCriticalSection;
  LPCRITICAL_SECTION *pp_Var1;
  
  pp_Var1 = &lpCriticalSection_0043d480;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x43d5a0);
  pp_Var1 = &lpCriticalSection_0043d480;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x43d5a0);
  return;
}



void __cdecl FUN_00406cc5(int param_1)

{
  LeaveCriticalSection((&lpCriticalSection_0043d480)[param_1 * 2]);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __mtinitlocknum
// 
// Library: Visual Studio 2010 Release

int __cdecl __mtinitlocknum(int _LockNum)

{
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION lpCriticalSection;
  int *piVar2;
  BOOL BVar3;
  int iVar4;
  int local_20;
  
  iVar4 = 1;
  local_20 = 1;
  if (hHeap_0047fd38 == (HANDLE)0x0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  pp_Var1 = &lpCriticalSection_0043d480 + _LockNum * 2;
  if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
    lpCriticalSection = (LPCRITICAL_SECTION)__malloc_crt(0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      piVar2 = __errno();
      *piVar2 = 0xc;
      iVar4 = 0;
    }
    else {
      __lock(10);
      if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
        BVar3 = InitializeCriticalSectionAndSpinCount(lpCriticalSection,4000);
        if (BVar3 == 0) {
          _free(lpCriticalSection);
          piVar2 = __errno();
          *piVar2 = 0xc;
          local_20 = 0;
        }
        else {
          *pp_Var1 = lpCriticalSection;
        }
      }
      else {
        _free(lpCriticalSection);
      }
      FUN_00406d95();
      iVar4 = local_20;
    }
  }
  return iVar4;
}



void FUN_00406d95(void)

{
  FUN_00406cc5(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((&lpCriticalSection_0043d480)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((&lpCriticalSection_0043d480)[_File * 2]);
  return;
}



// Library Function - Single Match
//  __flsbuf
// 
// Library: Visual Studio 2010 Release

int __cdecl __flsbuf(int _Ch,FILE *_File)

{
  char *_Buf;
  char *pcVar1;
  FILE *_File_00;
  int *piVar2;
  undefined **ppuVar3;
  int iVar4;
  undefined *puVar5;
  int unaff_EDI;
  uint uVar6;
  longlong lVar7;
  uint local_8;
  
  _File_00 = _File;
  _File = (FILE *)__fileno(_File);
  uVar6 = _File_00->_flag;
  if ((uVar6 & 0x82) == 0) {
    piVar2 = __errno();
    *piVar2 = 9;
LAB_00406df7:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar6 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_00406df7;
  }
  if ((uVar6 & 1) != 0) {
    _File_00->_cnt = 0;
    if ((uVar6 & 0x10) == 0) {
      _File_00->_flag = uVar6 | 0x20;
      return -1;
    }
    _File_00->_ptr = _File_00->_base;
    _File_00->_flag = uVar6 & 0xfffffffe;
  }
  uVar6 = _File_00->_flag;
  _File_00->_flag = uVar6 & 0xffffffef | 2;
  _File_00->_cnt = 0;
  local_8 = 0;
  if (((uVar6 & 0x10c) == 0) &&
     (((ppuVar3 = FUN_004042cc(), _File_00 != (FILE *)(ppuVar3 + 8) &&
       (ppuVar3 = FUN_004042cc(), _File_00 != (FILE *)(ppuVar3 + 0x10))) ||
      (iVar4 = __isatty((int)_File), iVar4 == 0)))) {
    __getbuf(_File_00);
  }
  if ((_File_00->_flag & 0x108U) == 0) {
    uVar6 = 1;
    local_8 = __write((int)_File,&_Ch,1);
  }
  else {
    _Buf = _File_00->_base;
    pcVar1 = _File_00->_ptr;
    _File_00->_ptr = _Buf + 1;
    uVar6 = (int)pcVar1 - (int)_Buf;
    _File_00->_cnt = _File_00->_bufsiz + -1;
    if ((int)uVar6 < 1) {
      if ((_File == (FILE *)0xffffffff) || (_File == (FILE *)0xfffffffe)) {
        puVar5 = &DAT_0043d440;
      }
      else {
        puVar5 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_0047fea0)[(int)_File >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64((int)_File,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_00406f1f;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar6);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar6) {
    return _Ch & 0xff;
  }
LAB_00406f1f:
  _File_00->_flag = _File_00->_flag | 0x20;
  return -1;
}



// Library Function - Single Match
//  __filbuf
// 
// Library: Visual Studio 2010 Release

int __cdecl __filbuf(FILE *_File)

{
  byte bVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  char *_DstBuf;
  
  if (_File == (FILE *)0x0) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_00406231();
  }
  else {
    uVar4 = _File->_flag;
    if (((uVar4 & 0x83) != 0) && ((uVar4 & 0x40) == 0)) {
      if ((uVar4 & 2) == 0) {
        _File->_flag = uVar4 | 1;
        if ((uVar4 & 0x10c) == 0) {
          __getbuf(_File);
        }
        else {
          _File->_ptr = _File->_base;
        }
        uVar4 = _File->_bufsiz;
        _DstBuf = _File->_base;
        iVar3 = __fileno(_File);
        iVar3 = __read(iVar3,_DstBuf,uVar4);
        _File->_cnt = iVar3;
        if ((iVar3 != 0) && (iVar3 != -1)) {
          if ((*(byte *)&_File->_flag & 0x82) == 0) {
            iVar3 = __fileno(_File);
            if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
              puVar5 = &DAT_0043d440;
            }
            else {
              iVar3 = __fileno(_File);
              uVar4 = __fileno(_File);
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0047fea0)[iVar3 >> 5]);
            }
            if ((puVar5[4] & 0x82) == 0x82) {
              _File->_flag = _File->_flag | 0x2000;
            }
          }
          if (((_File->_bufsiz == 0x200) && ((_File->_flag & 8U) != 0)) &&
             ((_File->_flag & 0x400U) == 0)) {
            _File->_bufsiz = 0x1000;
          }
          _File->_cnt = _File->_cnt + -1;
          bVar1 = *_File->_ptr;
          _File->_ptr = _File->_ptr + 1;
          return (uint)bVar1;
        }
        _File->_flag = _File->_flag | (-(uint)(iVar3 != 0) & 0x10) + 0x10;
        _File->_cnt = 0;
      }
      else {
        _File->_flag = uVar4 | 0x20;
      }
    }
  }
  return -1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl terminate(void)
// 
// Library: Visual Studio 2010 Release
// Ptr parameter of EncodePointer
// 

void __cdecl terminate(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if ((code *)p_Var1->_terminate != (code *)0x0) {
    (*(code *)p_Var1->_terminate)();
  }
                    // WARNING: Subroutine does not return
  _abort();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00407090(void)

{
  _DAT_0047f6d8 = EncodePointer(terminate);
  return;
}



// Library Function - Single Match
//  __initp_misc_winsig
// 
// Library: Visual Studio 2010 Release

void __cdecl __initp_misc_winsig(PVOID param_1)

{
  DAT_0047f6dc = param_1;
  DAT_0047f6e0 = param_1;
  Ptr_0047f6e4 = param_1;
  DAT_0047f6e8 = param_1;
  return;
}



// Library Function - Single Match
//  _siglookup
// 
// Library: Visual Studio 2010 Release

uint __fastcall _siglookup(undefined4 param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_3;
  do {
    if (*(int *)(uVar1 + 4) == param_2) break;
    uVar1 = uVar1 + 0xc;
  } while (uVar1 < param_3 + 0x90);
  if ((param_3 + 0x90 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}



void FUN_004070f6(void)

{
  DecodePointer(Ptr_0047f6e4);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _raise
// 
// Library: Visual Studio 2010 Release

int __cdecl _raise(int _SigNum)

{
  uint uVar1;
  int *piVar2;
  PVOID Ptr;
  code *pcVar3;
  int _File;
  code *pcVar4;
  undefined4 extraout_ECX;
  PVOID *ppvVar5;
  _ptiddata p_Var6;
  int local_34;
  void *local_30;
  int local_28;
  int local_20;
  
  p_Var6 = (_ptiddata)0x0;
  local_20 = 0;
  if (_SigNum < 0xc) {
    if (_SigNum != 0xb) {
      if (_SigNum == 2) {
        ppvVar5 = &DAT_0047f6dc;
        Ptr = DAT_0047f6dc;
        goto LAB_004071ad;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_0040718b;
        if (_SigNum != 8) goto LAB_00407179;
      }
    }
    p_Var6 = __getptd_noexit();
    if (p_Var6 == (_ptiddata)0x0) {
      return -1;
    }
    uVar1 = _siglookup(extraout_ECX,_SigNum,(uint)p_Var6->_pxcptacttab);
    ppvVar5 = (PVOID *)(uVar1 + 8);
    pcVar3 = (code *)*ppvVar5;
  }
  else {
    if (_SigNum == 0xf) {
      ppvVar5 = &DAT_0047f6e8;
      Ptr = DAT_0047f6e8;
    }
    else if (_SigNum == 0x15) {
      ppvVar5 = &DAT_0047f6e0;
      Ptr = DAT_0047f6e0;
    }
    else {
      if (_SigNum != 0x16) {
LAB_00407179:
        piVar2 = __errno();
        *piVar2 = 0x16;
        FUN_00406231();
        return -1;
      }
LAB_0040718b:
      ppvVar5 = &Ptr_0047f6e4;
      Ptr = Ptr_0047f6e4;
    }
LAB_004071ad:
    local_20 = 1;
    pcVar3 = (code *)DecodePointer(Ptr);
  }
  _File = 0;
  if (pcVar3 == (code *)0x1) {
    return 0;
  }
  if (pcVar3 == (code *)0x0) {
    _File = __exit(3);
  }
  if (local_20 != _File) {
    __lock(_File);
  }
  if (((_SigNum == 8) || (_SigNum == 0xb)) || (_SigNum == 4)) {
    local_30 = p_Var6->_tpxcptinfoptrs;
    p_Var6->_tpxcptinfoptrs = (void *)0x0;
    if (_SigNum == 8) {
      local_34 = p_Var6->_tfpecode;
      p_Var6->_tfpecode = 0x8c;
      goto LAB_00407211;
    }
  }
  else {
LAB_00407211:
    if (_SigNum == 8) {
      for (local_28 = 3; local_28 < 0xc; local_28 = local_28 + 1) {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var6->_pxcptacttab) = 0;
      }
      goto LAB_00407249;
    }
  }
  pcVar4 = (code *)FUN_004072fb();
  *ppvVar5 = pcVar4;
LAB_00407249:
  FUN_0040726a();
  if (_SigNum == 8) {
    (*pcVar3)(8,p_Var6->_tfpecode);
  }
  else {
    (*pcVar3)(_SigNum);
    if ((_SigNum != 0xb) && (_SigNum != 4)) {
      return 0;
    }
  }
  p_Var6->_tpxcptinfoptrs = local_30;
  if (_SigNum == 8) {
    p_Var6->_tfpecode = local_34;
  }
  return 0;
}



void FUN_0040726a(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_00406cc5(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004072a6(undefined4 param_1)

{
  _DAT_0047f6f0 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004072b5(undefined4 param_1)

{
  _DAT_0047f6f4 = param_1;
  return;
}



void __cdecl FUN_004072c4(PVOID param_1)

{
  Ptr_0047f6f8 = param_1;
  return;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 2010 Release

int __cdecl __callnewh(size_t _Size)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)DecodePointer(Ptr_0047f6f8);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
}



void FUN_004072fb(void)

{
  EncodePointer((PVOID)0x0);
  return;
}



// Library Function - Single Match
//  ___set_flsgetvalue
// 
// Library: Visual Studio 2010 Release

LPVOID ___set_flsgetvalue(void)

{
  LPVOID lpTlsValue;
  
  lpTlsValue = TlsGetValue(dwTlsIndex_0043d5a4);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = DecodePointer(lpTlsValue_0047f700);
    TlsSetValue(dwTlsIndex_0043d5a4,lpTlsValue);
  }
  return lpTlsValue;
}



// Library Function - Single Match
//  __mtterm
// 
// Library: Visual Studio 2010 Release

void __cdecl __mtterm(void)

{
  code *pcVar1;
  int iVar2;
  
  if (DAT_0043d5a0 != -1) {
    iVar2 = DAT_0043d5a0;
    pcVar1 = (code *)DecodePointer(Ptr_0047f708);
    (*pcVar1)(iVar2);
    DAT_0043d5a0 = -1;
  }
  if (dwTlsIndex_0043d5a4 != 0xffffffff) {
    TlsFree(dwTlsIndex_0043d5a4);
    dwTlsIndex_0043d5a4 = 0xffffffff;
  }
  __mtdeletelocks();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __initptd
// 
// Library: Visual Studio 2010 Release

void __cdecl __initptd(_ptiddata _Ptd,pthreadlocinfo _Locale)

{
  GetModuleHandleW(L"KERNEL32.DLL");
  _Ptd->_pxcptacttab = &DAT_00429a38;
  _Ptd->_terrno = 0;
  _Ptd->_holdrand = 1;
  _Ptd->_ownlocale = 1;
  *(undefined *)((_Ptd->_setloc_data)._cachein + 8) = 0x43;
  *(undefined *)((int)(_Ptd->_setloc_data)._cachein + 0x93) = 0x43;
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&lpAddend_0043d5d0;
  __lock(0xd);
  InterlockedIncrement(&_Ptd->ptmbcinfo->refcount);
  FUN_00407420();
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = (pthreadlocinfo)PTR_DAT_0043dd38;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_00407429();
  return;
}



void FUN_00407420(void)

{
  FUN_00406cc5(0xd);
  return;
}



void FUN_00407429(void)

{
  FUN_00406cc5(0xc);
  return;
}



// Library Function - Single Match
//  __getptd_noexit
// 
// Library: Visual Studio 2010 Release

_ptiddata __cdecl __getptd_noexit(void)

{
  DWORD dwErrCode;
  code *pcVar1;
  _ptiddata _Ptd;
  int iVar2;
  DWORD DVar3;
  undefined4 uVar4;
  _ptiddata p_Var5;
  
  dwErrCode = GetLastError();
  uVar4 = DAT_0043d5a0;
  pcVar1 = (code *)___set_flsgetvalue();
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      uVar4 = DAT_0043d5a0;
      p_Var5 = _Ptd;
      pcVar1 = (code *)DecodePointer(Ptr_0047f704);
      iVar2 = (*pcVar1)(uVar4,p_Var5);
      if (iVar2 == 0) {
        _free(_Ptd);
        _Ptd = (_ptiddata)0x0;
      }
      else {
        __initptd(_Ptd,(pthreadlocinfo)0x0);
        DVar3 = GetCurrentThreadId();
        _Ptd->_thandle = 0xffffffff;
        _Ptd->_tid = DVar3;
      }
    }
  }
  SetLastError(dwErrCode);
  return _Ptd;
}



// Library Function - Single Match
//  __getptd
// 
// Library: Visual Studio 2010 Release

_ptiddata __cdecl __getptd(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    __amsg_exit(0x10);
  }
  return p_Var1;
}



void FUN_004075df(void)

{
  FUN_00406cc5(0xd);
  return;
}



void FUN_004075eb(void)

{
  FUN_00406cc5(0xc);
  return;
}



// Library Function - Single Match
//  __mtinit
// 
// Library: Visual Studio 2010 Release

int __cdecl __mtinit(void)

{
  HMODULE hModule;
  BOOL BVar1;
  int iVar2;
  code *pcVar3;
  _ptiddata _Ptd;
  DWORD DVar4;
  undefined *puVar5;
  _ptiddata p_Var6;
  
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if (hModule == (HMODULE)0x0) {
    __mtterm();
    return 0;
  }
  Ptr_0047f6fc = GetProcAddress(hModule,"FlsAlloc");
  lpTlsValue_0047f700 = GetProcAddress(hModule,"FlsGetValue");
  Ptr_0047f704 = GetProcAddress(hModule,"FlsSetValue");
  Ptr_0047f708 = GetProcAddress(hModule,"FlsFree");
  if ((((Ptr_0047f6fc == (PVOID)0x0) || (lpTlsValue_0047f700 == (PVOID)0x0)) ||
      (Ptr_0047f704 == (PVOID)0x0)) || ((FARPROC)Ptr_0047f708 == (FARPROC)0x0)) {
    lpTlsValue_0047f700 = TlsGetValue_exref;
    Ptr_0047f6fc = &LAB_00407304;
    Ptr_0047f704 = TlsSetValue_exref;
    Ptr_0047f708 = TlsFree_exref;
  }
  dwTlsIndex_0043d5a4 = TlsAlloc();
  if ((dwTlsIndex_0043d5a4 != 0xffffffff) &&
     (BVar1 = TlsSetValue(dwTlsIndex_0043d5a4,lpTlsValue_0047f700), BVar1 != 0)) {
    __init_pointers();
    Ptr_0047f6fc = EncodePointer(Ptr_0047f6fc);
    lpTlsValue_0047f700 = EncodePointer(lpTlsValue_0047f700);
    Ptr_0047f704 = EncodePointer(Ptr_0047f704);
    Ptr_0047f708 = EncodePointer(Ptr_0047f708);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_004074c5;
      pcVar3 = (code *)DecodePointer(Ptr_0047f6fc);
      DAT_0043d5a0 = (*pcVar3)(puVar5);
      if ((DAT_0043d5a0 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_0043d5a0;
        p_Var6 = _Ptd;
        pcVar3 = (code *)DecodePointer(Ptr_0047f704);
        iVar2 = (*pcVar3)(iVar2,p_Var6);
        if (iVar2 != 0) {
          __initptd(_Ptd,(pthreadlocinfo)0x0);
          DVar4 = GetCurrentThreadId();
          _Ptd->_thandle = 0xffffffff;
          _Ptd->_tid = DVar4;
          return 1;
        }
      }
    }
    __mtterm();
  }
  return 0;
}



// Library Function - Single Match
//  __onexit_nolock
// 
// Library: Visual Studio 2010 Release

PVOID __cdecl __onexit_nolock(PVOID param_1)

{
  PVOID *_Memory;
  PVOID *ppvVar1;
  size_t sVar2;
  size_t sVar3;
  PVOID pvVar4;
  int iVar5;
  
  _Memory = (PVOID *)DecodePointer(Ptr_0047ffb8);
  ppvVar1 = (PVOID *)DecodePointer(Ptr_0047ffb4);
  if ((ppvVar1 < _Memory) || (iVar5 = (int)ppvVar1 - (int)_Memory, iVar5 + 4U < 4)) {
    return (PVOID)0x0;
  }
  sVar2 = __msize(_Memory);
  if (sVar2 < iVar5 + 4U) {
    sVar3 = 0x800;
    if (sVar2 < 0x800) {
      sVar3 = sVar2;
    }
    if ((sVar3 + sVar2 < sVar2) ||
       (pvVar4 = __realloc_crt(_Memory,sVar3 + sVar2), pvVar4 == (void *)0x0)) {
      if (sVar2 + 0x10 < sVar2) {
        return (PVOID)0x0;
      }
      pvVar4 = __realloc_crt(_Memory,sVar2 + 0x10);
      if (pvVar4 == (void *)0x0) {
        return (PVOID)0x0;
      }
    }
    ppvVar1 = (PVOID *)((int)pvVar4 + (iVar5 >> 2) * 4);
    Ptr_0047ffb8 = EncodePointer(pvVar4);
  }
  pvVar4 = EncodePointer(param_1);
  *ppvVar1 = pvVar4;
  Ptr_0047ffb4 = EncodePointer(ppvVar1 + 1);
  return param_1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 2010 Release

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;
  
  FUN_0040469a();
  p_Var1 = (_onexit_t)__onexit_nolock(_Func);
  FUN_0040788c();
  return p_Var1;
}



void FUN_0040788c(void)

{
  FUN_004046a3();
  return;
}



// Library Function - Single Match
//  _atexit
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _atexit(_func_4879 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = __onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// WARNING: Removing unreachable block (ram,0x004078bd)
// WARNING: Removing unreachable block (ram,0x004078c3)
// WARNING: Removing unreachable block (ram,0x004078c5)
// Library Function - Single Match
//  __RTC_Initialize
// 
// Library: Visual Studio 2010 Release

void __RTC_Initialize(void)

{
  return;
}



// Library Function - Single Match
//  __initp_misc_cfltcvt_tab
// 
// Library: Visual Studio 2010 Release

void __initp_misc_cfltcvt_tab(void)

{
  PVOID pvVar1;
  uint uVar2;
  
  uVar2 = 0;
  do {
    pvVar1 = EncodePointer(*(PVOID *)((int)&Ptr_0043d5a8 + uVar2));
    *(PVOID *)((int)&Ptr_0043d5a8 + uVar2) = pvVar1;
    uVar2 = uVar2 + 4;
  } while (uVar2 < 0x28);
  return;
}



// Library Function - Single Match
//  __ValidateImageBase
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

BOOL __cdecl __ValidateImageBase(PBYTE pImageBase)

{
  if ((*(short *)pImageBase == 0x5a4d) &&
     (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550)) {
    return (uint)(*(short *)((int)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x10b);
  }
  return 0;
}



// Library Function - Single Match
//  __FindPESection
// 
// Library: Visual Studio 2010 Release

PIMAGE_SECTION_HEADER __cdecl __FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  uint uVar3;
  
  iVar1 = *(int *)(pImageBase + 0x3c);
  uVar3 = 0;
  p_Var2 = (PIMAGE_SECTION_HEADER)
           (pImageBase + *(ushort *)(pImageBase + iVar1 + 0x14) + 0x18 + iVar1);
  if (*(ushort *)(pImageBase + iVar1 + 6) != 0) {
    do {
      if ((p_Var2->VirtualAddress <= rva) &&
         (rva < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) {
        return p_Var2;
      }
      uVar3 = uVar3 + 1;
      p_Var2 = p_Var2 + 1;
    } while (uVar3 < *(ushort *)(pImageBase + iVar1 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// Library Function - Single Match
//  __IsNonwritableInCurrentImage
// 
// Library: Visual Studio 2010 Release

BOOL __cdecl __IsNonwritableInCurrentImage(PBYTE pTarget)

{
  BOOL BVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  void *local_14;
  code *pcStack_10;
  uint local_c;
  undefined4 local_8;
  
  pcStack_10 = __except_handler4;
  local_14 = ExceptionList;
  local_c = DAT_0043d030 ^ 0x42a5e8;
  ExceptionList = &local_14;
  local_8 = 0;
  BVar1 = __ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_00400000);
  if (BVar1 != 0) {
    p_Var2 = __FindPESection((PBYTE)&IMAGE_DOS_HEADER_00400000,(DWORD_PTR)(pTarget + -0x400000));
    if (p_Var2 != (PIMAGE_SECTION_HEADER)0x0) {
      ExceptionList = local_14;
      return ~(p_Var2->Characteristics >> 0x1f) & 1;
    }
  }
  ExceptionList = local_14;
  return 0;
}



// Library Function - Single Match
//  __GET_RTERRMSG
// 
// Library: Visual Studio 2010 Release

wchar_t * __cdecl __GET_RTERRMSG(int param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_004294f8)[uVar1 * 2]) {
      return (wchar_t *)(&PTR_u_R6002___floating_point_support_n_004294fc)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x16);
  return (wchar_t *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __NMSG_WRITE
// 
// Library: Visual Studio 2010 Release

void __cdecl __NMSG_WRITE(int param_1)

{
  wchar_t *pwVar1;
  int iVar2;
  errno_t eVar3;
  DWORD DVar4;
  size_t sVar5;
  HANDLE hFile;
  uint uVar6;
  wchar_t **lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  wchar_t *local_200;
  char local_1fc [500];
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  pwVar1 = __GET_RTERRMSG(param_1);
  local_200 = pwVar1;
  if (pwVar1 != (wchar_t *)0x0) {
    iVar2 = __set_error_mode(3);
    if ((iVar2 == 1) || ((iVar2 = __set_error_mode(3), iVar2 == 0 && (DAT_0043d2c0 == 1)))) {
      hFile = GetStdHandle(0xfffffff4);
      if ((hFile != (HANDLE)0x0) && (hFile != (HANDLE)0xffffffff)) {
        uVar6 = 0;
        do {
          local_1fc[uVar6] = *(char *)(pwVar1 + uVar6);
          if (pwVar1[uVar6] == L'\0') break;
          uVar6 = uVar6 + 1;
        } while (uVar6 < 500);
        lpOverlapped = (LPOVERLAPPED)0x0;
        lpNumberOfBytesWritten = &local_200;
        local_1fc[499] = 0;
        sVar5 = _strlen(local_1fc);
        WriteFile(hFile,local_1fc,sVar5,(LPDWORD)lpNumberOfBytesWritten,lpOverlapped);
      }
    }
    else if (param_1 != 0xfc) {
      eVar3 = _wcscpy_s((wchar_t *)&DAT_0047f710,0x314,L"Runtime Error!\n\nProgram: ");
      if (eVar3 == 0) {
        _DAT_0047f94a = 0;
        DVar4 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_0047f742,0x104);
        if ((DVar4 != 0) ||
           (eVar3 = _wcscpy_s((wchar_t *)&DAT_0047f742,0x2fb,L"<program name unknown>"), eVar3 == 0)
           ) {
          sVar5 = _wcslen((wchar_t *)&DAT_0047f742);
          if (0x3c < sVar5 + 1) {
            sVar5 = _wcslen((wchar_t *)&DAT_0047f742);
            eVar3 = _wcsncpy_s((wchar_t *)(&DAT_0047f6cc + sVar5 * 2),
                               0x2fb - ((int)(sVar5 * 2 + -0x76) >> 1),L"...",3);
            if (eVar3 != 0) goto LAB_00407b57;
          }
          eVar3 = _wcscat_s((wchar_t *)&DAT_0047f710,0x314,L"\n\n");
          if ((eVar3 == 0) &&
             (eVar3 = _wcscat_s((wchar_t *)&DAT_0047f710,0x314,local_200), eVar3 == 0)) {
            ___crtMessageBoxW((LPCWSTR)&DAT_0047f710,L"Microsoft Visual C++ Runtime Library",0x12010
                             );
            goto LAB_00407c32;
          }
        }
      }
LAB_00407b57:
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
  }
LAB_00407c32:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __FF_MSGBANNER
// 
// Library: Visual Studio 2010 Release

void __cdecl __FF_MSGBANNER(void)

{
  int iVar1;
  
  iVar1 = __set_error_mode(3);
  if (iVar1 != 1) {
    iVar1 = __set_error_mode(3);
    if (iVar1 != 0) {
      return;
    }
    if (DAT_0043d2c0 != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
  return;
}



// Library Function - Single Match
//  __VEC_memcpy
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

undefined4 * __fastcall __VEC_memcpy(uint param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  uint uVar16;
  uint uVar17;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined4 *puVar18;
  
  puVar18 = unaff_EDI;
  if (((uint)unaff_ESI & 0xf) != 0) {
    uVar17 = 0x10 - ((uint)unaff_ESI & 0xf);
    param_1 = param_1 - uVar17;
    for (uVar16 = uVar17 & 3; uVar16 != 0; uVar16 = uVar16 - 1) {
      *(undefined *)puVar18 = *(undefined *)unaff_ESI;
      unaff_ESI = (undefined4 *)((int)unaff_ESI + 1);
      puVar18 = (undefined4 *)((int)puVar18 + 1);
    }
    for (uVar17 = uVar17 >> 2; uVar17 != 0; uVar17 = uVar17 - 1) {
      *puVar18 = *unaff_ESI;
      unaff_ESI = unaff_ESI + 1;
      puVar18 = puVar18 + 1;
    }
  }
  for (uVar16 = param_1 >> 7; uVar16 != 0; uVar16 = uVar16 - 1) {
    uVar1 = unaff_ESI[1];
    uVar2 = unaff_ESI[2];
    uVar3 = unaff_ESI[3];
    uVar4 = unaff_ESI[4];
    uVar5 = unaff_ESI[5];
    uVar6 = unaff_ESI[6];
    uVar7 = unaff_ESI[7];
    uVar8 = unaff_ESI[8];
    uVar9 = unaff_ESI[9];
    uVar10 = unaff_ESI[10];
    uVar11 = unaff_ESI[0xb];
    uVar12 = unaff_ESI[0xc];
    uVar13 = unaff_ESI[0xd];
    uVar14 = unaff_ESI[0xe];
    uVar15 = unaff_ESI[0xf];
    *puVar18 = *unaff_ESI;
    puVar18[1] = uVar1;
    puVar18[2] = uVar2;
    puVar18[3] = uVar3;
    puVar18[4] = uVar4;
    puVar18[5] = uVar5;
    puVar18[6] = uVar6;
    puVar18[7] = uVar7;
    puVar18[8] = uVar8;
    puVar18[9] = uVar9;
    puVar18[10] = uVar10;
    puVar18[0xb] = uVar11;
    puVar18[0xc] = uVar12;
    puVar18[0xd] = uVar13;
    puVar18[0xe] = uVar14;
    puVar18[0xf] = uVar15;
    uVar1 = unaff_ESI[0x11];
    uVar2 = unaff_ESI[0x12];
    uVar3 = unaff_ESI[0x13];
    uVar4 = unaff_ESI[0x14];
    uVar5 = unaff_ESI[0x15];
    uVar6 = unaff_ESI[0x16];
    uVar7 = unaff_ESI[0x17];
    uVar8 = unaff_ESI[0x18];
    uVar9 = unaff_ESI[0x19];
    uVar10 = unaff_ESI[0x1a];
    uVar11 = unaff_ESI[0x1b];
    uVar12 = unaff_ESI[0x1c];
    uVar13 = unaff_ESI[0x1d];
    uVar14 = unaff_ESI[0x1e];
    uVar15 = unaff_ESI[0x1f];
    puVar18[0x10] = unaff_ESI[0x10];
    puVar18[0x11] = uVar1;
    puVar18[0x12] = uVar2;
    puVar18[0x13] = uVar3;
    puVar18[0x14] = uVar4;
    puVar18[0x15] = uVar5;
    puVar18[0x16] = uVar6;
    puVar18[0x17] = uVar7;
    puVar18[0x18] = uVar8;
    puVar18[0x19] = uVar9;
    puVar18[0x1a] = uVar10;
    puVar18[0x1b] = uVar11;
    puVar18[0x1c] = uVar12;
    puVar18[0x1d] = uVar13;
    puVar18[0x1e] = uVar14;
    puVar18[0x1f] = uVar15;
    unaff_ESI = unaff_ESI + 0x20;
    puVar18 = puVar18 + 0x20;
  }
  if ((param_1 & 0x7f) != 0) {
    for (uVar16 = (param_1 & 0x7f) >> 4; uVar16 != 0; uVar16 = uVar16 - 1) {
      uVar1 = unaff_ESI[1];
      uVar2 = unaff_ESI[2];
      uVar3 = unaff_ESI[3];
      *puVar18 = *unaff_ESI;
      puVar18[1] = uVar1;
      puVar18[2] = uVar2;
      puVar18[3] = uVar3;
      unaff_ESI = unaff_ESI + 4;
      puVar18 = puVar18 + 4;
    }
    if ((param_1 & 0xf) != 0) {
      for (uVar16 = (param_1 & 0xf) >> 2; uVar16 != 0; uVar16 = uVar16 - 1) {
        *puVar18 = *unaff_ESI;
        unaff_ESI = unaff_ESI + 1;
        puVar18 = puVar18 + 1;
      }
      for (uVar16 = param_1 & 3; uVar16 != 0; uVar16 = uVar16 - 1) {
        *(undefined *)puVar18 = *(undefined *)unaff_ESI;
        unaff_ESI = (undefined4 *)((int)unaff_ESI + 1);
        puVar18 = (undefined4 *)((int)puVar18 + 1);
      }
    }
  }
  return unaff_EDI;
}



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2010 Release

int __cdecl __heap_init(void)

{
  hHeap_0047fd38 = HeapCreate(0,0x1000,0);
  return (uint)(hHeap_0047fd38 != (HANDLE)0x0);
}



// Library Function - Single Match
//  int __cdecl CPtoLCID(int)
// 
// Library: Visual Studio 2010 Release

int __cdecl CPtoLCID(int param_1)

{
  int in_EAX;
  
  if (in_EAX == 0x3a4) {
    return 0x411;
  }
  if (in_EAX == 0x3a8) {
    return 0x804;
  }
  if (in_EAX == 0x3b5) {
    return 0x412;
  }
  if (in_EAX != 0x3b6) {
    return 0;
  }
  return 0x404;
}



// Library Function - Single Match
//  void __cdecl setSBCS(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2010 Release

void __cdecl setSBCS(threadmbcinfostruct *param_1)

{
  int in_EAX;
  undefined *puVar1;
  int iVar2;
  
  _memset((void *)(in_EAX + 0x1c),0,0x101);
  *(undefined4 *)(in_EAX + 4) = 0;
  *(undefined4 *)(in_EAX + 8) = 0;
  *(undefined4 *)(in_EAX + 0xc) = 0;
  *(undefined4 *)(in_EAX + 0x10) = 0;
  *(undefined4 *)(in_EAX + 0x14) = 0;
  *(undefined4 *)(in_EAX + 0x18) = 0;
  puVar1 = (undefined *)(in_EAX + 0x1c);
  iVar2 = 0x101;
  do {
    *puVar1 = puVar1[(int)&lpAddend_0043d5d0 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&lpAddend_0043d5d0 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2010 Release

void __cdecl setSBUpLow(threadmbcinfostruct *param_1)

{
  byte *pbVar1;
  char *pcVar2;
  BOOL BVar3;
  uint uVar4;
  CHAR CVar5;
  char cVar6;
  BYTE *pBVar7;
  int unaff_ESI;
  _cpinfo local_51c;
  WORD local_508 [256];
  CHAR local_308 [256];
  CHAR local_208 [256];
  CHAR local_108 [256];
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_00407fa4:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_00407fa4;
        }
        *pcVar2 = '\0';
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  else {
    uVar4 = 0;
    do {
      local_108[uVar4] = (CHAR)uVar4;
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
    local_108[0] = ' ';
    if (local_51c.LeadByte[0] != 0) {
      pBVar7 = local_51c.LeadByte + 1;
      do {
        uVar4 = (uint)local_51c.LeadByte[0];
        if (uVar4 <= *pBVar7) {
          _memset(local_108 + uVar4,0x20,(*pBVar7 - uVar4) + 1);
        }
        local_51c.LeadByte[0] = pBVar7[1];
        pBVar7 = pBVar7 + 2;
      } while (local_51c.LeadByte[0] != 0);
    }
    ___crtGetStringTypeA
              ((_locale_t)0x0,1,local_108,0x100,local_508,*(int *)(unaff_ESI + 4),
               *(BOOL *)(unaff_ESI + 0xc));
    ___crtLCMapStringA((_locale_t)0x0,*(LPCWSTR *)(unaff_ESI + 0xc),0x100,local_108,0x100,local_208,
                       0x100,*(int *)(unaff_ESI + 4),0);
    ___crtLCMapStringA((_locale_t)0x0,*(LPCWSTR *)(unaff_ESI + 0xc),0x200,local_108,0x100,local_308,
                       0x100,*(int *)(unaff_ESI + 4),0);
    uVar4 = 0;
    do {
      if ((local_508[uVar4] & 1) == 0) {
        if ((local_508[uVar4] & 2) != 0) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          CVar5 = local_308[uVar4];
          goto LAB_00407f47;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_00407f47:
        *(CHAR *)(unaff_ESI + 0x11d + uVar4) = CVar5;
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___updatetmbcinfo
// 
// Library: Visual Studio 2010 Release

pthreadmbcinfo __cdecl ___updatetmbcinfo(void)

{
  _ptiddata p_Var1;
  LONG LVar2;
  pthreadmbcinfo lpAddend;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_0043daf0) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)lpAddend_0043d9f8) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&lpAddend_0043d5d0)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)lpAddend_0043d9f8;
      lpAddend = (pthreadmbcinfo)lpAddend_0043d9f8;
      InterlockedIncrement((LONG *)lpAddend_0043d9f8);
    }
    FUN_00408059();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_00408059(void)

{
  FUN_00406cc5(0xd);
  return;
}



// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Library: Visual Studio 2010 Release

int __cdecl getSystemCP(int param_1)

{
  UINT UVar1;
  int unaff_ESI;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,(localeinfo_struct *)0x0);
  DAT_0047fd40 = 0;
  if (unaff_ESI == -2) {
    DAT_0047fd40 = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_0047fd40 = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_0047fd40 = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_0047fd40 = 1;
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return UVar1;
}



// Library Function - Single Match
//  __setmbcp_nolock
// 
// Library: Visual Studio 2010 Release

void __cdecl __setmbcp_nolock(undefined4 param_1,int param_2)

{
  BYTE *pBVar1;
  byte *pbVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  BOOL BVar6;
  undefined2 *puVar7;
  byte *pbVar8;
  int extraout_ECX;
  undefined2 *puVar9;
  int iVar10;
  undefined4 extraout_EDX;
  BYTE *pBVar11;
  threadmbcinfostruct *unaff_EDI;
  uint local_24;
  byte *local_20;
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  uVar4 = getSystemCP((int)unaff_EDI);
  if (uVar4 != 0) {
    local_20 = (byte *)0x0;
    uVar5 = 0;
LAB_0040811c:
    if (*(uint *)((int)&DAT_0043da00 + uVar5) != uVar4) goto code_r0x00408128;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_0043da10 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar5 = (uint)*pbVar8; uVar5 <= bVar3; uVar5 = uVar5 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar5);
          *pbVar2 = *pbVar2 | (&DAT_0043d9fc)[local_24];
          bVar3 = pbVar8[1];
        }
      }
      local_24 = local_24 + 1;
      pbVar8 = local_20 + 8;
      local_20 = pbVar8;
    } while (local_24 < 4);
    *(uint *)(param_2 + 4) = uVar4;
    *(undefined4 *)(param_2 + 8) = 1;
    iVar10 = CPtoLCID((int)unaff_EDI);
    *(int *)(param_2 + 0xc) = iVar10;
    puVar7 = (undefined2 *)(param_2 + 0x10);
    puVar9 = (undefined2 *)(&DAT_0043da04 + extraout_ECX);
    iVar10 = 6;
    do {
      *puVar7 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar7 = puVar7 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    goto LAB_00408250;
  }
LAB_00408109:
  setSBCS(unaff_EDI);
LAB_004082b8:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x00408128:
  local_20 = (byte *)((int)local_20 + 1);
  uVar5 = uVar5 + 0x30;
  if (0xef < uVar5) goto code_r0x00408135;
  goto LAB_0040811c;
code_r0x00408135:
  if (((uVar4 == 65000) || (uVar4 == 0xfde9)) ||
     (BVar6 = IsValidCodePage(uVar4 & 0xffff), BVar6 == 0)) goto LAB_004082b8;
  BVar6 = GetCPInfo(uVar4,&local_1c);
  if (BVar6 != 0) {
    _memset((void *)(param_2 + 0x1c),0,0x101);
    *(uint *)(param_2 + 4) = uVar4;
    *(undefined4 *)(param_2 + 0xc) = 0;
    if (local_1c.MaxCharSize < 2) {
      *(undefined4 *)(param_2 + 8) = 0;
    }
    else {
      if (local_1c.LeadByte[0] != '\0') {
        pBVar11 = local_1c.LeadByte + 1;
        do {
          bVar3 = *pBVar11;
          if (bVar3 == 0) break;
          for (uVar4 = (uint)pBVar11[-1]; uVar4 <= bVar3; uVar4 = uVar4 + 1) {
            pbVar8 = (byte *)(param_2 + 0x1d + uVar4);
            *pbVar8 = *pbVar8 | 4;
          }
          pBVar1 = pBVar11 + 1;
          pBVar11 = pBVar11 + 2;
        } while (*pBVar1 != 0);
      }
      pbVar8 = (byte *)(param_2 + 0x1e);
      iVar10 = 0xfe;
      do {
        *pbVar8 = *pbVar8 | 8;
        pbVar8 = pbVar8 + 1;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
      iVar10 = CPtoLCID((int)unaff_EDI);
      *(int *)(param_2 + 0xc) = iVar10;
      *(undefined4 *)(param_2 + 8) = extraout_EDX;
    }
    *(undefined4 *)(param_2 + 0x10) = 0;
    *(undefined4 *)(param_2 + 0x14) = 0;
    *(undefined4 *)(param_2 + 0x18) = 0;
LAB_00408250:
    setSBUpLow(unaff_EDI);
    goto LAB_004082b8;
  }
  if (DAT_0047fd40 == 0) goto LAB_004082b8;
  goto LAB_00408109;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __setmbcp
// 
// Library: Visual Studio 2010 Release

int __cdecl __setmbcp(int _CodePage)

{
  _ptiddata p_Var1;
  int iVar2;
  pthreadmbcinfo ptVar3;
  LONG LVar4;
  int *piVar5;
  int iVar6;
  pthreadmbcinfo ptVar7;
  pthreadmbcinfo ptVar8;
  int in_stack_ffffffc8;
  int local_24;
  
  local_24 = -1;
  p_Var1 = __getptd();
  ___updatetmbcinfo();
  ptVar3 = p_Var1->ptmbcinfo;
  iVar2 = getSystemCP(in_stack_ffffffc8);
  if (iVar2 == ptVar3->mbcodepage) {
    local_24 = 0;
  }
  else {
    ptVar3 = (pthreadmbcinfo)__malloc_crt(0x220);
    if (ptVar3 != (pthreadmbcinfo)0x0) {
      ptVar7 = p_Var1->ptmbcinfo;
      ptVar8 = ptVar3;
      for (iVar6 = 0x88; iVar6 != 0; iVar6 = iVar6 + -1) {
        ptVar8->refcount = (int)ptVar7->refcount;
        ptVar7 = (pthreadmbcinfo)&ptVar7->mbcodepage;
        ptVar8 = (pthreadmbcinfo)&ptVar8->mbcodepage;
      }
      ptVar3->refcount = 0;
      local_24 = __setmbcp_nolock(iVar2,(int)ptVar3);
      if (local_24 == 0) {
        LVar4 = InterlockedDecrement(&p_Var1->ptmbcinfo->refcount);
        if ((LVar4 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&lpAddend_0043d5d0)) {
          _free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar3;
        InterlockedIncrement((LONG *)ptVar3);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_0043daf0 & 1) == 0)) {
          __lock(0xd);
          _DAT_0047fd50 = ptVar3->mbcodepage;
          _DAT_0047fd54 = ptVar3->ismbcodepage;
          _DAT_0047fd58 = *(undefined4 *)ptVar3->mbulinfo;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_0047fd44)[iVar2] = ptVar3->mbulinfo[iVar2 + 2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_0043d7f0)[iVar2] = ptVar3->mbctype[iVar2 + 4];
          }
          for (iVar2 = 0; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_0043d8f8)[iVar2] = ptVar3->mbcasemap[iVar2 + 4];
          }
          LVar4 = InterlockedDecrement((LONG *)lpAddend_0043d9f8);
          if ((LVar4 == 0) && ((LONG **)lpAddend_0043d9f8 != &lpAddend_0043d5d0)) {
            _free(lpAddend_0043d9f8);
          }
          lpAddend_0043d9f8 = (undefined *)ptVar3;
          InterlockedIncrement((LONG *)ptVar3);
          FUN_00408428();
        }
      }
      else if (local_24 == -1) {
        if (ptVar3 != (pthreadmbcinfo)&lpAddend_0043d5d0) {
          _free(ptVar3);
        }
        piVar5 = __errno();
        *piVar5 = 0x16;
      }
    }
  }
  return local_24;
}



void FUN_00408428(void)

{
  FUN_00406cc5(0xd);
  return;
}



// Library Function - Single Match
//  ___initmbctable
// 
// Library: Visual Studio 2010 Release

undefined4 ___initmbctable(void)

{
  if (DAT_0047ffbc == 0) {
    __setmbcp(-3);
    DAT_0047ffbc = 1;
  }
  return 0;
}



// Library Function - Single Match
//  ___addlocaleref
// 
// Library: Visual Studio 2010 Release

void __cdecl ___addlocaleref(LONG *param_1)

{
  LONG *pLVar1;
  LONG **ppLVar2;
  
  pLVar1 = param_1;
  InterlockedIncrement(param_1);
  if ((LONG *)param_1[0x2c] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x2c]);
  }
  if ((LONG *)param_1[0x2e] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x2e]);
  }
  if ((LONG *)param_1[0x2d] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x2d]);
  }
  if ((LONG *)param_1[0x30] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x30]);
  }
  ppLVar2 = (LONG **)(param_1 + 0x14);
  param_1 = (LONG *)0x6;
  do {
    if ((ppLVar2[-2] != (LONG *)&DAT_0043daf4) && (*ppLVar2 != (LONG *)0x0)) {
      InterlockedIncrement(*ppLVar2);
    }
    if ((ppLVar2[-1] != (LONG *)0x0) && (ppLVar2[1] != (LONG *)0x0)) {
      InterlockedIncrement(ppLVar2[1]);
    }
    ppLVar2 = ppLVar2 + 4;
    param_1 = (LONG *)((int)param_1 + -1);
  } while (param_1 != (LONG *)0x0);
  InterlockedIncrement((LONG *)(pLVar1[0x35] + 0xb4));
  return;
}



// Library Function - Single Match
//  ___removelocaleref
// 
// Library: Visual Studio 2010 Release

LONG * __cdecl ___removelocaleref(LONG *param_1)

{
  LONG *pLVar1;
  LONG **ppLVar2;
  
  pLVar1 = param_1;
  if (param_1 != (LONG *)0x0) {
    InterlockedDecrement(param_1);
    if ((LONG *)param_1[0x2c] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x2c]);
    }
    if ((LONG *)param_1[0x2e] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x2e]);
    }
    if ((LONG *)param_1[0x2d] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x2d]);
    }
    if ((LONG *)param_1[0x30] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x30]);
    }
    ppLVar2 = (LONG **)(param_1 + 0x14);
    param_1 = (LONG *)0x6;
    do {
      if ((ppLVar2[-2] != (LONG *)&DAT_0043daf4) && (*ppLVar2 != (LONG *)0x0)) {
        InterlockedDecrement(*ppLVar2);
      }
      if ((ppLVar2[-1] != (LONG *)0x0) && (ppLVar2[1] != (LONG *)0x0)) {
        InterlockedDecrement(ppLVar2[1]);
      }
      ppLVar2 = ppLVar2 + 4;
      param_1 = (LONG *)((int)param_1 + -1);
    } while (param_1 != (LONG *)0x0);
    InterlockedDecrement((LONG *)(pLVar1[0x35] + 0xb4));
  }
  return pLVar1;
}



// Library Function - Single Match
//  ___freetlocinfo
// 
// Library: Visual Studio 2010 Release

void __cdecl ___freetlocinfo(void *param_1)

{
  int *piVar1;
  undefined **ppuVar2;
  void *_Memory;
  int **ppiVar3;
  
  _Memory = param_1;
  if ((((*(undefined ***)((int)param_1 + 0xbc) != (undefined **)0x0) &&
       (*(undefined ***)((int)param_1 + 0xbc) != &PTR_DAT_0043de50)) &&
      (*(int **)((int)param_1 + 0xb0) != (int *)0x0)) && (**(int **)((int)param_1 + 0xb0) == 0)) {
    piVar1 = *(int **)((int)param_1 + 0xb8);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      _free(piVar1);
      ___free_lconv_mon(*(int *)((int)param_1 + 0xbc));
    }
    piVar1 = *(int **)((int)param_1 + 0xb4);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      _free(piVar1);
      ___free_lconv_num(*(void ***)((int)param_1 + 0xbc));
    }
    _free(*(void **)((int)param_1 + 0xb0));
    _free(*(void **)((int)param_1 + 0xbc));
  }
  if ((*(int **)((int)param_1 + 0xc0) != (int *)0x0) && (**(int **)((int)param_1 + 0xc0) == 0)) {
    _free((void *)(*(int *)((int)param_1 + 0xc4) + -0xfe));
    _free((void *)(*(int *)((int)param_1 + 0xcc) + -0x80));
    _free((void *)(*(int *)((int)param_1 + 0xd0) + -0x80));
    _free(*(void **)((int)param_1 + 0xc0));
  }
  ppuVar2 = *(undefined ***)((int)param_1 + 0xd4);
  if ((ppuVar2 != &PTR_DAT_0043daf8) && (ppuVar2[0x2d] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar3 = (int **)((int)param_1 + 0x50);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar3[-2] != (int *)&DAT_0043daf4) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      _free(piVar1);
    }
    if (((ppiVar3[-1] != (int *)0x0) && (piVar1 = ppiVar3[1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      _free(piVar1);
    }
    ppiVar3 = ppiVar3 + 4;
    param_1 = (void *)((int)param_1 + -1);
  } while (param_1 != (void *)0x0);
  _free(_Memory);
  return;
}



// Library Function - Single Match
//  __updatetlocinfoEx_nolock
// 
// Library: Visual Studio 2010 Release

LONG * __cdecl __updatetlocinfoEx_nolock(LONG **param_1,LONG *param_2)

{
  LONG *pLVar1;
  
  if ((param_2 == (LONG *)0x0) || (param_1 == (LONG **)0x0)) {
    param_2 = (LONG *)0x0;
  }
  else {
    pLVar1 = *param_1;
    if (pLVar1 != param_2) {
      *param_1 = param_2;
      ___addlocaleref(param_2);
      if (((pLVar1 != (LONG *)0x0) && (___removelocaleref(pLVar1), *pLVar1 == 0)) &&
         (pLVar1 != (LONG *)&DAT_0043dc60)) {
        ___freetlocinfo(pLVar1);
      }
    }
  }
  return param_2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___updatetlocinfo
// 
// Library: Visual Studio 2010 Release

pthreadlocinfo __cdecl ___updatetlocinfo(void)

{
  _ptiddata p_Var1;
  pthreadlocinfo ptVar2;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_0043daf0) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    ptVar2 = (pthreadlocinfo)&p_Var1->ptlocinfo;
    __updatetlocinfoEx_nolock((LONG **)ptVar2,(LONG *)PTR_DAT_0043dd38);
    FUN_004087ac();
  }
  else {
    p_Var1 = __getptd();
    ptVar2 = p_Var1->ptlocinfo;
  }
  if (ptVar2 == (pthreadlocinfo)0x0) {
    __amsg_exit(0x20);
  }
  return ptVar2;
}



void FUN_004087ac(void)

{
  FUN_00406cc5(0xc);
  return;
}



// Library Function - Single Match
//  __freea
// 
// Library: Visual Studio 2010 Release

void __cdecl __freea(void *_Memory)

{
  if ((_Memory != (void *)0x0) && (*(int *)((int)_Memory + -8) == 0xdddd)) {
    _free((int *)((int)_Memory + -8));
  }
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtLCMapStringA_stat(struct localeinfo_struct *,unsigned long,unsigned long,char
// const *,int,char *,int,int,int)
// 
// Library: Visual Studio 2010 Release

int __cdecl
__crtLCMapStringA_stat
          (localeinfo_struct *param_1,ulong param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8,int param_9)

{
  uint _Size;
  bool bVar1;
  uint uVar2;
  char *pcVar3;
  int iVar4;
  uint cchWideChar;
  uint uVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *local_10;
  
  uVar2 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  pcVar3 = param_4;
  iVar7 = param_5;
  if (0 < param_5) {
    do {
      iVar7 = iVar7 + -1;
      if (*pcVar3 == '\0') goto LAB_00408808;
      pcVar3 = pcVar3 + 1;
    } while (iVar7 != 0);
    iVar7 = -1;
LAB_00408808:
    iVar7 = param_5 - iVar7;
    iVar4 = iVar7 + -1;
    bVar1 = iVar4 < param_5;
    param_5 = iVar4;
    if (bVar1) {
      param_5 = iVar7;
    }
  }
  if (param_8 == 0) {
    param_8 = param_1->locinfo->lc_codepage;
  }
  cchWideChar = MultiByteToWideChar(param_8,(uint)(param_9 != 0) * 8 + 1,param_4,param_5,(LPWSTR)0x0
                                    ,0);
  if (cchWideChar == 0) goto LAB_004089ad;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar5 = cchWideChar * 2 + 8;
    if (uVar5 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffe0;
      local_10 = (undefined4 *)&stack0xffffffe0;
      if (&stack0x00000000 != (undefined *)0x20) {
LAB_00408898:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar5);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_00408898;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_004089ad;
  iVar7 = MultiByteToWideChar(param_8,1,param_4,param_5,(LPWSTR)local_10,cchWideChar);
  if ((iVar7 != 0) &&
     (uVar5 = LCMapStringW(param_2,param_3,(LPCWSTR)local_10,cchWideChar,(LPWSTR)0x0,0), uVar5 != 0)
     ) {
    if ((param_3 & 0x400) == 0) {
      if (((int)uVar5 < 1) || (0xffffffe0 / uVar5 < 2)) {
        puVar6 = (undefined4 *)0x0;
      }
      else {
        _Size = uVar5 * 2 + 8;
        if (_Size < 0x401) {
          if (&stack0x00000000 == (undefined *)0x20) goto LAB_004089a1;
          puVar6 = (undefined4 *)&stack0xffffffe8;
        }
        else {
          puVar6 = (undefined4 *)_malloc(_Size);
          if (puVar6 != (undefined4 *)0x0) {
            *puVar6 = 0xdddd;
            puVar6 = puVar6 + 2;
          }
        }
      }
      if (puVar6 != (undefined4 *)0x0) {
        iVar7 = LCMapStringW(param_2,param_3,(LPCWSTR)local_10,cchWideChar,(LPWSTR)puVar6,uVar5);
        if (iVar7 != 0) {
          if (param_7 == 0) {
            param_7 = 0;
            param_6 = (LPSTR)0x0;
          }
          WideCharToMultiByte(param_8,0,(LPCWSTR)puVar6,uVar5,param_6,param_7,(LPCSTR)0x0,
                              (LPBOOL)0x0);
        }
        __freea(puVar6);
      }
    }
    else if ((param_7 != 0) && ((int)uVar5 <= param_7)) {
      LCMapStringW(param_2,param_3,(LPCWSTR)local_10,cchWideChar,(LPWSTR)param_6,param_7);
    }
  }
LAB_004089a1:
  __freea(local_10);
LAB_004089ad:
  iVar7 = ___security_check_cookie_4(uVar2 ^ (uint)&stack0xfffffffc);
  return iVar7;
}



// Library Function - Single Match
//  ___crtLCMapStringA
// 
// Library: Visual Studio 2010 Release

int __cdecl
___crtLCMapStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwMapFlag,LPCSTR _LpSrcStr,
                  int _CchSrc,LPSTR _LpDestStr,int _CchDest,int _Code_page,BOOL _BError)

{
  int iVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Plocinfo);
  iVar1 = __crtLCMapStringA_stat
                    (&local_14,(ulong)_LocaleName,_DwMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,
                     _Code_page,_BError);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  __isleadbyte_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __isleadbyte_l(int _C,_locale_t _Locale)

{
  ushort uVar1;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
  uVar1 = *(ushort *)(*(int *)(local_14[0] + 200) + (_C & 0xffU) * 2);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1 & 0x8000;
}



// Library Function - Single Match
//  _isleadbyte
// 
// Library: Visual Studio 2010 Release

int __cdecl _isleadbyte(int _C)

{
  int iVar1;
  
  iVar1 = __isleadbyte_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __isctype_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __isctype_l(int _C,int _Type,_locale_t _Locale)

{
  int iVar1;
  BOOL BVar2;
  CHAR CVar3;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  CHAR local_c;
  CHAR local_b;
  undefined local_a;
  ushort local_8 [2];
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,_Locale);
  if (_C + 1U < 0x101) {
    local_8[0] = *(ushort *)(local_1c.locinfo[1].lc_category[0].locale + _C * 2);
  }
  else {
    iVar1 = __isleadbyte_l(_C >> 8 & 0xff,&local_1c);
    CVar3 = (CHAR)_C;
    if (iVar1 == 0) {
      local_b = '\0';
      iVar1 = 1;
      local_c = CVar3;
    }
    else {
      _C._0_1_ = (CHAR)((uint)_C >> 8);
      local_c = (CHAR)_C;
      local_a = 0;
      iVar1 = 2;
      local_b = CVar3;
    }
    BVar2 = ___crtGetStringTypeA
                      (&local_1c,1,&local_c,iVar1,local_8,(local_1c.locinfo)->lc_codepage,
                       (BOOL)(local_1c.locinfo)->lc_category[0].wlocale);
    if (BVar2 == 0) {
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
      return 0;
    }
  }
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return (uint)local_8[0] & _Type;
}



uint * __cdecl FUN_00408b26(uint *param_1)

{
  uint uVar1;
  char cVar2;
  uint in_EAX;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  char cVar6;
  uint uVar7;
  
  cVar6 = (char)in_EAX;
  uVar7 = (uint)param_1 & 3;
  while (uVar7 != 0) {
    if (*(char *)param_1 == cVar6) {
      return param_1;
    }
    if (*(char *)param_1 == '\0') {
      return (uint *)0x0;
    }
    uVar7 = (uint)(uint *)((int)param_1 + 1) & 3;
    param_1 = (uint *)((int)param_1 + 1);
  }
  uVar7 = in_EAX | in_EAX << 8;
  while( true ) {
    while( true ) {
      uVar1 = *param_1;
      uVar4 = uVar1 ^ (uVar7 << 0x10 | uVar7);
      uVar3 = uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff;
      puVar5 = param_1 + 1;
      if (((uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff) & 0x81010100) != 0) break;
      param_1 = puVar5;
      if ((uVar3 & 0x81010100) != 0) {
        if ((uVar3 & 0x1010100) != 0) {
          return (uint *)0x0;
        }
        if ((uVar1 + 0x7efefeff & 0x80000000) == 0) {
          return (uint *)0x0;
        }
      }
    }
    uVar1 = *param_1;
    if ((char)uVar1 == cVar6) {
      return param_1;
    }
    if ((char)uVar1 == '\0') {
      return (uint *)0x0;
    }
    cVar2 = (char)(uVar1 >> 8);
    if (cVar2 == cVar6) {
      return (uint *)((int)param_1 + 1);
    }
    if (cVar2 == '\0') break;
    cVar2 = (char)(uVar1 >> 0x10);
    if (cVar2 == cVar6) {
      return (uint *)((int)param_1 + 2);
    }
    if (cVar2 == '\0') {
      return (uint *)0x0;
    }
    cVar2 = (char)(uVar1 >> 0x18);
    if (cVar2 == cVar6) {
      return (uint *)((int)param_1 + 3);
    }
    param_1 = puVar5;
    if (cVar2 == '\0') {
      return (uint *)0x0;
    }
  }
  return (uint *)0x0;
}



// Library Function - Single Match
//  long __stdcall __CxxUnhandledExceptionFilter(struct _EXCEPTION_POINTERS *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS *param_1)

{
  PEXCEPTION_RECORD pEVar1;
  ULONG_PTR UVar2;
  
  pEVar1 = param_1->ExceptionRecord;
  if (((pEVar1->ExceptionCode == 0xe06d7363) && (pEVar1->NumberParameters == 3)) &&
     ((UVar2 = pEVar1->ExceptionInformation[0], UVar2 == 0x19930520 ||
      (((UVar2 == 0x19930521 || (UVar2 == 0x19930522)) || (UVar2 == 0x1994000)))))) {
    terminate();
  }
  return 0;
}



// Library Function - Single Match
//  __XcptFilter
// 
// Library: Visual Studio 2010 Release

int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  ulong *puVar1;
  code *pcVar2;
  void *pvVar3;
  ulong uVar4;
  _ptiddata p_Var5;
  ulong *puVar6;
  int iVar7;
  
  p_Var5 = __getptd_noexit();
  if (p_Var5 != (_ptiddata)0x0) {
    puVar1 = (ulong *)p_Var5->_pxcptacttab;
    puVar6 = puVar1;
    do {
      if (*puVar6 == _ExceptionNum) break;
      puVar6 = puVar6 + 3;
    } while (puVar6 < puVar1 + 0x24);
    if ((puVar1 + 0x24 <= puVar6) || (*puVar6 != _ExceptionNum)) {
      puVar6 = (ulong *)0x0;
    }
    if ((puVar6 == (ulong *)0x0) || (pcVar2 = (code *)puVar6[2], pcVar2 == (code *)0x0)) {
      p_Var5 = (_ptiddata)0x0;
    }
    else if (pcVar2 == (code *)0x5) {
      puVar6[2] = 0;
      p_Var5 = (_ptiddata)0x1;
    }
    else {
      if (pcVar2 != (code *)0x1) {
        pvVar3 = p_Var5->_tpxcptinfoptrs;
        p_Var5->_tpxcptinfoptrs = _ExceptionPtr;
        if (puVar6[1] == 8) {
          iVar7 = 0x24;
          do {
            *(undefined4 *)(iVar7 + 8 + (int)p_Var5->_pxcptacttab) = 0;
            iVar7 = iVar7 + 0xc;
          } while (iVar7 < 0x90);
          uVar4 = *puVar6;
          iVar7 = p_Var5->_tfpecode;
          if (uVar4 == 0xc000008e) {
            p_Var5->_tfpecode = 0x83;
          }
          else if (uVar4 == 0xc0000090) {
            p_Var5->_tfpecode = 0x81;
          }
          else if (uVar4 == 0xc0000091) {
            p_Var5->_tfpecode = 0x84;
          }
          else if (uVar4 == 0xc0000093) {
            p_Var5->_tfpecode = 0x85;
          }
          else if (uVar4 == 0xc000008d) {
            p_Var5->_tfpecode = 0x82;
          }
          else if (uVar4 == 0xc000008f) {
            p_Var5->_tfpecode = 0x86;
          }
          else if (uVar4 == 0xc0000092) {
            p_Var5->_tfpecode = 0x8a;
          }
          else if (uVar4 == 0xc00002b5) {
            p_Var5->_tfpecode = 0x8d;
          }
          else if (uVar4 == 0xc00002b4) {
            p_Var5->_tfpecode = 0x8e;
          }
          (*pcVar2)(8,p_Var5->_tfpecode);
          p_Var5->_tfpecode = iVar7;
        }
        else {
          puVar6[2] = 0;
          (*pcVar2)(puVar6[1]);
        }
        p_Var5->_tpxcptinfoptrs = pvVar3;
      }
      p_Var5 = (_ptiddata)0xffffffff;
    }
  }
  return (int)p_Var5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __setenvp
// 
// Library: Visual Studio 2010 Release

int __cdecl __setenvp(void)

{
  char **ppcVar1;
  size_t sVar2;
  char *_Dst;
  errno_t eVar3;
  char *pcVar4;
  int iVar5;
  
  if (DAT_0047ffbc == 0) {
    ___initmbctable();
  }
  iVar5 = 0;
  pcVar4 = DAT_0047f240;
  if (DAT_0047f240 != (char *)0x0) {
    for (; *pcVar4 != '\0'; pcVar4 = pcVar4 + sVar2 + 1) {
      if (*pcVar4 != '=') {
        iVar5 = iVar5 + 1;
      }
      sVar2 = _strlen(pcVar4);
    }
    ppcVar1 = (char **)__calloc_crt(iVar5 + 1,4);
    pcVar4 = DAT_0047f240;
    DAT_0047f21c = ppcVar1;
    if (ppcVar1 != (char **)0x0) {
      do {
        if (*pcVar4 == '\0') {
          _free(DAT_0047f240);
          DAT_0047f240 = (char *)0x0;
          *ppcVar1 = (char *)0x0;
          _DAT_0047ffb0 = 1;
          return 0;
        }
        sVar2 = _strlen(pcVar4);
        sVar2 = sVar2 + 1;
        if (*pcVar4 != '=') {
          _Dst = (char *)__calloc_crt(sVar2,1);
          *ppcVar1 = _Dst;
          if (_Dst == (char *)0x0) {
            _free(DAT_0047f21c);
            DAT_0047f21c = (char **)0x0;
            return -1;
          }
          eVar3 = _strcpy_s(_Dst,sVar2,pcVar4);
          if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          ppcVar1 = ppcVar1 + 1;
        }
        pcVar4 = pcVar4 + sVar2;
      } while( true );
    }
  }
  return -1;
}



// Library Function - Single Match
//  _parse_cmdline
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall
_parse_cmdline(undefined4 param_1,byte *param_2,byte **param_3,byte *param_4,int *param_5)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  byte bVar6;
  byte *pbVar7;
  byte *pbVar8;
  int *unaff_EDI;
  
  *unaff_EDI = 0;
  *param_5 = 1;
  if (param_3 != (byte **)0x0) {
    *param_3 = param_4;
    param_3 = param_3 + 1;
  }
  bVar2 = false;
  pbVar5 = param_4;
  do {
    if (*param_2 == 0x22) {
      bVar2 = !bVar2;
      bVar6 = 0x22;
      pbVar7 = param_2 + 1;
    }
    else {
      *unaff_EDI = *unaff_EDI + 1;
      if (pbVar5 != (byte *)0x0) {
        *pbVar5 = *param_2;
        param_4 = pbVar5 + 1;
      }
      bVar6 = *param_2;
      pbVar7 = param_2 + 1;
      iVar3 = __ismbblead((uint)bVar6);
      if (iVar3 != 0) {
        *unaff_EDI = *unaff_EDI + 1;
        if (param_4 != (byte *)0x0) {
          *param_4 = *pbVar7;
          param_4 = param_4 + 1;
        }
        pbVar7 = param_2 + 2;
      }
      pbVar5 = param_4;
      if (bVar6 == 0) {
        pbVar7 = pbVar7 + -1;
        goto LAB_00408ee8;
      }
    }
    param_2 = pbVar7;
  } while ((bVar2) || ((bVar6 != 0x20 && (bVar6 != 9))));
  if (pbVar5 != (byte *)0x0) {
    pbVar5[-1] = 0;
  }
LAB_00408ee8:
  bVar2 = false;
  while (*pbVar7 != 0) {
    for (; (*pbVar7 == 0x20 || (*pbVar7 == 9)); pbVar7 = pbVar7 + 1) {
    }
    if (*pbVar7 == 0) break;
    if (param_3 != (byte **)0x0) {
      *param_3 = pbVar5;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
    while( true ) {
      bVar1 = true;
      uVar4 = 0;
      for (; *pbVar7 == 0x5c; pbVar7 = pbVar7 + 1) {
        uVar4 = uVar4 + 1;
      }
      if (*pbVar7 == 0x22) {
        pbVar8 = pbVar7;
        if (((uVar4 & 1) == 0) && ((!bVar2 || (pbVar8 = pbVar7 + 1, *pbVar8 != 0x22)))) {
          bVar1 = false;
          bVar2 = !bVar2;
          pbVar8 = pbVar7;
        }
        uVar4 = uVar4 >> 1;
        pbVar7 = pbVar8;
      }
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        if (pbVar5 != (byte *)0x0) {
          *pbVar5 = 0x5c;
          pbVar5 = pbVar5 + 1;
        }
        *unaff_EDI = *unaff_EDI + 1;
        param_4 = pbVar5;
      }
      bVar6 = *pbVar7;
      if ((bVar6 == 0) || ((!bVar2 && ((bVar6 == 0x20 || (bVar6 == 9)))))) break;
      if (bVar1) {
        if (pbVar5 == (byte *)0x0) {
          iVar3 = __ismbblead((int)(char)bVar6);
          if (iVar3 != 0) {
            pbVar7 = pbVar7 + 1;
            *unaff_EDI = *unaff_EDI + 1;
          }
        }
        else {
          iVar3 = __ismbblead((int)(char)bVar6);
          if (iVar3 != 0) {
            *param_4 = *pbVar7;
            pbVar7 = pbVar7 + 1;
            *unaff_EDI = *unaff_EDI + 1;
            param_4 = param_4 + 1;
          }
          *param_4 = *pbVar7;
          param_4 = param_4 + 1;
        }
        *unaff_EDI = *unaff_EDI + 1;
        pbVar5 = param_4;
      }
      pbVar7 = pbVar7 + 1;
    }
    if (pbVar5 != (byte *)0x0) {
      *pbVar5 = 0;
      pbVar5 = pbVar5 + 1;
      param_4 = pbVar5;
    }
    *unaff_EDI = *unaff_EDI + 1;
  }
  if (param_3 != (byte **)0x0) {
    *param_3 = (byte *)0x0;
  }
  *param_5 = *param_5 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __setargv
// 
// Library: Visual Studio 2010 Release

int __cdecl __setargv(void)

{
  uint uVar1;
  byte **ppbVar2;
  undefined4 extraout_ECX;
  uint _Size;
  uint local_10;
  uint local_c;
  byte *local_8;
  
  if (DAT_0047ffbc == 0) {
    ___initmbctable();
  }
  DAT_0047fe64 = 0;
  GetModuleFileNameA((HMODULE)0x0,&DAT_0047fd60,0x104);
  _DAT_0047f22c = &DAT_0047fd60;
  if ((DAT_0047ffa8 == (byte *)0x0) || (local_8 = DAT_0047ffa8, *DAT_0047ffa8 == 0)) {
    local_8 = &DAT_0047fd60;
  }
  _parse_cmdline(extraout_ECX,local_8,(byte **)0x0,(byte *)0x0,(int *)&local_c);
  uVar1 = local_c;
  if ((local_c < 0x3fffffff) && (local_10 != 0xffffffff)) {
    _Size = local_c * 4 + local_10;
    if ((local_10 <= _Size) && (ppbVar2 = (byte **)__malloc_crt(_Size), ppbVar2 != (byte **)0x0)) {
      _parse_cmdline(_Size,local_8,ppbVar2,(byte *)(ppbVar2 + uVar1),(int *)&local_c);
      DAT_0047f210 = local_c - 1;
      DAT_0047f214 = ppbVar2;
      return 0;
    }
  }
  return -1;
}



// Library Function - Single Match
//  ___crtGetEnvironmentStringsA
// 
// Library: Visual Studio 2010 Release

LPVOID __cdecl ___crtGetEnvironmentStringsA(void)

{
  WCHAR WVar1;
  LPWCH lpWideCharStr;
  WCHAR *pWVar2;
  int iVar4;
  size_t _Size;
  LPSTR local_8;
  WCHAR *pWVar3;
  
  lpWideCharStr = GetEnvironmentStringsW();
  if (lpWideCharStr == (LPWCH)0x0) {
    local_8 = (LPSTR)0x0;
  }
  else {
    WVar1 = *lpWideCharStr;
    pWVar2 = lpWideCharStr;
    while (WVar1 != L'\0') {
      do {
        pWVar3 = pWVar2;
        pWVar2 = pWVar3 + 1;
      } while (*pWVar2 != L'\0');
      pWVar2 = pWVar3 + 2;
      WVar1 = *pWVar2;
    }
    iVar4 = ((int)pWVar2 - (int)lpWideCharStr >> 1) + 1;
    _Size = WideCharToMultiByte(0,0,lpWideCharStr,iVar4,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
    if ((_Size == 0) || (local_8 = (LPSTR)__malloc_crt(_Size), local_8 == (LPSTR)0x0)) {
      FreeEnvironmentStringsW(lpWideCharStr);
      local_8 = (LPSTR)0x0;
    }
    else {
      iVar4 = WideCharToMultiByte(0,0,lpWideCharStr,iVar4,local_8,_Size,(LPCSTR)0x0,(LPBOOL)0x0);
      if (iVar4 == 0) {
        _free(local_8);
        local_8 = (LPSTR)0x0;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
    }
  }
  return local_8;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2010 Release

void __cdecl ___security_init_cookie(void)

{
  DWORD DVar1;
  DWORD DVar2;
  DWORD DVar3;
  uint uVar4;
  LARGE_INTEGER local_14;
  _FILETIME local_c;
  
  local_c.dwLowDateTime = 0;
  local_c.dwHighDateTime = 0;
  if ((DAT_0043d030 == 0xbb40e64e) || ((DAT_0043d030 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_c);
    uVar4 = local_c.dwHighDateTime ^ local_c.dwLowDateTime;
    DVar1 = GetCurrentProcessId();
    DVar2 = GetCurrentThreadId();
    DVar3 = GetTickCount();
    QueryPerformanceCounter(&local_14);
    DAT_0043d030 = uVar4 ^ DVar1 ^ DVar2 ^ DVar3 ^ local_14.s.HighPart ^ local_14.s.LowPart;
    if (DAT_0043d030 == 0xbb40e64e) {
      DAT_0043d030 = 0xbb40e64f;
    }
    else if ((DAT_0043d030 & 0xffff0000) == 0) {
      DAT_0043d030 = DAT_0043d030 | (DAT_0043d030 | 0x4711) << 0x10;
    }
    DAT_0043d034 = ~DAT_0043d030;
  }
  else {
    DAT_0043d034 = ~DAT_0043d030;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004091de(void)

{
  _DAT_0047fe84 = 0;
  return;
}



// Library Function - Single Match
//  __isatty
// 
// Library: Visual Studio 2010 Release

int __cdecl __isatty(int _FileHandle)

{
  int *piVar1;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_0047fe88)) {
      return (int)*(char *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
             0x40;
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_00406231();
  }
  return 0;
}



// Library Function - Single Match
//  __wctomb_s_l
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl
__wctomb_s_l(int *_SizeConverted,char *_MbCh,size_t _SizeInBytes,wchar_t _WCh,_locale_t _Locale)

{
  char *lpMultiByteStr;
  size_t _Size;
  int iVar1;
  int *piVar2;
  DWORD DVar3;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _Size = _SizeInBytes;
  lpMultiByteStr = _MbCh;
  if ((_MbCh == (char *)0x0) && (_SizeInBytes != 0)) {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = 0;
    }
LAB_00409260:
    iVar1 = 0;
  }
  else {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = -1;
    }
    if (0x7fffffff < _SizeInBytes) {
      piVar2 = __errno();
      *piVar2 = 0x16;
      FUN_00406231();
      return 0x16;
    }
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
    if (*(int *)(local_14[0] + 0x14) == 0) {
      if ((ushort)_WCh < 0x100) {
        if (lpMultiByteStr != (char *)0x0) {
          if (_Size == 0) goto LAB_004092ec;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_0040931b:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_00409260;
      }
      if ((lpMultiByteStr != (char *)0x0) && (_Size != 0)) {
        _memset(lpMultiByteStr,0,_Size);
      }
    }
    else {
      _MbCh = (char *)0x0;
      iVar1 = WideCharToMultiByte(*(UINT *)(local_14[0] + 4),0,&_WCh,1,lpMultiByteStr,_Size,
                                  (LPCSTR)0x0,(LPBOOL)&_MbCh);
      if (iVar1 == 0) {
        DVar3 = GetLastError();
        if (DVar3 == 0x7a) {
          if ((lpMultiByteStr != (char *)0x0) && (_Size != 0)) {
            _memset(lpMultiByteStr,0,_Size);
          }
LAB_004092ec:
          piVar2 = __errno();
          *piVar2 = 0x22;
          FUN_00406231();
          if (local_8 == '\0') {
            return 0x22;
          }
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
          return 0x22;
        }
      }
      else if (_MbCh == (char *)0x0) {
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = iVar1;
        }
        goto LAB_0040931b;
      }
    }
    piVar2 = __errno();
    *piVar2 = 0x2a;
    piVar2 = __errno();
    iVar1 = *piVar2;
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  return iVar1;
}



// Library Function - Single Match
//  _wctomb_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wctomb_s(int *_SizeConverted,char *_MbCh,rsize_t _SizeInBytes,wchar_t _WCh)

{
  errno_t eVar1;
  
  eVar1 = __wctomb_s_l(_SizeConverted,_MbCh,_SizeInBytes,_WCh,(_locale_t)0x0);
  return eVar1;
}



// Library Function - Single Match
//  __aulldvrm
// 
// Library: Visual Studio

undefined8 __aulldvrm(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  uVar3 = param_1;
  uVar8 = param_4;
  uVar6 = param_2;
  uVar9 = param_3;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar5 = uVar8 >> 1;
      uVar9 = uVar9 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar8 = uVar5;
      uVar6 = uVar7;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar9;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar8 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar8)) ||
       ((param_2 <= uVar8 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  return CONCAT44(uVar3,iVar4);
}



// Library Function - Single Match
//  __local_unwind4
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __cdecl __local_unwind4(uint *param_1,int param_2,uint param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  void *pvStack_28;
  undefined *puStack_24;
  uint local_20;
  uint uStack_1c;
  int iStack_18;
  uint *puStack_14;
  
  puStack_14 = param_1;
  iStack_18 = param_2;
  uStack_1c = param_3;
  puStack_24 = &LAB_004094e0;
  pvStack_28 = ExceptionList;
  local_20 = DAT_0043d030 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_0040b5f4();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



void FUN_00409526(int param_1)

{
  __local_unwind4(*(uint **)(param_1 + 0x28),*(int *)(param_1 + 0x18),*(uint *)(param_1 + 0x1c));
  return;
}



// Library Function - Single Match
//  @_EH4_CallFilterFunc@8
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_CallFilterFunc_8(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  @_EH4_TransferToHandler@8
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_TransferToHandler_8(undefined *UNRECOVERED_JUMPTABLE)

{
  __NLG_Notify(1);
                    // WARNING: Could not recover jumptable at 0x00409570. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  @_EH4_GlobalUnwind2@8
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_GlobalUnwind2_8(PVOID param_1,PEXCEPTION_RECORD param_2)

{
  RtlUnwind(param_1,(PVOID)0x409586,param_2,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  @_EH4_LocalUnwind@16
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_LocalUnwind_16(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  __local_unwind4(param_4,param_1,param_2);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __write_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __write_nolock(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  char cVar1;
  WCHAR WVar2;
  wchar_t *pwVar3;
  wint_t wVar4;
  ulong *puVar5;
  int *piVar6;
  int iVar7;
  _ptiddata p_Var8;
  BOOL BVar9;
  DWORD nNumberOfBytesToWrite;
  WCHAR *pWVar10;
  int iVar11;
  uint uVar12;
  int unaff_EBX;
  WCHAR *pWVar13;
  uint uVar14;
  int iVar15;
  ushort uVar16;
  uint local_1ae8;
  WCHAR *local_1ae4;
  int *local_1ae0;
  uint local_1adc;
  WCHAR *local_1ad8;
  int local_1ad4;
  WCHAR *local_1ad0;
  uint local_1acc;
  char local_1ac5;
  uint local_1ac4;
  DWORD local_1ac0;
  WCHAR local_1abc [852];
  CHAR local_1414 [3416];
  WCHAR local_6bc [854];
  undefined local_10;
  char local_f;
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  local_1ad0 = (WCHAR *)_Buf;
  local_1acc = 0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) goto LAB_00409c91;
  if (_Buf == (void *)0x0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_00406231();
    goto LAB_00409c91;
  }
  piVar6 = &DAT_0047fea0 + (_FileHandle >> 5);
  iVar11 = (_FileHandle & 0x1fU) * 0x40;
  local_1ac5 = (char)(*(char *)(*piVar6 + 0x24 + iVar11) * '\x02') >> 1;
  local_1ae0 = piVar6;
  if (((local_1ac5 == '\x02') || (local_1ac5 == '\x01')) && ((~_MaxCharCount & 1) == 0)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_00406231();
    goto LAB_00409c91;
  }
  if ((*(byte *)(*piVar6 + 4 + iVar11) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0x200000000,unaff_EBX);
  }
  iVar7 = __isatty(_FileHandle);
  if ((iVar7 == 0) || ((*(byte *)(iVar11 + 4 + *piVar6) & 0x80) == 0)) {
LAB_00409922:
    if ((*(byte *)(*piVar6 + 4 + iVar11) & 0x80) == 0) {
      BVar9 = WriteFile(*(HANDLE *)(*piVar6 + iVar11),local_1ad0,_MaxCharCount,&local_1adc,
                        (LPOVERLAPPED)0x0);
      if (BVar9 == 0) {
LAB_00409c03:
        local_1ac0 = GetLastError();
      }
      else {
        local_1ac0 = 0;
        local_1acc = local_1adc;
      }
LAB_00409c0f:
      if (local_1acc != 0) goto LAB_00409c91;
      goto LAB_00409c18;
    }
    local_1ac0 = 0;
    if (local_1ac5 == '\0') {
      pWVar13 = local_1ad0;
      if (_MaxCharCount == 0) goto LAB_00409c4e;
      do {
        uVar14 = 0;
        uVar12 = (int)pWVar13 - (int)local_1ad0;
        pWVar10 = local_1abc;
        do {
          if (_MaxCharCount <= uVar12) break;
          cVar1 = *(char *)pWVar13;
          pWVar13 = (WCHAR *)((int)pWVar13 + 1);
          uVar12 = uVar12 + 1;
          if (cVar1 == '\n') {
            local_1ad4 = local_1ad4 + 1;
            *(char *)pWVar10 = '\r';
            pWVar10 = (WCHAR *)((int)pWVar10 + 1);
            uVar14 = uVar14 + 1;
          }
          *(char *)pWVar10 = cVar1;
          pWVar10 = (WCHAR *)((int)pWVar10 + 1);
          uVar14 = uVar14 + 1;
          local_1ae4 = pWVar13;
        } while (uVar14 < 0x13ff);
        BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),local_1abc,
                          (int)pWVar10 - (int)local_1abc,&local_1adc,(LPOVERLAPPED)0x0);
        if (BVar9 == 0) goto LAB_00409c03;
        local_1acc = local_1acc + local_1adc;
      } while (((int)pWVar10 - (int)local_1abc <= (int)local_1adc) &&
              ((uint)((int)pWVar13 - (int)local_1ad0) < _MaxCharCount));
      goto LAB_00409c0f;
    }
    if (local_1ac5 == '\x02') {
      pWVar13 = local_1ad0;
      if (_MaxCharCount != 0) {
        do {
          local_1ac4 = 0;
          uVar12 = (int)pWVar13 - (int)local_1ad0;
          pWVar10 = local_1abc;
          do {
            if (_MaxCharCount <= uVar12) break;
            WVar2 = *pWVar13;
            pWVar13 = pWVar13 + 1;
            uVar12 = uVar12 + 2;
            if (WVar2 == L'\n') {
              local_1ad4 = local_1ad4 + 2;
              *pWVar10 = L'\r';
              pWVar10 = pWVar10 + 1;
              local_1ac4 = local_1ac4 + 2;
            }
            local_1ac4 = local_1ac4 + 2;
            *pWVar10 = WVar2;
            pWVar10 = pWVar10 + 1;
            local_1ae4 = pWVar13;
          } while (local_1ac4 < 0x13fe);
          BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),local_1abc,
                            (int)pWVar10 - (int)local_1abc,&local_1adc,(LPOVERLAPPED)0x0);
          if (BVar9 == 0) goto LAB_00409c03;
          local_1acc = local_1acc + local_1adc;
        } while (((int)pWVar10 - (int)local_1abc <= (int)local_1adc) &&
                ((uint)((int)pWVar13 - (int)local_1ad0) < _MaxCharCount));
        goto LAB_00409c0f;
      }
    }
    else {
      local_1ad8 = local_1ad0;
      if (_MaxCharCount != 0) {
        do {
          local_1ac4 = 0;
          uVar12 = (int)local_1ad8 - (int)local_1ad0;
          pWVar13 = local_6bc;
          do {
            if (_MaxCharCount <= uVar12) break;
            WVar2 = *local_1ad8;
            local_1ad8 = local_1ad8 + 1;
            uVar12 = uVar12 + 2;
            if (WVar2 == L'\n') {
              *pWVar13 = L'\r';
              pWVar13 = pWVar13 + 1;
              local_1ac4 = local_1ac4 + 2;
            }
            local_1ac4 = local_1ac4 + 2;
            *pWVar13 = WVar2;
            pWVar13 = pWVar13 + 1;
          } while (local_1ac4 < 0x6a8);
          iVar15 = 0;
          iVar7 = WideCharToMultiByte(0xfde9,0,local_6bc,((int)pWVar13 - (int)local_6bc) / 2,
                                      local_1414,0xd55,(LPCSTR)0x0,(LPBOOL)0x0);
          if (iVar7 == 0) goto LAB_00409c03;
          do {
            BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),local_1414 + iVar15,iVar7 - iVar15,
                              &local_1adc,(LPOVERLAPPED)0x0);
            if (BVar9 == 0) {
              local_1ac0 = GetLastError();
              break;
            }
            iVar15 = iVar15 + local_1adc;
          } while (iVar15 < iVar7);
        } while ((iVar7 <= iVar15) &&
                (local_1acc = (int)local_1ad8 - (int)local_1ad0, local_1acc < _MaxCharCount));
        goto LAB_00409c0f;
      }
    }
  }
  else {
    p_Var8 = __getptd();
    pwVar3 = p_Var8->ptlocinfo->lc_category[0].wlocale;
    BVar9 = GetConsoleMode(*(HANDLE *)(iVar11 + *piVar6),(LPDWORD)&local_1ae4);
    if ((BVar9 == 0) || ((pwVar3 == (wchar_t *)0x0 && (local_1ac5 == '\0')))) goto LAB_00409922;
    local_1ae4 = (WCHAR *)GetConsoleCP();
    local_1ad8 = (WCHAR *)0x0;
    if (_MaxCharCount != 0) {
      local_1ac4 = 0;
      pWVar13 = local_1ad0;
      do {
        piVar6 = local_1ae0;
        if (local_1ac5 == '\0') {
          cVar1 = *(char *)pWVar13;
          local_1ae8 = (uint)(cVar1 == '\n');
          iVar7 = *local_1ae0 + iVar11;
          if (*(int *)(iVar7 + 0x38) == 0) {
            iVar7 = _isleadbyte(CONCAT22(cVar1 >> 7,(short)cVar1));
            if (iVar7 == 0) {
              uVar16 = 1;
              pWVar10 = pWVar13;
              goto LAB_00409789;
            }
            if ((char *)((int)local_1ad0 + (_MaxCharCount - (int)pWVar13)) < (char *)0x2) {
              local_1acc = local_1acc + 1;
              *(undefined *)(iVar11 + 0x34 + *piVar6) = *(undefined *)pWVar13;
              *(undefined4 *)(iVar11 + 0x38 + *piVar6) = 1;
              break;
            }
            iVar7 = _mbtowc((wchar_t *)&local_1ac0,(char *)pWVar13,2);
            if (iVar7 == -1) break;
            pWVar13 = (WCHAR *)((int)pWVar13 + 1);
            local_1ac4 = local_1ac4 + 1;
          }
          else {
            local_10 = *(undefined *)(iVar7 + 0x34);
            *(undefined4 *)(iVar7 + 0x38) = 0;
            uVar16 = 2;
            pWVar10 = (WCHAR *)&local_10;
            local_f = cVar1;
LAB_00409789:
            iVar7 = _mbtowc((wchar_t *)&local_1ac0,(char *)pWVar10,(uint)uVar16);
            if (iVar7 == -1) break;
          }
          pWVar13 = (WCHAR *)((int)pWVar13 + 1);
          local_1ac4 = local_1ac4 + 1;
          nNumberOfBytesToWrite =
               WideCharToMultiByte((UINT)local_1ae4,0,(LPCWSTR)&local_1ac0,1,&local_10,5,(LPCSTR)0x0
                                   ,(LPBOOL)0x0);
          if (nNumberOfBytesToWrite == 0) break;
          BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),&local_10,nNumberOfBytesToWrite,
                            (LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
          if (BVar9 == 0) goto LAB_00409c03;
          local_1acc = local_1ac4 + local_1ad4;
          if ((int)local_1ad8 < (int)nNumberOfBytesToWrite) break;
          if (local_1ae8 != 0) {
            local_10 = 0xd;
            BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),&local_10,1,(LPDWORD)&local_1ad8,
                              (LPOVERLAPPED)0x0);
            if (BVar9 == 0) goto LAB_00409c03;
            if ((int)local_1ad8 < 1) break;
            local_1ad4 = local_1ad4 + 1;
            local_1acc = local_1acc + 1;
          }
        }
        else {
          if ((local_1ac5 == '\x01') || (local_1ac5 == '\x02')) {
            local_1ac0 = (DWORD)(ushort)*pWVar13;
            local_1ae8 = (uint)(local_1ac0 == 10);
            pWVar13 = pWVar13 + 1;
            local_1ac4 = local_1ac4 + 2;
          }
          if ((local_1ac5 == '\x01') || (local_1ac5 == '\x02')) {
            wVar4 = __putwch_nolock((wchar_t)local_1ac0);
            if (wVar4 != (wint_t)local_1ac0) goto LAB_00409c03;
            local_1acc = local_1acc + 2;
            if (local_1ae8 != 0) {
              local_1ac0 = 0xd;
              wVar4 = __putwch_nolock(L'\r');
              if (wVar4 != (wint_t)local_1ac0) goto LAB_00409c03;
              local_1acc = local_1acc + 1;
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
      } while (local_1ac4 < _MaxCharCount);
      goto LAB_00409c0f;
    }
LAB_00409c18:
    if (local_1ac0 != 0) {
      if (local_1ac0 == 5) {
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        __dosmaperr(local_1ac0);
      }
      goto LAB_00409c91;
    }
  }
LAB_00409c4e:
  if (((*(byte *)(iVar11 + 4 + *local_1ae0) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    piVar6 = __errno();
    *piVar6 = 0x1c;
    puVar5 = ___doserrno();
    *puVar5 = 0;
  }
LAB_00409c91:
  iVar11 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar11;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __write
// 
// Library: Visual Studio 2010 Release

int __cdecl __write(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_0047fe88)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_00409d6b();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_00406231();
  }
  return -1;
}



void FUN_00409d6b(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// Library Function - Single Match
//  __calloc_impl
// 
// Library: Visual Studio 2010 Release

LPVOID __cdecl __calloc_impl(uint param_1,uint param_2,undefined4 *param_3)

{
  int *piVar1;
  LPVOID pvVar2;
  int iVar3;
  uint dwBytes;
  
  if ((param_1 != 0) && (0xffffffe0 / param_1 < param_2)) {
    piVar1 = __errno();
    *piVar1 = 0xc;
    return (LPVOID)0x0;
  }
  dwBytes = param_1 * param_2;
  if (dwBytes == 0) {
    dwBytes = 1;
  }
  do {
    pvVar2 = (LPVOID)0x0;
    if ((dwBytes < 0xffffffe1) &&
       (pvVar2 = HeapAlloc(hHeap_0047fd38,8,dwBytes), pvVar2 != (LPVOID)0x0)) {
      return pvVar2;
    }
    if (DAT_0047fd3c == 0) {
      if (param_3 == (undefined4 *)0x0) {
        return pvVar2;
      }
      *param_3 = 0xc;
      return pvVar2;
    }
    iVar3 = __callnewh(dwBytes);
  } while (iVar3 != 0);
  if (param_3 != (undefined4 *)0x0) {
    *param_3 = 0xc;
  }
  return (LPVOID)0x0;
}



// Library Function - Single Match
//  _realloc
// 
// Library: Visual Studio 2010 Release

void * __cdecl _realloc(void *_Memory,size_t _NewSize)

{
  void *pvVar1;
  LPVOID pvVar2;
  int iVar3;
  int *piVar4;
  DWORD DVar5;
  
  if (_Memory == (void *)0x0) {
    pvVar1 = _malloc(_NewSize);
    return pvVar1;
  }
  if (_NewSize == 0) {
    _free(_Memory);
  }
  else {
    do {
      if (0xffffffe0 < _NewSize) {
        __callnewh(_NewSize);
        piVar4 = __errno();
        *piVar4 = 0xc;
        return (void *)0x0;
      }
      if (_NewSize == 0) {
        _NewSize = 1;
      }
      pvVar2 = HeapReAlloc(hHeap_0047fd38,0,_Memory,_NewSize);
      if (pvVar2 != (LPVOID)0x0) {
        return pvVar2;
      }
      if (DAT_0047fd3c == 0) {
        piVar4 = __errno();
        DVar5 = GetLastError();
        iVar3 = __get_errno_from_oserr(DVar5);
        *piVar4 = iVar3;
        return (void *)0x0;
      }
      iVar3 = __callnewh(_NewSize);
    } while (iVar3 != 0);
    piVar4 = __errno();
    DVar5 = GetLastError();
    iVar3 = __get_errno_from_oserr(DVar5);
    *piVar4 = iVar3;
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __fclose_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __fclose_nolock(FILE *_File)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00406231();
    iVar3 = -1;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x83) != 0) {
      iVar3 = __flush(_File);
      __freebuf(_File);
      iVar2 = __fileno(_File);
      iVar2 = __close(iVar2);
      if (iVar2 < 0) {
        iVar3 = -1;
      }
      else if (_File->_tmpfname != (char *)0x0) {
        _free(_File->_tmpfname);
        _File->_tmpfname = (char *)0x0;
      }
    }
    _File->_flag = 0;
  }
  return iVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

int __cdecl FUN_00409f0f(FILE *param_1)

{
  int *piVar1;
  int local_20;
  
  local_20 = -1;
  if (param_1 == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00406231();
    local_20 = -1;
  }
  else if ((*(byte *)&param_1->_flag & 0x40) == 0) {
    __lock_file(param_1);
    local_20 = __fclose_nolock(param_1);
    FUN_00409f7b();
  }
  else {
    param_1->_flag = 0;
  }
  return local_20;
}



void FUN_00409f7b(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __commit
// 
// Library: Visual Studio 2010 Release

int __cdecl __commit(int _FileHandle)

{
  int *piVar1;
  HANDLE hFile;
  BOOL BVar2;
  ulong *puVar3;
  int iVar4;
  DWORD local_20;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_0047fe88)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_0047fea0)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_0047fea0)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_0040a03c;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_0040a03c:
        FUN_0040a054();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_00406231();
  }
  return -1;
}



void FUN_0040a054(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// Library Function - Single Match
//  __lseeki64_nolock
// 
// Library: Visual Studio 2010 Release

longlong __cdecl __lseeki64_nolock(int _FileHandle,longlong _Offset,int _Origin)

{
  byte *pbVar1;
  HANDLE hFile;
  int *piVar2;
  DWORD DVar3;
  DWORD DVar4;
  LONG in_stack_00000008;
  LONG local_8;
  
  local_8 = (LONG)_Offset;
  hFile = (HANDLE)__get_osfhandle(_FileHandle);
  if (hFile == (HANDLE)0xffffffff) {
    piVar2 = __errno();
    *piVar2 = 9;
LAB_0040a08d:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,in_stack_00000008,&local_8,_Offset._4_4_);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_0040a08d;
      }
    }
    pbVar1 = (byte *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
    *pbVar1 = *pbVar1 & 0xfd;
  }
  return CONCAT44(local_8,DVar3);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __lseeki64
// 
// Library: Visual Studio 2010 Release

longlong __cdecl __lseeki64(int _FileHandle,longlong _Offset,int _Origin)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int in_stack_ffffffc8;
  undefined8 local_28;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_0047fe88)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,in_stack_ffffffc8);
        }
        FUN_0040a1c1();
        goto LAB_0040a1bb;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_00406231();
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_0040a1bb:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_0040a1c1(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Library: Visual Studio 2010 Release

void __cdecl __getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_0047f208 = _DAT_0047f208 + 1;
  pcVar1 = (char *)__malloc_crt(0x1000);
  _File->_base = pcVar1;
  if (pcVar1 == (char *)0x0) {
    _File->_flag = _File->_flag | 4;
    _File->_base = (char *)&_File->_charbuf;
    _File->_bufsiz = 2;
  }
  else {
    _File->_flag = _File->_flag | 8;
    _File->_bufsiz = 0x1000;
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return;
}



// Library Function - Single Match
//  __read_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __read_nolock(int _FileHandle,void *_DstBuf,uint _MaxCharCount)

{
  byte *pbVar1;
  uint uVar2;
  byte bVar3;
  char cVar4;
  ulong *puVar5;
  int *piVar6;
  uint uVar7;
  short *psVar8;
  BOOL BVar9;
  DWORD DVar10;
  ulong uVar11;
  short *psVar12;
  int iVar13;
  int iVar14;
  int unaff_EDI;
  bool bVar15;
  longlong lVar16;
  short sVar17;
  uint local_1c;
  int local_18;
  short *local_14;
  short *local_10;
  undefined2 local_c;
  char local_6;
  char local_5;
  
  uVar2 = _MaxCharCount;
  local_18 = -2;
  if (_FileHandle == -2) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    return -1;
  }
  if ((_FileHandle < 0) || (uNumber_0047fe88 <= (uint)_FileHandle)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    FUN_00406231();
    return -1;
  }
  piVar6 = &DAT_0047fea0 + (_FileHandle >> 5);
  iVar14 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar6 + 4 + iVar14);
  if ((bVar3 & 1) == 0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    goto LAB_0040a313;
  }
  if (_MaxCharCount < 0x80000000) {
    local_10 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar6 + 0x24 + iVar14) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) == 0) goto LAB_0040a301;
        uVar7 = _MaxCharCount >> 1;
        _MaxCharCount = 4;
        if (3 < uVar7) {
          _MaxCharCount = uVar7;
        }
        psVar12 = (short *)__malloc_crt(_MaxCharCount);
        local_14 = psVar12;
        if (psVar12 == (short *)0x0) {
          piVar6 = __errno();
          *piVar6 = 0xc;
          puVar5 = ___doserrno();
          *puVar5 = 8;
          return -1;
        }
        lVar16 = __lseeki64_nolock(_FileHandle,0x100000000,unaff_EDI);
        iVar13 = *piVar6;
        *(int *)(iVar14 + 0x28 + iVar13) = (int)lVar16;
        *(int *)(iVar14 + 0x2c + iVar13) = (int)((ulonglong)lVar16 >> 0x20);
      }
      else {
        if (local_6 == '\x02') {
          if ((~_MaxCharCount & 1) == 0) goto LAB_0040a301;
          _MaxCharCount = _MaxCharCount & 0xfffffffe;
        }
        local_14 = (short *)_DstBuf;
        psVar12 = (short *)_DstBuf;
      }
      psVar8 = psVar12;
      uVar7 = _MaxCharCount;
      if ((((*(byte *)(*piVar6 + iVar14 + 4) & 0x48) != 0) &&
          (cVar4 = *(char *)(*piVar6 + iVar14 + 5), cVar4 != '\n')) && (_MaxCharCount != 0)) {
        uVar7 = _MaxCharCount - 1;
        *(char *)psVar12 = cVar4;
        psVar8 = (short *)((int)psVar12 + 1);
        local_10 = (short *)0x1;
        *(undefined *)(iVar14 + 5 + *piVar6) = 10;
        if (((local_6 != '\0') && (cVar4 = *(char *)(iVar14 + 0x25 + *piVar6), cVar4 != '\n')) &&
           (uVar7 != 0)) {
          *(char *)psVar8 = cVar4;
          psVar8 = psVar12 + 1;
          uVar7 = _MaxCharCount - 2;
          local_10 = (short *)0x2;
          *(undefined *)(iVar14 + 0x25 + *piVar6) = 10;
          if (((local_6 == '\x01') && (cVar4 = *(char *)(iVar14 + 0x26 + *piVar6), cVar4 != '\n'))
             && (uVar7 != 0)) {
            *(char *)psVar8 = cVar4;
            psVar8 = (short *)((int)psVar12 + 3);
            local_10 = (short *)0x3;
            *(undefined *)(iVar14 + 0x26 + *piVar6) = 10;
            uVar7 = _MaxCharCount - 3;
          }
        }
      }
      _MaxCharCount = uVar7;
      BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),psVar8,_MaxCharCount,&local_1c,
                       (LPOVERLAPPED)0x0);
      if (((BVar9 == 0) || ((int)local_1c < 0)) || (_MaxCharCount < local_1c)) {
        uVar11 = GetLastError();
        if (uVar11 != 5) {
          if (uVar11 == 0x6d) {
            local_18 = 0;
            goto LAB_0040a620;
          }
          goto LAB_0040a615;
        }
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        local_10 = (short *)((int)local_10 + local_1c);
        pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
        if ((*pbVar1 & 0x80) == 0) goto LAB_0040a620;
        if (local_6 == '\x02') {
          if ((local_1c == 0) || (*psVar12 != 10)) {
            *pbVar1 = *pbVar1 & 0xfb;
          }
          else {
            *pbVar1 = *pbVar1 | 4;
          }
          local_10 = (short *)((int)local_10 + (int)local_14);
          _MaxCharCount = (uint)local_14;
          psVar12 = local_14;
          if (local_14 < local_10) {
            do {
              sVar17 = *(short *)_MaxCharCount;
              if (sVar17 == 0x1a) {
                pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
                if ((*pbVar1 & 0x40) == 0) {
                  *pbVar1 = *pbVar1 | 2;
                }
                else {
                  *psVar12 = *(short *)_MaxCharCount;
                  psVar12 = psVar12 + 1;
                }
                break;
              }
              if (sVar17 == 0xd) {
                if (_MaxCharCount < local_10 + -1) {
                  if (*(short *)(_MaxCharCount + 2) == 10) {
                    uVar2 = _MaxCharCount + 4;
                    goto LAB_0040a6c0;
                  }
LAB_0040a753:
                  _MaxCharCount = _MaxCharCount + 2;
                  sVar17 = 0xd;
LAB_0040a755:
                  *psVar12 = sVar17;
                }
                else {
                  uVar2 = _MaxCharCount + 2;
                  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_c,2,&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                  goto LAB_0040a753;
                  if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                    if ((psVar12 == local_14) && (local_c == 10)) goto LAB_0040a6c0;
                    __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                    if (local_c == 10) goto LAB_0040a75c;
                    goto LAB_0040a753;
                  }
                  if (local_c == 10) {
LAB_0040a6c0:
                    _MaxCharCount = uVar2;
                    sVar17 = 10;
                    goto LAB_0040a755;
                  }
                  *psVar12 = 0xd;
                  *(undefined *)(iVar14 + 5 + *piVar6) = (undefined)local_c;
                  *(undefined *)(iVar14 + 0x25 + *piVar6) = local_c._1_1_;
                  *(undefined *)(iVar14 + 0x26 + *piVar6) = 10;
                  _MaxCharCount = uVar2;
                }
                psVar12 = psVar12 + 1;
                uVar2 = _MaxCharCount;
              }
              else {
                *psVar12 = sVar17;
                psVar12 = psVar12 + 1;
                uVar2 = _MaxCharCount + 2;
              }
LAB_0040a75c:
              _MaxCharCount = uVar2;
            } while (_MaxCharCount < local_10);
          }
          local_10 = (short *)((int)psVar12 - (int)local_14);
          goto LAB_0040a620;
        }
        if ((local_1c == 0) || (*(char *)psVar12 != '\n')) {
          *pbVar1 = *pbVar1 & 0xfb;
        }
        else {
          *pbVar1 = *pbVar1 | 4;
        }
        local_10 = (short *)((int)local_10 + (int)local_14);
        _MaxCharCount = (uint)local_14;
        psVar12 = local_14;
        if (local_14 < local_10) {
          do {
            cVar4 = *(char *)_MaxCharCount;
            if (cVar4 == '\x1a') {
              pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
              if ((*pbVar1 & 0x40) == 0) {
                *pbVar1 = *pbVar1 | 2;
              }
              else {
                *(undefined *)psVar12 = *(undefined *)_MaxCharCount;
                psVar12 = (short *)((int)psVar12 + 1);
              }
              break;
            }
            if (cVar4 == '\r') {
              if (_MaxCharCount < (undefined *)((int)local_10 + -1)) {
                if (*(char *)(_MaxCharCount + 1) == '\n') {
                  uVar7 = _MaxCharCount + 2;
                  goto LAB_0040a4a0;
                }
LAB_0040a517:
                _MaxCharCount = _MaxCharCount + 1;
                *(undefined *)psVar12 = 0xd;
              }
              else {
                uVar7 = _MaxCharCount + 1;
                BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_5,1,&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                goto LAB_0040a517;
                if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                  if ((psVar12 == local_14) && (local_5 == '\n')) goto LAB_0040a4a0;
                  __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                  if (local_5 == '\n') goto LAB_0040a51b;
                  goto LAB_0040a517;
                }
                if (local_5 == '\n') {
LAB_0040a4a0:
                  _MaxCharCount = uVar7;
                  *(undefined *)psVar12 = 10;
                }
                else {
                  *(undefined *)psVar12 = 0xd;
                  *(char *)(iVar14 + 5 + *piVar6) = local_5;
                  _MaxCharCount = uVar7;
                }
              }
              psVar12 = (short *)((int)psVar12 + 1);
              uVar7 = _MaxCharCount;
            }
            else {
              *(char *)psVar12 = cVar4;
              psVar12 = (short *)((int)psVar12 + 1);
              uVar7 = _MaxCharCount + 1;
            }
LAB_0040a51b:
            _MaxCharCount = uVar7;
          } while (_MaxCharCount < local_10);
        }
        local_10 = (short *)((int)psVar12 - (int)local_14);
        if ((local_6 != '\x01') || (local_10 == (short *)0x0)) goto LAB_0040a620;
        bVar3 = *(byte *)(short *)((int)psVar12 + -1);
        if ((char)bVar3 < '\0') {
          iVar13 = 1;
          psVar12 = (short *)((int)psVar12 + -1);
          while ((((&DAT_0043dd40)[bVar3] == '\0' && (iVar13 < 5)) && (local_14 <= psVar12))) {
            psVar12 = (short *)((int)psVar12 + -1);
            bVar3 = *(byte *)psVar12;
            iVar13 = iVar13 + 1;
          }
          if ((char)(&DAT_0043dd40)[*(byte *)psVar12] == 0) {
            piVar6 = __errno();
            *piVar6 = 0x2a;
            goto LAB_0040a61c;
          }
          if ((char)(&DAT_0043dd40)[*(byte *)psVar12] + 1 == iVar13) {
            psVar12 = (short *)((int)psVar12 + iVar13);
          }
          else if ((*(byte *)(*piVar6 + 4 + iVar14) & 0x48) == 0) {
            __lseeki64_nolock(_FileHandle,CONCAT44(1,-iVar13 >> 0x1f),unaff_EDI);
          }
          else {
            psVar8 = (short *)((int)psVar12 + 1);
            *(byte *)(*piVar6 + 5 + iVar14) = *(byte *)psVar12;
            if (1 < iVar13) {
              *(undefined *)(iVar14 + 0x25 + *piVar6) = *(undefined *)psVar8;
              psVar8 = psVar12 + 1;
            }
            if (iVar13 == 3) {
              *(undefined *)(iVar14 + 0x26 + *piVar6) = *(undefined *)psVar8;
              psVar8 = (short *)((int)psVar8 + 1);
            }
            psVar12 = (short *)((int)psVar8 - iVar13);
          }
        }
        iVar13 = (int)psVar12 - (int)local_14;
        local_10 = (short *)MultiByteToWideChar(0xfde9,0,(LPCSTR)local_14,iVar13,(LPWSTR)_DstBuf,
                                                uVar2 >> 1);
        if (local_10 != (short *)0x0) {
          bVar15 = local_10 != (short *)iVar13;
          local_10 = (short *)((int)local_10 * 2);
          *(uint *)(iVar14 + 0x30 + *piVar6) = (uint)bVar15;
          goto LAB_0040a620;
        }
        uVar11 = GetLastError();
LAB_0040a615:
        __dosmaperr(uVar11);
      }
LAB_0040a61c:
      local_18 = -1;
LAB_0040a620:
      if (local_14 != (short *)_DstBuf) {
        _free(local_14);
      }
      if (local_18 == -2) {
        return (int)local_10;
      }
      return local_18;
    }
  }
LAB_0040a301:
  puVar5 = ___doserrno();
  *puVar5 = 0;
  piVar6 = __errno();
  *piVar6 = 0x16;
LAB_0040a313:
  FUN_00406231();
  return -1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __read
// 
// Library: Visual Studio 2010 Release

int __cdecl __read(int _FileHandle,void *_DstBuf,uint _MaxCharCount)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    return -1;
  }
  if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_0047fe88)) {
    iVar3 = (_FileHandle & 0x1fU) * 0x40;
    if ((*(byte *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
      if (_MaxCharCount < 0x80000000) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_0040a8b9();
        return local_20;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_0040a819;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_0040a819:
  FUN_00406231();
  return -1;
}



void FUN_0040a8b9(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2010 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  int iVar2;
  
  iVar2 = FUN_004070f6();
  if (iVar2 != 0) {
    _raise(0x16);
  }
  if ((DAT_0043de40 & 2) != 0) {
    __call_reportfault(3,0x40000015,1);
  }
  __exit(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  __msize
// 
// Library: Visual Studio 2010 Release

size_t __cdecl __msize(void *_Memory)

{
  int *piVar1;
  SIZE_T SVar2;
  
  if (_Memory == (void *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00406231();
    return 0xffffffff;
  }
  SVar2 = HeapSize(hHeap_0047fd38,0,_Memory);
  return SVar2;
}



// Library Function - Single Match
//  ___crtMessageBoxW
// 
// Library: Visual Studio 2010 Release

int __cdecl ___crtMessageBoxW(LPCWSTR _LpText,LPCWSTR _LpCaption,UINT _UType)

{
  HMODULE hModule;
  FARPROC pFVar1;
  code *pcVar2;
  code *pcVar3;
  int iVar4;
  undefined local_28 [4];
  LPCWSTR local_24;
  LPCWSTR local_20;
  PVOID local_1c;
  int local_18;
  undefined local_14 [8];
  byte local_c;
  uint local_8;
  
  local_8 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  local_24 = _LpText;
  local_20 = _LpCaption;
  local_1c = (PVOID)FUN_004072fb();
  local_18 = 0;
  if (Ptr_0047fe68 == (PVOID)0x0) {
    hModule = LoadLibraryW(L"USER32.DLL");
    if ((hModule == (HMODULE)0x0) ||
       (pFVar1 = GetProcAddress(hModule,"MessageBoxW"), pFVar1 == (FARPROC)0x0)) goto LAB_0040aa8d;
    Ptr_0047fe68 = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,"GetActiveWindow");
    DAT_0047fe6c = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,"GetLastActivePopup");
    DAT_0047fe70 = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,"GetUserObjectInformationW");
    Ptr_0047fe78 = EncodePointer(pFVar1);
    if (Ptr_0047fe78 != (PVOID)0x0) {
      pFVar1 = GetProcAddress(hModule,"GetProcessWindowStation");
      DAT_0047fe74 = EncodePointer(pFVar1);
    }
  }
  if ((DAT_0047fe74 == local_1c) || (Ptr_0047fe78 == local_1c)) {
LAB_0040aa3c:
    if ((((DAT_0047fe6c != local_1c) &&
         (pcVar2 = (code *)DecodePointer(DAT_0047fe6c), pcVar2 != (code *)0x0)) &&
        (local_18 = (*pcVar2)(), local_18 != 0)) &&
       ((DAT_0047fe70 != local_1c &&
        (pcVar2 = (code *)DecodePointer(DAT_0047fe70), pcVar2 != (code *)0x0)))) {
      local_18 = (*pcVar2)(local_18);
    }
  }
  else {
    pcVar2 = (code *)DecodePointer(DAT_0047fe74);
    pcVar3 = (code *)DecodePointer(Ptr_0047fe78);
    if (((pcVar2 == (code *)0x0) || (pcVar3 == (code *)0x0)) ||
       (((iVar4 = (*pcVar2)(), iVar4 != 0 &&
         (iVar4 = (*pcVar3)(iVar4,1,local_14,0xc,local_28), iVar4 != 0)) && ((local_c & 1) != 0))))
    goto LAB_0040aa3c;
    _UType = _UType | 0x200000;
  }
  pcVar2 = (code *)DecodePointer(Ptr_0047fe68);
  if (pcVar2 != (code *)0x0) {
    (*pcVar2)(local_18,local_24,local_20,_UType);
  }
LAB_0040aa8d:
  iVar4 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar4;
}



// Library Function - Single Match
//  _wcscat_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wcscat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  int iVar4;
  errno_t eStack_10;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    pwVar3 = _Dst;
    if (_Src != (wchar_t *)0x0) {
      do {
        if (*pwVar3 == L'\0') break;
        pwVar3 = pwVar3 + 1;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        iVar4 = (int)pwVar3 - (int)_Src;
        do {
          wVar1 = *_Src;
          *(wchar_t *)(iVar4 + (int)_Src) = wVar1;
          _Src = _Src + 1;
          if (wVar1 == L'\0') break;
          _SizeInWords = _SizeInWords - 1;
        } while (_SizeInWords != 0);
        if (_SizeInWords != 0) {
          return 0;
        }
        *_Dst = L'\0';
        piVar2 = __errno();
        eStack_10 = 0x22;
        *piVar2 = 0x22;
        goto LAB_0040aabb;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_0040aabb:
  FUN_00406231();
  return eStack_10;
}



// Library Function - Single Match
//  _wcsncpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wcsncpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src,rsize_t _MaxCount)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  int iVar4;
  rsize_t rVar5;
  errno_t eStack_14;
  
  if (_MaxCount == 0) {
    if (_Dst == (wchar_t *)0x0) {
      if (_SizeInWords == 0) {
        return 0;
      }
    }
    else {
LAB_0040ab37:
      if (_SizeInWords != 0) {
        if (_MaxCount == 0) {
          *_Dst = L'\0';
          return 0;
        }
        if (_Src != (wchar_t *)0x0) {
          rVar5 = _SizeInWords;
          if (_MaxCount == 0xffffffff) {
            iVar4 = (int)_Dst - (int)_Src;
            do {
              wVar1 = *_Src;
              *(wchar_t *)(iVar4 + (int)_Src) = wVar1;
              _Src = _Src + 1;
              if (wVar1 == L'\0') break;
              rVar5 = rVar5 - 1;
            } while (rVar5 != 0);
          }
          else {
            pwVar3 = _Dst;
            do {
              wVar1 = *(wchar_t *)(((int)_Src - (int)_Dst) + (int)pwVar3);
              *pwVar3 = wVar1;
              pwVar3 = pwVar3 + 1;
              if ((wVar1 == L'\0') || (rVar5 = rVar5 - 1, rVar5 == 0)) break;
              _MaxCount = _MaxCount - 1;
            } while (_MaxCount != 0);
            if (_MaxCount == 0) {
              *pwVar3 = L'\0';
            }
          }
          if (rVar5 != 0) {
            return 0;
          }
          if (_MaxCount == 0xffffffff) {
            _Dst[_SizeInWords - 1] = L'\0';
            return 0x50;
          }
          *_Dst = L'\0';
          piVar2 = __errno();
          eStack_14 = 0x22;
          *piVar2 = 0x22;
          goto LAB_0040ab48;
        }
        *_Dst = L'\0';
      }
    }
  }
  else if (_Dst != (wchar_t *)0x0) goto LAB_0040ab37;
  piVar2 = __errno();
  eStack_14 = 0x16;
  *piVar2 = 0x16;
LAB_0040ab48:
  FUN_00406231();
  return eStack_14;
}



// Library Function - Single Match
//  _wcslen
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2015 Release,
// Visual Studio 2019 Release

size_t __cdecl _wcslen(wchar_t *_Str)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  
  pwVar2 = _Str;
  do {
    wVar1 = *pwVar2;
    pwVar2 = pwVar2 + 1;
  } while (wVar1 != L'\0');
  return ((int)pwVar2 - (int)_Str >> 1) - 1;
}



// Library Function - Single Match
//  _wcscpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  int iVar3;
  errno_t eStack_10;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    if (_Src != (wchar_t *)0x0) {
      iVar3 = (int)_Dst - (int)_Src;
      do {
        wVar1 = *_Src;
        *(wchar_t *)(iVar3 + (int)_Src) = wVar1;
        _Src = _Src + 1;
        if (wVar1 == L'\0') break;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        return 0;
      }
      *_Dst = L'\0';
      piVar2 = __errno();
      eStack_10 = 0x22;
      *piVar2 = 0x22;
      goto LAB_0040ac18;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_0040ac18:
  FUN_00406231();
  return eStack_10;
}



// Library Function - Single Match
//  __set_error_mode
// 
// Library: Visual Studio 2010 Release

int __cdecl __set_error_mode(int _Mode)

{
  int iVar1;
  int *piVar2;
  
  if (-1 < _Mode) {
    if (_Mode < 3) {
      iVar1 = DAT_0047f248;
      DAT_0047f248 = _Mode;
      return iVar1;
    }
    if (_Mode == 3) {
      return DAT_0047f248;
    }
  }
  piVar2 = __errno();
  *piVar2 = 0x16;
  FUN_00406231();
  return -1;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtGetStringTypeA_stat(struct localeinfo_struct *,unsigned long,char const
// *,int,unsigned short *,int,int,int)
// 
// Library: Visual Studio 2010 Release

int __cdecl
__crtGetStringTypeA_stat
          (localeinfo_struct *param_1,ulong param_2,char *param_3,int param_4,ushort *param_5,
          int param_6,int param_7,int param_8)

{
  uint _Size;
  uint uVar1;
  uint cchWideChar;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *lpWideCharStr;
  
  uVar1 = DAT_0043d030 ^ (uint)&stack0xfffffffc;
  if (param_6 == 0) {
    param_6 = param_1->locinfo->lc_codepage;
  }
  cchWideChar = MultiByteToWideChar(param_6,(uint)(param_7 != 0) * 8 + 1,param_3,param_4,(LPWSTR)0x0
                                    ,0);
  if (cchWideChar == 0) goto LAB_0040ad70;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar2 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_0040ad2a:
        lpWideCharStr = puVar2 + 2;
      }
    }
    else {
      puVar2 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar2;
      if (puVar2 != (undefined4 *)0x0) {
        *puVar2 = 0xdddd;
        goto LAB_0040ad2a;
      }
    }
  }
  if (lpWideCharStr != (undefined4 *)0x0) {
    _memset(lpWideCharStr,0,cchWideChar * 2);
    iVar3 = MultiByteToWideChar(param_6,1,param_3,param_4,(LPWSTR)lpWideCharStr,cchWideChar);
    if (iVar3 != 0) {
      GetStringTypeW(param_2,(LPCWSTR)lpWideCharStr,iVar3,param_5);
    }
    __freea(lpWideCharStr);
  }
LAB_0040ad70:
  iVar3 = ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// Library Function - Single Match
//  ___crtGetStringTypeA
// 
// Library: Visual Studio 2010 Release

BOOL __cdecl
___crtGetStringTypeA
          (_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,
          int _Code_page,BOOL _BError)

{
  int iVar1;
  int in_stack_00000020;
  pthreadlocinfo in_stack_ffffffec;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&stack0xffffffec,_Plocinfo);
  iVar1 = __crtGetStringTypeA_stat
                    ((localeinfo_struct *)&stack0xffffffec,_DWInfoType,_LpSrcStr,_CchSrc,_LpCharType
                     ,_Code_page,in_stack_00000020,(int)in_stack_ffffffec);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  ___free_lc_time
// 
// Library: Visual Studio 2010 Release

void __cdecl ___free_lc_time(void **param_1)

{
  if (param_1 != (void **)0x0) {
    _free(param_1[1]);
    _free(param_1[2]);
    _free(param_1[3]);
    _free(param_1[4]);
    _free(param_1[5]);
    _free(param_1[6]);
    _free(*param_1);
    _free(param_1[8]);
    _free(param_1[9]);
    _free(param_1[10]);
    _free(param_1[0xb]);
    _free(param_1[0xc]);
    _free(param_1[0xd]);
    _free(param_1[7]);
    _free(param_1[0xe]);
    _free(param_1[0xf]);
    _free(param_1[0x10]);
    _free(param_1[0x11]);
    _free(param_1[0x12]);
    _free(param_1[0x13]);
    _free(param_1[0x14]);
    _free(param_1[0x15]);
    _free(param_1[0x16]);
    _free(param_1[0x17]);
    _free(param_1[0x18]);
    _free(param_1[0x19]);
    _free(param_1[0x1a]);
    _free(param_1[0x1b]);
    _free(param_1[0x1c]);
    _free(param_1[0x1d]);
    _free(param_1[0x1e]);
    _free(param_1[0x1f]);
    _free(param_1[0x20]);
    _free(param_1[0x21]);
    _free(param_1[0x22]);
    _free(param_1[0x23]);
    _free(param_1[0x24]);
    _free(param_1[0x25]);
    _free(param_1[0x26]);
    _free(param_1[0x27]);
    _free(param_1[0x28]);
    _free(param_1[0x29]);
    _free(param_1[0x2a]);
    _free(param_1[0x2f]);
    _free(param_1[0x30]);
    _free(param_1[0x31]);
    _free(param_1[0x32]);
    _free(param_1[0x33]);
    _free(param_1[0x34]);
    _free(param_1[0x2e]);
    _free(param_1[0x36]);
    _free(param_1[0x37]);
    _free(param_1[0x38]);
    _free(param_1[0x39]);
    _free(param_1[0x3a]);
    _free(param_1[0x3b]);
    _free(param_1[0x35]);
    _free(param_1[0x3c]);
    _free(param_1[0x3d]);
    _free(param_1[0x3e]);
    _free(param_1[0x3f]);
    _free(param_1[0x40]);
    _free(param_1[0x41]);
    _free(param_1[0x42]);
    _free(param_1[0x43]);
    _free(param_1[0x44]);
    _free(param_1[0x45]);
    _free(param_1[0x46]);
    _free(param_1[0x47]);
    _free(param_1[0x48]);
    _free(param_1[0x49]);
    _free(param_1[0x4a]);
    _free(param_1[0x4b]);
    _free(param_1[0x4c]);
    _free(param_1[0x4d]);
    _free(param_1[0x4e]);
    _free(param_1[0x4f]);
    _free(param_1[0x50]);
    _free(param_1[0x51]);
    _free(param_1[0x52]);
    _free(param_1[0x53]);
    _free(param_1[0x54]);
    _free(param_1[0x55]);
    _free(param_1[0x56]);
    _free(param_1[0x57]);
    _free(param_1[0x58]);
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_num
// 
// Library: Visual Studio 2010 Release

void __cdecl ___free_lconv_num(void **param_1)

{
  if (param_1 != (void **)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_0043de50) {
      _free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_0043de54) {
      _free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_0043de58) {
      _free(param_1[2]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_0043de80) {
      _free(param_1[0xc]);
    }
    if ((undefined *)param_1[0xd] != PTR_DAT_0043de84) {
      _free(param_1[0xd]);
    }
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_mon
// 
// Library: Visual Studio 2010 Release

void __cdecl ___free_lconv_mon(int param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_0043de5c) {
      _free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_0043de60) {
      _free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_0043de64) {
      _free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_0043de68) {
      _free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_0043de6c) {
      _free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_0043de70) {
      _free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_0043de74) {
      _free(*(undefined **)(param_1 + 0x24));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_0043de88) {
      _free(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x3c) != PTR_DAT_0043de8c) {
      _free(*(undefined **)(param_1 + 0x3c));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_0043de90) {
      _free(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x44) != PTR_DAT_0043de94) {
      _free(*(undefined **)(param_1 + 0x44));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_0043de98) {
      _free(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x4c) != PTR_DAT_0043de9c) {
      _free(*(undefined **)(param_1 + 0x4c));
    }
  }
  return;
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_16
// 
// Library: Visual Studio 2010 Release

uint __alloca_probe_16(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 0xf;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_8
// 
// Library: Visual Studio

uint __alloca_probe_8(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 7;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// Library Function - Single Match
//  _strcspn
// 
// Library: Visual Studio

size_t __cdecl _strcspn(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  size_t sVar3;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0;
  uStack_10 = 0;
  uStack_14 = 0;
  uStack_18 = 0;
  uStack_1c = 0;
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 0;
  while( true ) {
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  sVar3 = 0xffffffff;
  do {
    sVar3 = sVar3 + 1;
    bVar1 = *_Str;
    if (bVar1 == 0) {
      return sVar3;
    }
    _Str = (char *)((byte *)_Str + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return sVar3;
}



// Library Function - Single Match
//  _strcpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  errno_t eStack_10;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    if (_Src != (char *)0x0) {
      iVar3 = (int)_Dst - (int)_Src;
      do {
        cVar1 = *_Src;
        _Src[iVar3] = cVar1;
        _Src = _Src + 1;
        if (cVar1 == '\0') break;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        return 0;
      }
      *_Dst = '\0';
      piVar2 = __errno();
      eStack_10 = 0x22;
      *piVar2 = 0x22;
      goto LAB_0040b335;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_0040b335:
  FUN_00406231();
  return eStack_10;
}



// Library Function - Single Match
//  _strpbrk
// 
// Library: Visual Studio

char * __cdecl _strpbrk(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0;
  uStack_10 = 0;
  uStack_14 = 0;
  uStack_18 = 0;
  uStack_1c = 0;
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 0;
  while( true ) {
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = (byte *)_Str;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (char *)(uint)bVar1;
    }
    _Str = (char *)(pbVar2 + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(char *)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return (char *)pbVar2;
}



// Library Function - Single Match
//  int __cdecl x_ismbbtype_l(struct localeinfo_struct *,unsigned int,int,int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl x_ismbbtype_l(localeinfo_struct *param_1,uint param_2,int param_3,int param_4)

{
  uint uVar1;
  int local_14;
  int local_10;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,param_1);
  if ((*(byte *)(local_10 + 0x1d + (param_2 & 0xff)) & (byte)param_4) == 0) {
    if (param_3 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = (uint)*(ushort *)(*(int *)(local_14 + 200) + (param_2 & 0xff) * 2) & param_3;
    }
    if (uVar1 == 0) goto LAB_0040b494;
  }
  uVar1 = 1;
LAB_0040b494:
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  __ismbblead
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __ismbblead(uint _C)

{
  int iVar1;
  
  iVar1 = x_ismbbtype_l((localeinfo_struct *)0x0,_C,0,4);
  return iVar1;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x40b4d8,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __cdecl __local_unwind2(int param_1,uint param_2)

{
  uint uVar1;
  void *local_20;
  undefined *puStack_1c;
  undefined4 local_18;
  int iStack_14;
  
  iStack_14 = param_1;
  puStack_1c = &LAB_0040b4e0;
  local_20 = ExceptionList;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_0040b5f4();
    }
  }
  ExceptionList = local_20;
  return;
}



// Library Function - Single Match
//  __NLG_Notify
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __NLG_Notify(ulong param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_0043dec8 = param_1;
  DAT_0043dec4 = in_EAX;
  DAT_0043decc = unaff_EBP;
  return;
}



void FUN_0040b5f4(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2010 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  BOOL BVar1;
  DWORD local_8;
  
  if (DAT_0043ded0 == (HANDLE)0xfffffffe) {
    ___initconout();
  }
  if (DAT_0043ded0 != (HANDLE)0xffffffff) {
    BVar1 = WriteConsoleW(DAT_0043ded0,&_WCh,1,&local_8,(LPVOID)0x0);
    if (BVar1 != 0) {
      return _WCh;
    }
  }
  return 0xffff;
}



// Library Function - Single Match
//  __mbtowc_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbtowc_l(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes,_locale_t _Locale)

{
  wchar_t *pwVar1;
  int iVar2;
  int *piVar3;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  if ((_SrcCh != (char *)0x0) && (_SrcSizeInBytes != 0)) {
    if (*_SrcCh != '\0') {
      _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
      if ((local_14.locinfo)->lc_category[0].wlocale != (wchar_t *)0x0) {
        iVar2 = __isleadbyte_l((uint)(byte)*_SrcCh,&local_14);
        if (iVar2 == 0) {
          iVar2 = MultiByteToWideChar((local_14.locinfo)->lc_codepage,9,_SrcCh,1,_DstCh,
                                      (uint)(_DstCh != (wchar_t *)0x0));
          if (iVar2 != 0) goto LAB_0040b687;
        }
        else {
          pwVar1 = (local_14.locinfo)->locale_name[3];
          if ((((1 < (int)pwVar1) && ((int)pwVar1 <= (int)_SrcSizeInBytes)) &&
              (iVar2 = MultiByteToWideChar((local_14.locinfo)->lc_codepage,9,_SrcCh,(int)pwVar1,
                                           _DstCh,(uint)(_DstCh != (wchar_t *)0x0)), iVar2 != 0)) ||
             (((local_14.locinfo)->locale_name[3] <= _SrcSizeInBytes && (_SrcCh[1] != '\0')))) {
            pwVar1 = (local_14.locinfo)->locale_name[3];
            if (local_8 == '\0') {
              return (int)pwVar1;
            }
            *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
            return (int)pwVar1;
          }
        }
        piVar3 = __errno();
        *piVar3 = 0x2a;
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        return -1;
      }
      if (_DstCh != (wchar_t *)0x0) {
        *_DstCh = (ushort)(byte)*_SrcCh;
      }
LAB_0040b687:
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      return 1;
    }
    if (_DstCh != (wchar_t *)0x0) {
      *_DstCh = L'\0';
    }
  }
  return 0;
}



// Library Function - Single Match
//  _mbtowc
// 
// Library: Visual Studio 2010 Release

int __cdecl _mbtowc(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes)

{
  int iVar1;
  
  iVar1 = __mbtowc_l(_DstCh,_SrcCh,_SrcSizeInBytes,(_locale_t)0x0);
  return iVar1;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Library: Visual Studio 2010 Release

void __alloca_probe(void)

{
  undefined *in_EAX;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 unaff_retaddr;
  undefined auStack_4 [4];
  
  puVar2 = (undefined4 *)((int)&stack0x00000000 - (int)in_EAX & ~-(uint)(&stack0x00000000 < in_EAX))
  ;
  for (puVar1 = (undefined4 *)((uint)auStack_4 & 0xfffff000); puVar2 < puVar1;
      puVar1 = puVar1 + -0x400) {
  }
  *puVar2 = unaff_retaddr;
  return;
}



// Library Function - Single Match
//  __free_osfhnd
// 
// Library: Visual Studio 2010 Release

int __cdecl __free_osfhnd(int param_1)

{
  int iVar1;
  int *piVar2;
  ulong *puVar3;
  int iVar4;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < uNumber_0047fe88)) {
    iVar1 = (&DAT_0047fea0)[param_1 >> 5];
    iVar4 = (param_1 & 0x1fU) * 0x40;
    if (((*(byte *)(iVar1 + 4 + iVar4) & 1) != 0) && (*(int *)(iVar1 + iVar4) != -1)) {
      if (DAT_0043d2c0 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0040b7fd;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_0040b7fd:
      *(undefined4 *)(iVar4 + (&DAT_0047fea0)[param_1 >> 5]) = 0xffffffff;
      return 0;
    }
  }
  piVar2 = __errno();
  *piVar2 = 9;
  puVar3 = ___doserrno();
  *puVar3 = 0;
  return -1;
}



// Library Function - Single Match
//  __get_osfhandle
// 
// Library: Visual Studio 2010 Release

intptr_t __cdecl __get_osfhandle(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_0047fe88)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar3 + 4 + (&DAT_0047fea0)[_FileHandle >> 5]) & 1) != 0) {
        return *(intptr_t *)(iVar3 + (&DAT_0047fea0)[_FileHandle >> 5]);
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_00406231();
  }
  return -1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___lock_fhandle
// 
// Library: Visual Studio 2010 Release

int __cdecl ___lock_fhandle(int _Filehandle)

{
  BOOL BVar1;
  int iVar2;
  uint local_20;
  
  iVar2 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_0047fea0)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      BVar1 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(iVar2 + 0xc),4000);
      local_20 = (uint)(BVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_0040b920();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_0047fea0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  }
  return local_20;
}



void FUN_0040b920(void)

{
  FUN_00406cc5(10);
  return;
}



// Library Function - Single Match
//  __unlock_fhandle
// 
// Library: Visual Studio 2010 Release

void __cdecl __unlock_fhandle(int _Filehandle)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_0047fea0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  return;
}



// Library Function - Single Match
//  __close_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __close_nolock(int _FileHandle)

{
  intptr_t iVar1;
  intptr_t iVar2;
  HANDLE hObject;
  BOOL BVar3;
  DWORD DVar4;
  int iVar5;
  
  iVar1 = __get_osfhandle(_FileHandle);
  if (iVar1 != -1) {
    if (((_FileHandle == 1) && ((*(byte *)(DAT_0047fea0 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_0047fea0 + 0x44) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_0040b9b6;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_0040b9b8;
    }
  }
LAB_0040b9b6:
  DVar4 = 0;
LAB_0040b9b8:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
  if (DVar4 == 0) {
    iVar5 = 0;
  }
  else {
    __dosmaperr(DVar4);
    iVar5 = -1;
  }
  return iVar5;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __close
// 
// Library: Visual Studio 2010 Release

int __cdecl __close(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < uNumber_0047fe88)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0047fea0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_0040baa8();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_00406231();
  }
  return -1;
}



void FUN_0040baa8(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// Library Function - Single Match
//  __freebuf
// 
// Library: Visual Studio 2010 Release

void __cdecl __freebuf(FILE *_File)

{
  if (((_File->_flag & 0x83U) != 0) && ((_File->_flag & 8U) != 0)) {
    _free(_File->_base);
    _File->_flag = _File->_flag & 0xfffffbf7;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_cnt = 0;
  }
  return;
}



// Library Function - Single Match
//  ___initconout
// 
// Library: Visual Studio 2010 Release

void __cdecl ___initconout(void)

{
  DAT_0043ded0 = CreateFileW(L"CONOUT$",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  return;
}



// Library Function - Single Match
//  ___ascii_strnicmp
// 
// Library: Visual Studio

int __cdecl ___ascii_strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  char cVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  bool bVar5;
  
  if (_MaxCount != 0) {
    do {
      bVar2 = *_Str1;
      cVar1 = *_Str2;
      uVar3 = CONCAT11(bVar2,cVar1);
      if (bVar2 == 0) break;
      uVar3 = CONCAT11(bVar2,cVar1);
      uVar4 = (uint)uVar3;
      if (cVar1 == '\0') break;
      _Str1 = (char *)((byte *)_Str1 + 1);
      _Str2 = _Str2 + 1;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar4 = (uint)CONCAT11(bVar2 + 0x20,cVar1);
      }
      uVar3 = (ushort)uVar4;
      bVar2 = (byte)uVar4;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar3 = (ushort)CONCAT31((int3)(uVar4 >> 8),bVar2 + 0x20);
      }
      bVar2 = (byte)(uVar3 >> 8);
      bVar5 = bVar2 < (byte)uVar3;
      if (bVar2 != (byte)uVar3) goto LAB_0040bb71;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_0040bb71:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x0040bbc4. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}


