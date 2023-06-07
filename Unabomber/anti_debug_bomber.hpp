#ifndef BOMBER_ANTI_DEBUG

#define  BOMBER_ANTI_DEBUG

#include <iostream>
#include "Struct.h"
#include "NtApiDef.h"
#include "lazy_importer.hpp"  
#include "hash_str.h"
#include "hash_str.h"

#define STATUAS_VENDOR_SUPPORTED 1
#define STATUAS_VENDOR_NOT_SUPPORTED 2
 
 
#define BREAK_INFO() \
    HANDLE uniq_process_id = NtCurrentTeb()->ClientId.UniqueProcess; \
    HANDLE uniq_thread_id = NtCurrentTeb()->ClientId.UniqueThread; \
    NtCurrentTeb()->ClientId.UniqueProcess = reinterpret_cast<HANDLE>(NULL); \
    NtCurrentTeb()->ClientId.UniqueThread = reinterpret_cast<HANDLE>(NULL);  

#define RESTORE_INFO() \
    NtCurrentTeb()->ClientId.UniqueProcess = uniq_process_id; \
    NtCurrentTeb()->ClientId.UniqueThread = uniq_thread_id; 
/*
    Secret 1337 info
*/
namespace anti_debug_bomber
{
     
  
    namespace crt_wrapper
    {
        /*
        GenuineIntel
        AuthenticAMD
        */
        static INT vendor_status = NULL;

        INLINE  auto is_support_vendor() -> bool
        {
            if (vendor_status & STATUAS_VENDOR_SUPPORTED)
            {
                return TRUE;
            }

            INT cpuid[4]{ -1 };
            __cpuid(cpuid, NULL);

            if (
                ((cpuid[1] == 'htuA') &&
                    (cpuid[3] == 'itne') &&
                    (cpuid[2] == 'DMAc'))
                ||
                ((cpuid[1] == 'uneG') &&
                    (cpuid[3] == 'Ieni') &&
                    (cpuid[2] == 'letn')))
            {
                vendor_status |= STATUAS_VENDOR_SUPPORTED;
                return TRUE;
            }
            vendor_status |= STATUAS_VENDOR_NOT_SUPPORTED;
            return FALSE;
        }

        INLINE auto memset(PVOID src, INT val, unsigned __int64 count) -> PVOID
        {
            __stosb((uint8_t*)((uint64_t)(volatile CHAR*)src), val, count);
            return src;
        }

        INLINE  auto get_name_file() -> WCHAR*
        {  
            LDR_DATA_TABLE_ENTRY* modEntry = nullptr;

#ifdef _WIN64
            PEB* peb = (PEB*)__readgsqword(0x60); 
#else
            PEB* peb = (PEB*)__readfsdword(0x30);
#endif
            LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

            LIST_ENTRY curr = head;

            for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink)
            {
                LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                if (mod->BaseDllName.Buffer)
                {
                    return mod->FullDllName.Buffer;
                }
            } 
            return FALSE;
        }
          
        INLINE  auto safe_check_dr7_set_any(uint64_t val) -> bool
        {

            if (is_support_vendor())
            {
                return  (val & (1 << 0)) || (val & (1 << 2)) || (val & (1 << 4)) || (val % (1 << 6));
            }
            return FALSE;
        }

        INLINE  auto safe_check_dr7_not_set_any(uint64_t val) -> bool
        { 
            if (is_support_vendor())
            {
                return  !((val & (1 << 0)) || (val & (1 << 2)) || (val & (1 << 4)) || (val % (1 << 6)));
            }
            return FALSE;
        }

        static NO_INLINE auto constexpr  get_random_number() -> uint64_t
        {
            return  (__TIME__[7] - '0') +
                (__TIME__[6] - '0') * 10 +
                (__TIME__[4] - '0') * 60 +
                (__TIME__[3] - '0') * 600 +
                (__TIME__[1] - '0') * 3600 +
                (__TIME__[0] - '0') * 36000 + __COUNTER__;
        }

        INLINE  auto get_windows_number() -> INT
        {
            auto build_number = NtCurrentPeb()->OSBuildNumber;
            auto nt_majorVersion = *reinterpret_cast<uint8_t*>(0x7FFE026C);
            if (nt_majorVersion == 10)
            {
                auto nt_build_number = *reinterpret_cast<INT*>(0x7FFE0260);//NtBuildNumber
                if (nt_build_number == 22000 || nt_build_number == 22621)
                {
                    return WINDOWS_NUMBER_11;
                }
                return WINDOWS_NUMBER_10;
            }
            else if (nt_majorVersion == 5)
            {
                return WINDOWS_NUMBER_XP;//Windows XP
            }
            else if (nt_majorVersion == 6)
            {
                /*
                https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html
                */
                switch (*reinterpret_cast<uint8_t*>(0x7FFE0270))  //0x7FFE0270 NtMinorVersion
                {
                case 1:
                    return WINDOWS_NUMBER_7;//windows 7
                case 2:
                    return WINDOWS_NUMBER_8; //window 8
                case 3:
                    return WINDOWS_NUMBER_8_1; //windows 8.1
                default:
                    break;
                }

            }
            if (build_number < 7600 &&
                build_number > 3800
                )
            {
                return WINDOWS_VISTA;
            }

            if (build_number <= 2195)
            {
                return WINDOWS_NUMBER_2000;
            }
            if (build_number <= 22621 && build_number >= 10240)
            {
                return WINDOWS_NUMBER_10;
            }
            return NULL;
        }

        INLINE auto malloc(size_t size) -> PVOID
        {
            return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
        }

        INLINE auto free(PVOID ptr) -> VOID
        {
            if (nullptr != ptr)
                VirtualFree(ptr, NULL, MEM_RELEASE);
        }

        INLINE auto wtolower(INT c) -> INT
        {
            if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
            return c;
        }
         
        INLINE auto wstrlen(CONST WCHAR* s) -> INT
        {
            INT cnt = NULL;
            if (!s) 
                return NULL;
            for (; *s != NULL; ++s) ++cnt;
            return cnt;
        }
         
        INLINE auto wstricmp(CONST WCHAR* cs, CONST WCHAR* ct) -> INT
        {
            if (cs && ct)
            {
                while (wtolower(*cs) == wtolower(*ct))
                {
                    if (*cs == NULL && *ct == NULL) return NULL;
                    if (*cs == NULL || *ct == NULL) break;
                    cs++;
                    ct++;
                }
                return wtolower(*cs) - wtolower(*ct);
            }
            return -1;
        }
         
        INLINE  auto wstrstr(CONST WCHAR* s, CONST WCHAR* find)->WCHAR*
        {
            WCHAR c, sc;
            if ((c = *find++) != NULL)
            {
                do
                {
                    do
                    {
                        if ((sc = *s++) == NULL)
                            return NULL;
                    } while (sc != c);
                } while (wstricmp(s, find) != NULL);
                s--;
            }
            return (WCHAR*)s;
        }

        INLINE  auto memcpy(PVOID dest, const PVOID src, uint64_t count) -> PVOID
        {
            auto char_dest = (CHAR*)dest;
            auto char_src = (CHAR*)src;
            if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
            {
                while (count > NULL)
                {
                    *char_dest = *char_src;
                    char_dest++;
                    char_src++;
                    count--;
                }
            }
            else
            {
                char_dest = (CHAR*)dest + count - 1;
                char_src = (CHAR*)src + count - 1;
                while (count > NULL)
                {
                    *char_dest = *char_src;
                    char_dest--;
                    char_src--;
                    count--;
                }
            }
            return dest;
        }

        INLINE auto get_number_handle(PVOID nt_query_system_information) -> uint64_t
        {
            PVOID buffer = NULL;
            ULONG ret_lenght = NULL;
            uint64_t handle_number = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
            
            nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemHandleInformation, &ret_lenght, ret_lenght, &ret_lenght);
            while (nt_status == STATUS_INFO_LENGTH_MISMATCH) 
            {
                if (buffer != NULL)
                    crt_wrapper::free(buffer);

                buffer = crt_wrapper::malloc(ret_lenght);
                nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemHandleInformation, buffer, ret_lenght, &ret_lenght);
            }

            if (!NT_SUCCESS(nt_status))
            {
                if (buffer != NULL)
                    crt_wrapper::free(buffer);
                return NULL;
            }
            auto handle_info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer);
            for (ULONG i = NULL; i < handle_info->NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handle_info->Handles[i];
                if (handleInfo.UniqueProcessId == reinterpret_cast<USHORT>(NtCurrentTeb()->ClientId.UniqueProcess))
                    handle_number++;
            }
            crt_wrapper::free(buffer);
            return handle_number;
        }

        INLINE auto is_object_exist_proc(PSYSTEM_HANDLE_INFORMATION handle_info, PVOID Object, INT pid, ULONG access = NULL) -> ULONG
        {
            ULONG number = NULL;
            for (ULONG i = NULL; i < handle_info->NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handle_info->Handles[i];
                if (handleInfo.UniqueProcessId == pid)
                {
                    if (handleInfo.Object == Object && access)
                    {
                        if ((handleInfo.GrantedAccess & access) != NULL)
                            number++;
                    }
                    else if (handleInfo.Object == Object)
                            number++;
                }
            }
            return number;
        }

        INLINE auto is_object_type_exist_proc(PSYSTEM_HANDLE_INFORMATION handle_info, INT ObjectTypeIndex, INT pid, LONG access = NULL) -> ULONG
        {
            ULONG number = NULL;
            for (ULONG i = NULL; i < handle_info->NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handle_info->Handles[i];
                if (handleInfo.UniqueProcessId == pid)
                {
                    if (handleInfo.ObjectTypeIndex == ObjectTypeIndex && access)
                    {
                        if ((handleInfo.GrantedAccess & access) != NULL)
                            number++;
                    }
                    else if (handleInfo.ObjectTypeIndex == ObjectTypeIndex)
                            number++;
                }
            }
            return number;
        }

        /*
        
         reinterpret_cast<decltype(&NtDuplicateObject)>(nt_dublicate_object)
        
        */
        INLINE auto is_object_type_present_name(PVOID nt_dublicate_object,PVOID nt_close, PVOID nt_query_object ,PSYSTEM_HANDLE_INFORMATION handle_info, INT ObjectTypeIndex, INT pid, LONG access = NULL) -> bool
        { 
            bool is_detect = FALSE;
            INT lenght_file = NULL;
            ULONG ret_lenght = NULL;

            HANDLE proc_oper = NULL;
            PVOID buffer = NULL;
            WCHAR* buffer_str = NULL;
            WCHAR* str_file = NULL;
            HANDLE dublicate_handle = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
            
            str_file = crt_wrapper::get_name_file();
            lenght_file = crt_wrapper::wstrlen(crt_wrapper::get_name_file()) + 1;
            buffer_str = (WCHAR*)crt_wrapper::malloc(lenght_file); 

			//aye get process name
            for (size_t i = lenght_file -1 ;i != NULL; i--)
            {
                if (str_file[i-1] == '\\')
                {
                    crt_wrapper::memcpy(buffer_str  , crt_wrapper::get_name_file() + i, crt_wrapper::wstrlen(crt_wrapper::get_name_file() + i)* sizeof(buffer_str));
                    break;
                }
            }

            for (ULONG i = NULL; i < handle_info->NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handle_info->Handles[i];
                if (handleInfo.UniqueProcessId == pid)
                {
                    if (handleInfo.ObjectTypeIndex == ObjectTypeIndex && access)
                    {
                        if ((handleInfo.GrantedAccess & access) != NULL)
                        {
                            proc_oper = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
                            if (proc_oper)
                            {
                                nt_status = reinterpret_cast<decltype(&NtDuplicateObject)>(nt_dublicate_object)(proc_oper, reinterpret_cast<HANDLE>(handleInfo.HandleValue), NtCurrentProcess, &dublicate_handle, NULL, FALSE, DUPLICATE_SAME_ACCESS);
                                if (NT_SUCCESS(nt_status))
                                {
                                    // std::cout << "ntstatus dub ->\t" << std::hex << nt_status << '\n';
                                    nt_status = reinterpret_cast<decltype(&NtQueryObject)>(nt_query_object)(dublicate_handle, ObjectNameInformation, &ret_lenght, sizeof(OBJECT_NAME_INFORMATION), &ret_lenght);
                                    //std::cout << "ntstatus 1->\t" << std::hex << nt_status << '\n';
                                    buffer = crt_wrapper::malloc(ret_lenght);
                                    nt_status = reinterpret_cast<decltype(&NtQueryObject)>(nt_query_object)(dublicate_handle, ObjectNameInformation, buffer, ret_lenght, &ret_lenght);
                                    // Sleep(20000);
                                    if (NT_SUCCESS(nt_status))
                                    {
                                        //StrStrW
                                        if (crt_wrapper::wstrstr(reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer)->Name.Buffer, buffer_str) ||
                                            crt_wrapper::wstrstr(reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer)->Name.Buffer, L"scylla_hide.log")
                                            )
                                        {
                                            is_detect = TRUE;
                                        }
                                    }
                                    if (dublicate_handle) 
                                        reinterpret_cast<decltype(&NtClose)>(nt_close)(dublicate_handle);
									if(buffer)
										crt_wrapper::free(buffer);
                                        buffer = NULL;
                                }
                                if (proc_oper)
                                    reinterpret_cast<decltype(&NtClose)>(nt_close)(proc_oper);

                                if (is_detect)
                                {
                                    break;
                                }
                            }

                        }
                    }
                }
            }
            crt_wrapper::free(buffer_str);
            return is_detect;
        }
          
        INLINE auto remove_object_dublicate(PVOID nt_dublicate_object,PVOID nt_close ,PSYSTEM_HANDLE_INFORMATION handle_info, INT ObjectTypeIndex, INT pid, LONG access = NULL) -> bool
        {
            bool is_remove = FALSE;

            HANDLE proc_oper = NULL;
            HANDLE dublicate_handle = NULL;
            HANDLE dublicate_handle_port = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;


            for (ULONG i = NULL; i < handle_info->NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handle_info->Handles[i];
                if (handleInfo.UniqueProcessId == pid)
                {
                    if (handleInfo.ObjectTypeIndex == ObjectTypeIndex && access)
                    {
                        if ((handleInfo.GrantedAccess & access) != NULL)
                        {
                            proc_oper = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
                            if (proc_oper)
                            {
                                //DebugPort remove
                                nt_status = reinterpret_cast<decltype(&NtDuplicateObject)>(nt_dublicate_object)(proc_oper, reinterpret_cast<HANDLE>(handleInfo.HandleValue), NtCurrentProcess, &dublicate_handle_port, NULL, FALSE, DUPLICATE_SAME_ACCESS);
                                if (NT_SUCCESS(nt_status))
                                {
                                    nt_status = LI_FN(NtRemoveProcessDebug).nt_cached()(NtCurrentProcess, dublicate_handle_port);
                                    if (NT_SUCCESS(nt_status))
                                        is_remove = TRUE;
                                    
                                    if (dublicate_handle_port)
                                        reinterpret_cast<decltype(&NtClose)>(nt_close)(dublicate_handle_port);
                                }

                                //Just try close handle
                                nt_status = reinterpret_cast<decltype(&NtDuplicateObject)>(nt_dublicate_object)(proc_oper, reinterpret_cast<HANDLE>(handleInfo.HandleValue), NtCurrentProcess, &dublicate_handle, NULL, FALSE, DUPLICATE_CLOSE_SOURCE);
                                if (NT_SUCCESS(nt_status))
                                {
                                    is_remove = TRUE;
                                    if (dublicate_handle) 
                                        reinterpret_cast<decltype(&NtClose)>(nt_close)(dublicate_handle);
                                }
                                reinterpret_cast<decltype(&NtClose)>(nt_close)(proc_oper);
                                if (is_remove)
                                {
                                    break;
                                }
                            }

                        }
                    }
                }
            }

            return is_remove;
        }
         
        INLINE auto remove_dbg_reserved(PVOID nt_close ,USHORT pid) -> bool
        {
            uint64_t is_detect = FALSE;
            HANDLE proc_oper = NULL;
            HANDLE thread_handle = NULL;
            LPVOID allocate_shell = NULL;
#ifndef _WIN64
            uint8_t fuck_dbg_reserved_ss[] =
            {
                0x50, //push eax
                0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, //mov eax,dword ptr fs:[18]
                0x3E, 0x83, 0xB8, 0x24, 0x0F, 0x00, 0x00, 0x00, //cmp dword ptr ds:[eax+F24],0
                0x74,0x1F, //je okey
                0xC7, 0x80, 0x24, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //mov dword ptr ds:[eax+F24],0
                0xE8, 0x00, 0x00, 0x00, 0x00, // $+5
                0x8B, 0x04, 0x24, //mov eax,dword ptr ss:[esp]
                0x83, 0xC4, 0x04, //add esp,4
                0x36, 0xC7, 0x40, 0xE0, 0x01, 0x00, 0x00, 0x00, //mov dword ptr ss:[eax-20],1
                0x58, //pop eax
                0xC3, //ret 
                0xE8, 0x00, 0x00, 0x00, 0x00, // $+5
                0x8B, 0x04, 0x24, //mov eax,dword ptr ss:[esp]
                0x83, 0xC4, 0x04, //add esp,4
                0x36, 0xC7, 0x40, 0xCB, 0x00,0x00, 0x00, 0x00, //mov dword ptr ss:[eax-35],0
                0x58, //pop eax
                0xC3 //ret 
            };
#else
            uint8_t fuck_dbg_reserved_ss[] =
            {
                0x50,//push rax
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,//mov rax,qword ptr gs:[0x30]
                0x3E, 0x48, 0x83, 0xB8, 0xA8, 0x16, 0x00, 0x00, 0x00, ////cmp qword ptr ds:[rax+0x16A8],0x0 or if(NtCurrentTeb()->DbgSsReserved[1] == NULL)
                0x74, 0x20, //je okey
                0x3E, 0x48, 0xC7, 0x80, 0xA8, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,0x00,//mov qword ptr ds:[rax+0x16A8],0x0 or ,NtCurrentTeb()->DbgSsReserved[1] = NULL
                0x48, 0x31, 0xC0, //xor rax,rax
                0x48, 0x8D, 0x05, 0xD5, 0xFF, 0xFF, 0xFF, //lea rax,qword ptr ds:[0x7FF619E8108A] or fuck_dbg_reserved_ss[0]
                0x36, 0x48, 0xC7, 0x00, 0x01,0x00, 0x00, 0x00, ////mov qword ptr ss:[rax],0x1
                0x58, //pop rax
                0xC3, //ret  
                0x48, 0x31, 0xC0,//xor rax,rax
                0x48, 0x8D, 0x05, 0xC1, 0xFF, 0xFF, 0xFF, //lea rax,qword ptr ds:[0x7FF619E8108A] or fuck_dbg_reserved_ss[0]
                0x36,0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, //mov qword ptr ss:[rax],0x0
                0x58, //pop rax
                0xC3  //ret 
            };
#endif // !_WIN64

            proc_oper = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, pid);
            if (proc_oper)
            {
                allocate_shell = VirtualAllocEx(proc_oper, NULL, PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (allocate_shell)
                {
                    if (WriteProcessMemory(proc_oper, allocate_shell, fuck_dbg_reserved_ss, sizeof(fuck_dbg_reserved_ss), NULL))
                    {
                        thread_handle = CreateRemoteThread(proc_oper, NULL, 0x1000, reinterpret_cast<LPTHREAD_START_ROUTINE>(allocate_shell), NULL, NULL, NULL);
                        if (thread_handle)
                        {
                            Sleep(5);
                            ReadProcessMemory(proc_oper, allocate_shell, &is_detect, sizeof(is_detect), NULL);
                        }
                        reinterpret_cast<decltype(&NtClose)>(nt_close)(thread_handle);
                    }
                    VirtualFree(allocate_shell, NULL, MEM_RELEASE);
                }
                reinterpret_cast<decltype(&NtClose)>(nt_close)(proc_oper);
            }
            return is_detect != NULL;
        }

        namespace get_proc_info
        {
            INT status_process = NULL;
#if defined(__clang__)

            ALLOCATE_TEXT uint8_t get_process_info[] =
            {
                0x66, 0x8C, 0xC8, //mov ax, cs
                0xC3 //ret
            };
#endif // !__clang__

            INLINE  auto get_process_platform() -> INT
            { 

                SYSTEM_INFO sys_inf;  
#if defined(__clang__)
                if (status_process)
                {
                    return status_process;
                }
                auto proc = reinterpret_cast<BYTE(__cdecl*)()>(get_proc_info::get_process_info)();
                status_process = proc;
                if (proc == CS_64)
                {
                    status_process =  PROCESS_64;
                }
                else if (proc == CS_WOW)
                {
                    status_process =  PROCESS_WOW64;
                }
                else if (proc == CS_32)
                {
                    status_process = PROCESS_32;
                }
                else
                {
                    status_process = PROCESS_UNK;
                }
#else

#ifdef _WIN64
                status_process = PROCESS_64;
#else  
                LI_FN(GetNativeSystemInfo).forwarded_cached()(&sys_inf);
                if (sys_inf.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                    sys_inf.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
                {
                    status_process = PROCESS_WOW64;
                }
                else if (sys_inf.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL)
                {
                    status_process = PROCESS_32;
                } 
                else if(sys_inf.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_UNKNOWN)
                {
                    status_process = PROCESS_UNK;
                } 

#endif // _WIN64



#endif // !__clang__
                return status_process;
            }
        }


    }
    
    namespace util_process
    {
        /*
			NO_INLINE auto hide_thread(uint32_t thread_id) -> bool
			{
			
				HANDLE thread_handle = NULL;
				PVOID ntdll_base = NULL; 
				PVOID nt_set_informathion_thread = NULL;
				PVOID nt_open_thread = NULL;
				PVOID nt_close = NULL;
				CLIENT_ID client_id;
				OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(OBJECT_ATTRIBUTES) };
				
				
				if (thread_id)
				{
					client_id.UniqueThread = reinterpret_cast<HANDLE>(thread_id);
					client_id.UniqueProcess = NULL;
					
					ntdll_base = api_wrapper::get_module_address(FNV(L"ntdll.dll"));
			
					if (ntdll_base )
					{
						
						nt_close = api_wrapper::get_proc_address(ntdll_base, FNV("NtClose"));
						nt_set_informathion_thread = api_wrapper::get_proc_address(ntdll_base, FNV("NtSetInformationThread"));
						nt_open_thread =  api_wrapper::get_proc_address(ntdll_base, FNV("NtOpenThread"));
						
						if ( nt_close)
						{
							if(!NT_SUCCESS(reinterpret_cast<decltype(&NtOpenThread)>(nt_open_thread)(&thread_handle,THREAD_SET_INFORMATION, &ObjectAttributes, &client_id)))
								return FALSE;
			
							if (nt_set_informathion_thread && thread_handle)
								reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(thread_handle, ThreadHideFromDebugger, NULL, NULL);
							
							if (thread_handle)
								reinterpret_cast<decltype(&NtClose)>(nt_close)(thread_handle); 
						}
					}
				}
				return NULL;
			}
		*/
        uint8_t shell_hide_thread_64[] =
        {
            0x4C, 0x8B, 0xDC, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00, 0x45, 0x33, 0xFF, 0xC7,
            0x44, 0x24, 0x30, 0x30, 0x00, 0x00, 0x00, 0x0F, 0x57, 0xC0, 0x4D, 0x89, 0x7B, 0x10, 0x33, 0xC0,
            0x0F, 0x11, 0x44, 0x24, 0x38, 0x0F, 0x11, 0x44, 0x24, 0x48, 0x49, 0x89, 0x43, 0xD0, 0x85, 0xC9,
            0x0F, 0x84, 0xAC, 0x03, 0x00, 0x00, 0x49, 0x89, 0x5B, 0x08, 0x41, 0x8B, 0xDF, 0x4D, 0x89, 0x7B,
            0x98, 0x49, 0x89, 0x7B, 0xF0, 0x4D, 0x89, 0x63, 0xE8, 0x49, 0xBC, 0x51, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x4D, 0x89, 0x6B, 0xE0, 0x49, 0xBD, 0xC3, 0x22, 0x22, 0x84, 0xE4, 0x9C, 0xF2,
            0xCB, 0x8B, 0xC1, 0x49, 0x89, 0x43, 0xA0, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0x58, 0x18, 0x49, 0x83, 0xC3, 0x20, 0x4D, 0x8B, 0x0B, 0x4D, 0x3B, 0xCB, 0x74, 0x47,
            0x48, 0xBF, 0x17, 0xF2, 0x17, 0x97, 0xFB, 0xE7, 0xDF, 0x20, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00,
            0x4D, 0x8B, 0x41, 0x50, 0x4D, 0x85, 0xC0, 0x74, 0x20, 0x49, 0x8B, 0xD5, 0x0F, 0x1F, 0x40, 0x00,
            0x41, 0x0F, 0xB7, 0x08, 0x4D, 0x8D, 0x40, 0x02, 0x48, 0x33, 0xD1, 0x49, 0x0F, 0xAF, 0xD4, 0x66,
            0x85, 0xC9, 0x75, 0xEC, 0x48, 0x3B, 0xD7, 0x74, 0x0A, 0x4D, 0x8B, 0x09, 0x4D, 0x3B, 0xCB, 0x75,
            0xCF, 0xEB, 0x04, 0x49, 0x8D, 0x59, 0xF0, 0x4C, 0x8B, 0x4B, 0x30, 0x4D, 0x85, 0xC9, 0x0F, 0x84,
            0xF7, 0x02, 0x00, 0x00, 0xB8, 0x4D, 0x5A, 0x00, 0x00, 0x66, 0x41, 0x39, 0x01, 0x0F, 0x85, 0xE8,
            0x02, 0x00, 0x00, 0x49, 0x63, 0x41, 0x3C, 0x42, 0x81, 0x3C, 0x08, 0x50, 0x45, 0x00, 0x00, 0x0F,
            0x85, 0xD6, 0x02, 0x00, 0x00, 0x42, 0x8B, 0x84, 0x08, 0x88, 0x00, 0x00, 0x00, 0x49, 0x03, 0xC1,
            0x0F, 0x84, 0xC5, 0x02, 0x00, 0x00, 0x44, 0x8B, 0x50, 0x20, 0x48, 0x89, 0xAC, 0x24, 0xA0, 0x00,
            0x00, 0x00, 0x48, 0x89, 0xB4, 0x24, 0xA8, 0x00, 0x00, 0x00, 0x4C, 0x89, 0x74, 0x24, 0x60, 0x4D,
            0x03, 0xD1, 0x0F, 0x84, 0xC7, 0x00, 0x00, 0x00, 0x8B, 0x78, 0x24, 0x49, 0x03, 0xF9, 0x0F, 0x84,
            0xBB, 0x00, 0x00, 0x00, 0x8B, 0x70, 0x1C, 0x49, 0x03, 0xF1, 0x0F, 0x84, 0xAF, 0x00, 0x00, 0x00,
            0x8B, 0x58, 0x14, 0x45, 0x8B, 0xDF, 0x85, 0xDB, 0x74, 0x4A, 0x48, 0xBD, 0x5F, 0x51, 0x4B, 0x9E,
            0x4B, 0xC6, 0x65, 0xCC, 0x0F, 0x1F, 0x40, 0x00, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x8B, 0x02, 0x49, 0x8B, 0xD5, 0x4D, 0x03, 0xC1, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x49, 0x0F, 0xBE, 0x08, 0x4D, 0x8D, 0x40, 0x01, 0x48, 0x33, 0xD1, 0x49, 0x0F, 0xAF, 0xD4, 0x84,
            0xC9, 0x75, 0xED, 0x48, 0x3B, 0xD5, 0x74, 0x33, 0x41, 0xFF, 0xC3, 0x49, 0x83, 0xC2, 0x04, 0x44,
            0x3B, 0xDB, 0x72, 0xCC, 0x49, 0x63, 0x41, 0x3C, 0x49, 0x8B, 0xFF, 0x42, 0x8B, 0x8C, 0x08, 0x88,
            0x00, 0x00, 0x00, 0x49, 0x03, 0xC9, 0x44, 0x8B, 0x51, 0x20, 0x8B, 0x69, 0x24, 0x4D, 0x03, 0xD1,
            0x8B, 0x71, 0x1C, 0x49, 0x03, 0xE9, 0x49, 0x03, 0xF1, 0xEB, 0x6B, 0x41, 0x8B, 0xC3, 0x0F, 0xB7,
            0x0C, 0x47, 0x49, 0x63, 0x41, 0x3C, 0x8B, 0x3C, 0x8E, 0x42, 0x8B, 0x8C, 0x08, 0x88, 0x00, 0x00,
            0x00, 0x49, 0x03, 0xF9, 0x49, 0x03, 0xC9, 0x44, 0x8B, 0x51, 0x20, 0x8B, 0x69, 0x24, 0x4D, 0x03,
            0xD1, 0x8B, 0x71, 0x1C, 0x49, 0x03, 0xE9, 0x8B, 0x59, 0x14, 0x49, 0x03, 0xF1, 0xEB, 0x3E, 0x49,
            0x63, 0x41, 0x3C, 0x49, 0x8B, 0xFF, 0x42, 0x8B, 0x8C, 0x08, 0x88, 0x00, 0x00, 0x00, 0x49, 0x03,
            0xC9, 0x44, 0x8B, 0x51, 0x20, 0x4D, 0x03, 0xD1, 0x0F, 0x84, 0xC4, 0x00, 0x00, 0x00, 0x8B, 0x69,
            0x24, 0x49, 0x03, 0xE9, 0x0F, 0x84, 0xB8, 0x00, 0x00, 0x00, 0x8B, 0x71, 0x1C, 0x49, 0x03, 0xF1,
            0x0F, 0x84, 0xAC, 0x00, 0x00, 0x00, 0x8B, 0x59, 0x14, 0x85, 0xDB, 0x74, 0x47, 0x45, 0x8B, 0xDF,
            0x49, 0xBE, 0xF9, 0xF9, 0xB7, 0x25, 0x29, 0x55, 0x67, 0xF5, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00,
            0x45, 0x8B, 0x02, 0x49, 0x8B, 0xD5, 0x4D, 0x03, 0xC1, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x49, 0x0F, 0xBE, 0x08, 0x4D, 0x8D, 0x40, 0x01, 0x48, 0x33, 0xD1, 0x49, 0x0F, 0xAF, 0xD4, 0x84,
            0xC9, 0x75, 0xED, 0x49, 0x3B, 0xD6, 0x74, 0x34, 0x41, 0xFF, 0xC3, 0x49, 0x83, 0xC2, 0x04, 0x44,
            0x3B, 0xDB, 0x72, 0xCC, 0x49, 0x63, 0x41, 0x3C, 0x49, 0x8B, 0xDF, 0x42, 0x8B, 0x8C, 0x08, 0x88,
            0x00, 0x00, 0x00, 0x49, 0x03, 0xC9, 0x44, 0x8B, 0x51, 0x20, 0x44, 0x8B, 0x71, 0x24, 0x4D, 0x03,
            0xD1, 0x8B, 0x69, 0x1C, 0x4D, 0x03, 0xF1, 0x49, 0x03, 0xE9, 0xEB, 0x62, 0x41, 0x8B, 0xC3, 0x0F,
            0xB7, 0x4C, 0x45, 0x00, 0x49, 0x63, 0x41, 0x3C, 0x8B, 0x1C, 0x8E, 0x42, 0x8B, 0x8C, 0x08, 0x88,
            0x00, 0x00, 0x00, 0x49, 0x03, 0xD9, 0x49, 0x03, 0xC9, 0x44, 0x8B, 0x51, 0x20, 0x44, 0x8B, 0x71,
            0x24, 0x4D, 0x03, 0xD1, 0x8B, 0x69, 0x1C, 0x4D, 0x03, 0xF1, 0x8B, 0x71, 0x14, 0x49, 0x03, 0xE9,
            0xEB, 0x33, 0x49, 0x63, 0x41, 0x3C, 0x49, 0x8B, 0xDF, 0x42, 0x8B, 0x8C, 0x08, 0x88, 0x00, 0x00,
            0x00, 0x49, 0x03, 0xC9, 0x44, 0x8B, 0x51, 0x20, 0x4D, 0x03, 0xD1, 0x74, 0x79, 0x44, 0x8B, 0x71,
            0x24, 0x4D, 0x03, 0xF1, 0x74, 0x70, 0x8B, 0x69, 0x1C, 0x49, 0x03, 0xE9, 0x74, 0x68, 0x8B, 0x71,
            0x14, 0x85, 0xF6, 0x74, 0x61, 0x45, 0x8B, 0xDF, 0x49, 0xBD, 0xE3, 0x59, 0xCC, 0x66, 0xEC, 0x5F,
            0xC4, 0x2B, 0x0F, 0x1F, 0x40, 0x00, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x8B, 0x02, 0x48, 0xBA, 0xC3, 0x22, 0x22, 0x84, 0xE4, 0x9C, 0xF2, 0xCB, 0x4D, 0x03, 0xC1,
            0x49, 0x0F, 0xBE, 0x08, 0x4D, 0x8D, 0x40, 0x01, 0x48, 0x33, 0xD1, 0x49, 0x0F, 0xAF, 0xD4, 0x84,
            0xC9, 0x75, 0xED, 0x49, 0x3B, 0xD5, 0x74, 0x0E, 0x41, 0xFF, 0xC3, 0x49, 0x83, 0xC2, 0x04, 0x44,
            0x3B, 0xDE, 0x72, 0xCC, 0xEB, 0x10, 0x41, 0x8B, 0xC3, 0x41, 0x0F, 0xB7, 0x0C, 0x46, 0x44, 0x8B,
            0x7C, 0x8D, 0x00, 0x4D, 0x03, 0xF9, 0x4C, 0x8B, 0x74, 0x24, 0x60, 0x48, 0x8B, 0xB4, 0x24, 0xA8,
            0x00, 0x00, 0x00, 0x48, 0x8B, 0xAC, 0x24, 0xA0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xFF, 0x74, 0x4B,
            0x4C, 0x8D, 0x4C, 0x24, 0x20, 0xBA, 0x20, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x44, 0x24, 0x30, 0x48,
            0x8D, 0x8C, 0x24, 0x98, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xD7, 0x85, 0xC0, 0x78, 0x2D, 0x48, 0x85,
            0xDB, 0x74, 0x19, 0x48, 0x8B, 0x8C, 0x24, 0x98, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC9, 0x74, 0x1B,
            0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x41, 0x8D, 0x51, 0x11, 0xFF, 0xD3, 0x48, 0x8B, 0x8C, 0x24,
            0x98, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC9, 0x74, 0x02, 0xFF, 0xD7, 0x4C, 0x8B, 0x64, 0x24, 0x70,
            0x48, 0x8B, 0x7C, 0x24, 0x78, 0x48, 0x8B, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x6C,
            0x24, 0x68, 0x32, 0xC0, 0x48, 0x81, 0xC4, 0x80, 0x00, 0x00, 0x00, 0x41, 0x5F, 0xC3
        };

        uint8_t shell_hide_thread_32[] = 
        {
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x44, 0xC7, 0x45, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x57, 0xC0,
            0xC7, 0x45, 0xC0, 0x18, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xD4, 0x00, 0x00, 0x00, 0x00, 0x53, 0x56,
            0x57, 0x0F, 0x11, 0x45, 0xC4, 0x85, 0xC9, 0x0F, 0x84, 0x5A, 0x01, 0x00, 0x00, 0x64, 0xA1, 0x30,
            0x00, 0x00, 0x00, 0x89, 0x4D, 0xDC, 0xC7, 0x45, 0xD8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x48, 0x0C,
            0x8B, 0x41, 0x18, 0x83, 0xC1, 0x14, 0x89, 0x4D, 0xF4, 0x89, 0x45, 0xE4, 0x8B, 0x19, 0x3B, 0xD9,
            0x74, 0x40, 0x8B, 0xC3, 0x8B, 0x50, 0x28, 0x8D, 0x78, 0xF8, 0x85, 0xD2, 0x74, 0x22, 0xBE, 0x5C,
            0x9D, 0x1C, 0x81, 0x0F, 0xB7, 0x0A, 0x8D, 0x52, 0x02, 0x8B, 0xC1, 0x33, 0xC6, 0x69, 0xF0, 0x2A,
            0x01, 0x00, 0x01, 0x66, 0x85, 0xC9, 0x75, 0xEB, 0x81, 0xFE, 0x50, 0xB5, 0x03, 0x52, 0x74, 0x14,
            0x8B, 0x4B, 0x04, 0x8B, 0x1B, 0x8B, 0xC3, 0x89, 0x4D, 0xE4, 0x89, 0x4D, 0xE4, 0x3B, 0x45, 0xF4,
            0x75, 0xC2, 0x33, 0xFF, 0x8B, 0x77, 0x18, 0x85, 0xF6, 0x0F, 0x84, 0xE8, 0x00, 0x00, 0x00, 0xB8,
            0x4D, 0x5A, 0x00, 0x00, 0x66, 0x39, 0x06, 0x0F, 0x85, 0xDA, 0x00, 0x00, 0x00, 0x8B, 0x46, 0x3C,
            0x8D, 0x4E, 0x3C, 0x89, 0x4D, 0xFC, 0x81, 0x3C, 0x30, 0x50, 0x45, 0x00, 0x00, 0x0F, 0x84, 0xCD,
            0x00, 0x00, 0x00, 0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xF4, 0x00, 0x00, 0x00,
            0x00, 0x8B, 0x45, 0xFC, 0x8B, 0x00, 0x81, 0x3C, 0x30, 0x50, 0x45, 0x00, 0x00, 0x75, 0x6A, 0x8B,
            0x44, 0x30, 0x78, 0x03, 0xC6, 0x74, 0x62, 0x8B, 0x48, 0x20, 0x03, 0xCE, 0x89, 0x4D, 0xE8, 0x74,
            0x58, 0x8B, 0x50, 0x24, 0x03, 0xD6, 0x89, 0x55, 0xEC, 0x74, 0x4E, 0x8B, 0x50, 0x1C, 0x03, 0xD6,
            0x89, 0x55, 0xFC, 0x74, 0x44, 0x8B, 0x40, 0x14, 0x33, 0xDB, 0x89, 0x45, 0xE4, 0x85, 0xC0, 0x74,
            0x38, 0x8B, 0x14, 0x99, 0xBF, 0x5C, 0x9D, 0x1C, 0x81, 0x03, 0xD6, 0x0F, 0x1F, 0x44, 0x00, 0x00,
            0x8A, 0x0A, 0x8D, 0x52, 0x01, 0x0F, 0xBE, 0xC1, 0x33, 0xC7, 0x69, 0xF8, 0x2A, 0x01, 0x00, 0x01,
            0x84, 0xC9, 0x75, 0xEC, 0x81, 0xFF, 0x68, 0xDE, 0xC3, 0xEC, 0x0F, 0x84, 0x80, 0x01, 0x00, 0x00,
            0x8B, 0x4D, 0xE8, 0x43, 0x3B, 0x5D, 0xE4, 0x72, 0xC8, 0x33, 0xC0, 0x8B, 0x75, 0xF8, 0x85, 0xF6,
            0x74, 0x35, 0x8D, 0x4D, 0xD8, 0x51, 0x8D, 0x4D, 0xC0, 0x51, 0x6A, 0x20, 0x8D, 0x4D, 0xF0, 0x51,
            0xFF, 0xD0, 0x85, 0xC0, 0x78, 0x21, 0x8B, 0x45, 0xF4, 0x85, 0xC0, 0x74, 0x10, 0x8B, 0x4D, 0xF0,
            0x85, 0xC9, 0x74, 0x13, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x11, 0x51, 0xFF, 0xD0, 0x8B, 0x45, 0xF0,
            0x85, 0xC0, 0x74, 0x03, 0x50, 0xFF, 0xD6, 0x5F, 0x5E, 0x32, 0xC0, 0x5B, 0x8B, 0xE5, 0x5D, 0xC3,
            0x8B, 0x44, 0x30, 0x78, 0x03, 0xC6, 0x74, 0x64, 0x8B, 0x50, 0x20, 0x03, 0xD6, 0x89, 0x55, 0xF8,
            0x74, 0x5A, 0x8B, 0x58, 0x24, 0x03, 0xDE, 0x89, 0x5D, 0xFC, 0x74, 0x50, 0x8B, 0x58, 0x1C, 0x03,
            0xDE, 0x89, 0x5D, 0xEC, 0x74, 0x46, 0x8B, 0x40, 0x14, 0x33, 0xDB, 0x89, 0x45, 0xF4, 0x85, 0xC0,
            0x74, 0x3A, 0x8B, 0x14, 0x9A, 0xBF, 0x5C, 0x9D, 0x1C, 0x81, 0x03, 0xD6, 0x0F, 0x1F, 0x40, 0x00,
            0x8A, 0x0A, 0x8D, 0x52, 0x01, 0x0F, 0xBE, 0xC1, 0x33, 0xC7, 0x69, 0xF8, 0x2A, 0x01, 0x00, 0x01,
            0x84, 0xC9, 0x75, 0xEC, 0x81, 0xFF, 0xBC, 0xBE, 0x9A, 0xAF, 0x0F, 0x84, 0x9A, 0x00, 0x00, 0x00,
            0x8B, 0x55, 0xF8, 0x43, 0x3B, 0x5D, 0xF4, 0x72, 0xC9, 0x8D, 0x4E, 0x3C, 0x8B, 0x01, 0xC7, 0x45,
            0xF8, 0x00, 0x00, 0x00, 0x00, 0x89, 0x4D, 0xFC, 0x03, 0xC6, 0x8B, 0x40, 0x78, 0x03, 0xC6, 0x0F,
            0x84, 0xB5, 0xFE, 0xFF, 0xFF, 0x8B, 0x48, 0x20, 0x03, 0xCE, 0x89, 0x4D, 0xF4, 0x0F, 0x84, 0xA7,
            0xFE, 0xFF, 0xFF, 0x8B, 0x50, 0x24, 0x03, 0xD6, 0x89, 0x55, 0xE8, 0x0F, 0x84, 0x99, 0xFE, 0xFF,
            0xFF, 0x8B, 0x50, 0x1C, 0x03, 0xD6, 0x89, 0x55, 0xE4, 0x0F, 0x84, 0x8B, 0xFE, 0xFF, 0xFF, 0x8B,
            0x40, 0x14, 0x33, 0xDB, 0x89, 0x45, 0xEC, 0x85, 0xC0, 0x0F, 0x84, 0x7B, 0xFE, 0xFF, 0xFF, 0x90,
            0x8B, 0x14, 0x99, 0xBF, 0x5C, 0x9D, 0x1C, 0x81, 0x03, 0xD6, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00,
            0x8A, 0x0A, 0x8D, 0x52, 0x01, 0x0F, 0xBE, 0xC1, 0x33, 0xC7, 0x69, 0xF8, 0x2A, 0x01, 0x00, 0x01,
            0x84, 0xC9, 0x75, 0xEC, 0x81, 0xFF, 0x68, 0xE6, 0xDC, 0x35, 0x74, 0x2D, 0x8B, 0x4D, 0xF4, 0x43,
            0x3B, 0x5D, 0xEC, 0x72, 0xCB, 0xE9, 0x40, 0xFE, 0xFF, 0xFF, 0x8B, 0x45, 0xFC, 0x8B, 0x4D, 0xEC,
            0x0F, 0xB7, 0x04, 0x58, 0x8B, 0x14, 0x81, 0x8D, 0x46, 0x3C, 0x03, 0xD6, 0x89, 0x45, 0xFC, 0x8B,
            0x00, 0x89, 0x55, 0xF8, 0xE9, 0x5F, 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xE8, 0x8B, 0x4D, 0xE4, 0x0F,
            0xB7, 0x04, 0x58, 0x8B, 0x0C, 0x81, 0x03, 0xCE, 0x89, 0x4D, 0xF4, 0xE9, 0x11, 0xFE, 0xFF, 0xFF,
            0x8B, 0x45, 0xEC, 0x8B, 0x4D, 0xFC, 0x0F, 0xB7, 0x04, 0x58, 0x8B, 0x04, 0x81, 0x03, 0xC6, 0xE9,
            0x77, 0xFE, 0xFF, 0xFF
        };


        INLINE auto get_process_exp(PVOID nt_query_system_information) -> uint32_t
        {
            ULONG ret_lenght = NULL;
            uint32_t process_id = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
            PVOID buffer = NULL;
            PSYSTEM_PROCESS_INFORMATION process_info = NULL;
            
            nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemProcessInformation, &ret_lenght, ret_lenght, &ret_lenght);

            while (nt_status == STATUS_INFO_LENGTH_MISMATCH)
            {
                if (buffer != NULL)
                    crt_wrapper::free(buffer);
                buffer = crt_wrapper::malloc(ret_lenght);
                nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemProcessInformation, buffer, ret_lenght, &ret_lenght);
            }

            if (!NT_SUCCESS(nt_status))
            { 
                crt_wrapper::free(buffer);
                return NULL;
            }  

            process_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
            while (process_info->NextEntryOffset) // Loop over the list until we reach the last entry.
            {
                
                if (crt_wrapper::wstricmp(process_info->ImageName.Buffer, L"explorer.exe") == NULL)
                { 
                    process_id = reinterpret_cast<uint32_t>(process_info->UniqueProcessId);
                    break;
                } 
                process_info = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)process_info + process_info->NextEntryOffset); // Calculate the address of the next entry.
            }
            crt_wrapper::free(buffer);
            return process_id;

        }
		
		//Hide thread by explorer.exe(PsGetCurrentProcessId() bypass) WoW64 not correct
        INLINE auto hide_thread_shell(PVOID nt_query_system_information,PVOID nt_close) -> VOID
        {
            
            INT inf_proc = NULL;
            INT is_wow_64 = NULL;
            INT is_write_correct = NULL;
            uint32_t pid_explorer = NULL;
            uint64_t is_detect = FALSE;
            HANDLE proc_oper = NULL;
            HANDLE thread_handle = NULL;
            LPVOID allocate_shell = NULL; 

            pid_explorer = get_process_exp(nt_query_system_information);
            if (!pid_explorer)
                return;
            proc_oper = OpenProcess(PROCESS_QUERY_INFORMATION  | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, pid_explorer);
            if (proc_oper)
            {
                allocate_shell = VirtualAllocEx(proc_oper, NULL,sizeof(shell_hide_thread_64) + sizeof(shell_hide_thread_32), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (allocate_shell)
                {
                    inf_proc = crt_wrapper::get_proc_info::get_process_platform();
                    IsWow64Process(proc_oper, &is_wow_64);

                    if (inf_proc == PROCESS_32)
                        is_write_correct = WriteProcessMemory(proc_oper, allocate_shell, shell_hide_thread_32, sizeof(shell_hide_thread_32), NULL);
                    else if(!is_wow_64 && inf_proc == PROCESS_64)
                        is_write_correct = WriteProcessMemory(proc_oper, allocate_shell, shell_hide_thread_64, sizeof(shell_hide_thread_64), NULL);
                    
                    if (is_write_correct)
                    {
                        thread_handle = CreateRemoteThread(proc_oper, NULL, 0x1000, reinterpret_cast<LPTHREAD_START_ROUTINE>(allocate_shell), (LPVOID)NtCurrentTeb()->ClientId.UniqueThread, NULL, NULL);
                        if (thread_handle)
                            Sleep(5);

                        if (thread_handle)
                            reinterpret_cast<decltype(&NtClose)>(nt_close)(thread_handle);
                    }
                    VirtualFree(allocate_shell, NULL, MEM_RELEASE);
                }
                reinterpret_cast<decltype(&NtClose)>(nt_close)(proc_oper);
            }
        }


    }



    namespace seh_filter
    {
#if defined(__clang__)
        //Use BP for trigger SEH
        __declspec(allocate(".text")) uint8_t seh_bp_arry[] =
        {
            0xCC,//int3
            0xC3//ret
        };
#else
         NO_INLINE auto seh_bp_functhion() -> VOID
        {
            __debugbreak();
            return;
        }
#endif
        INLINE auto is_set_any_bp(PEXCEPTION_POINTERS p_excep, bool* p_is_detect) -> LONG
        {

            if (p_excep->ContextRecord->Dr0 != NULL ||
                p_excep->ContextRecord->Dr1 != NULL ||
                p_excep->ContextRecord->Dr2 != NULL ||
                p_excep->ContextRecord->Dr3 != NULL ||
                p_excep->ContextRecord->Dr7 != NULL
                )
            {
                *p_is_detect = TRUE;
            }

            return EXCEPTION_EXECUTE_HANDLER;
        }



        /*
            Compare my set BP by NtSetContextThread and SEH
        */
        INLINE auto compare_seh_bp(PEXCEPTION_POINTERS p_excep, PCONTEXT p_ctx, bool* p_is_detect) -> LONG
        {

            if (p_ctx->Dr0 != p_excep->ContextRecord->Dr0 ||
                p_ctx->Dr1 != p_excep->ContextRecord->Dr1 ||
                p_ctx->Dr2 != p_excep->ContextRecord->Dr2 ||
                p_ctx->Dr3 != p_excep->ContextRecord->Dr3
                )
            {
                *p_is_detect = TRUE;
            }

            return EXCEPTION_EXECUTE_HANDLER;
        }

        /*
            Check Dr2 by raise info
        */
        INLINE auto is_trigger_correct_dr(PEXCEPTION_POINTERS p_excep, PCONTEXT p_ctx, bool* p_is_detect) -> LONG
        {
            if (p_excep->ContextRecord->Dr0 != NULL ||
                p_excep->ContextRecord->Dr1 != NULL ||
                p_ctx->Dr2 != p_excep->ContextRecord->Dr2 ||
                p_excep->ContextRecord->Dr3 != NULL ||
                (p_excep->ContextRecord->Dr6 & (1 << 4) == NULL) || //Is raise by Dr2?
                p_excep->ContextRecord->Dr6 == NULL ||
#if defined(__clang__)
                p_excep->ExceptionRecord->ExceptionAddress != reinterpret_cast<PVOID>(seh_filter::seh_bp_arry)// Is correct address exception?
#else
                p_excep->ExceptionRecord->ExceptionAddress != reinterpret_cast<PVOID>(seh_bp_functhion)// Is correct address exception?
#endif
                )
            {
                *p_is_detect = TRUE;
            }
            return EXCEPTION_EXECUTE_HANDLER;
        }

       

    }
     
    namespace driver_off
    {
        //Don't protect open HANDLE to driver
        INLINE auto disable_titan_hide() -> VOID
        {
            DWORD written = NULL;
            HIDE_INFO titan_hide;
            HANDLE driver_handle = NULL;

            driver_handle = CreateFileA("\\\\.\\TitanHide", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, NULL, NULL);
            if (driver_handle == INVALID_HANDLE_VALUE)
                return;

            titan_hide.Command = UnhideAll;
            titan_hide.Pid = NtCurrentProcessId();
            titan_hide.Type = 0x3FF;//0b1111111111 (10 bit 1)
        
            WriteFile(driver_handle, &titan_hide, sizeof(titan_hide), &written, NULL);
            CloseHandle(driver_handle);
        }
    } 

   /*
   https://github.com/Air14/HyperHide/blob/1976e07c584ed171fc5e92407c18c485e6a608d8/HyperHideDrv/HookedFunctions.cpp#L42
   HyperHide check if ProcessInformationLength != NULL,but system don't chekc this
   https://github.com/HighSchoolSoftwareClub/Windows-Research-Kernel-WRK-/blob/26b524b2d0f18de703018e16ec5377889afcf4ab/WRK-v1.2/base/ntos/ps/psquery.c#L644
   (work only with ReturnLength,because ProcessInformationLength shoult be NULL,so ProbeForRead don't triggered)
   TitanHide have mem update,but don't correct consistency - https://github.com/mrexodia/TitanHide/blob/6a5a68a2447ad9454adfcbd9390ec05b9dcef2d6/TitanHide/hooks.cpp#L468
   Pasting code from HyperHide https://github.com/AyinSama/Anti-AntiDebuggerDriver/blob/ba99fbfe40de6c5cb1f1714a18d7dda3dbcebe1b/Main.cpp#L129
  */
    class debug_object_present
    {
    private:
        
        PVOID nt_close = NULL;
        PVOID nt_query_information_process = NULL;
        PVOID nt_query_system_information = NULL;
        INT build_number = NULL; // crt_wrapper::get_windows_number();
        INT inf_proc = NULL;

        INLINE auto init_struct(bool is_manual_syscall) -> bool
        { 
            inf_proc = crt_wrapper::get_proc_info::get_process_platform();

            nt_query_information_process = LI_FN(NtQueryInformationProcess).nt_cached();
            build_number = crt_wrapper::get_windows_number();
            nt_close = LI_FN(NtClose).nt_cached();
            nt_query_system_information = LI_FN(NtQuerySystemInformation).nt_cached();
            return nt_close && nt_query_information_process && nt_query_system_information;
        }

    public:

        NO_INLINE auto is_debug_object_present(bool is_manual_syscall = TRUE )-> bool
        {
            bool is_detect = FALSE;
            uint64_t kernel_address = NULL;
            uint64_t self_handle_number = NULL;
            HANDLE debug_object = reinterpret_cast<HANDLE>(1);
            HANDLE bug_handle = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

            if (!init_struct(is_manual_syscall))
                return FALSE;

            driver_off::disable_titan_hide();

            self_handle_number = crt_wrapper::get_number_handle(nt_query_system_information);

#ifdef _WIN64
            kernel_address = 0xFFFFF80000000000 + __rdtsc() % 0x10000000000; //Crazy value
#else
            if (inf_proc & PROCESS_32)
            {
                kernel_address = 0x7FFF000;
            }
            else if (inf_proc & PROCESS_WOW64)
            {
                kernel_address = 0xFFFFF80000000000 + __rdtsc() % 0x10000000000; //Crazy value
            }
#endif // _WIN64
             

            bug_handle = OpenProcess(PROCESS_SET_INFORMATION, FALSE, (DWORD)NtCurrentTeb()->ClientId.UniqueProcess);
            if (bug_handle)
            { 
                BREAK_INFO();
                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), NULL);
                RESTORE_INFO();
                reinterpret_cast<decltype(&NtClose)>(nt_close)(bug_handle);

                if (nt_status != STATUS_ACCESS_DENIED || reinterpret_cast<ULONG>(debug_object) != 1)
                {
                    is_detect = TRUE;
                }
            }
             
            bug_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)NtCurrentTeb()->ClientId.UniqueProcess);
            if (bug_handle)
            {
                BREAK_INFO();

                //Try BSOD by don't check address buffer in ProcessInformation
                for (uint8_t i = NULL; i < 0x10; i++, kernel_address += (0x10000000 + __rdtsc() % 0x1000000000))
                {
                  
                   reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, reinterpret_cast<PVOID>(kernel_address), sizeof(HANDLE), NULL);
                   reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, reinterpret_cast<PVOID>(kernel_address), NULL, NULL);
                   reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, NULL, NULL, reinterpret_cast<PULONG>(kernel_address));
                   reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), reinterpret_cast<PULONG>(&debug_object));
                
                }  

                debug_object = reinterpret_cast<HANDLE>(NULL);
                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), NULL);

                if (nt_status != STATUS_PORT_NOT_SET || reinterpret_cast<ULONG>(debug_object) != NULL)
                {
                    LI_FN(NtRemoveProcessDebug).nt_cached()(NtCurrentProcess, debug_object);
                    is_detect = TRUE;
                }
                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), reinterpret_cast<PULONG>(&debug_object));
                if (nt_status != STATUS_PORT_NOT_SET || reinterpret_cast<uint64_t>(debug_object) != sizeof(debug_object))
                    is_detect = TRUE;

                debug_object = reinterpret_cast<HANDLE>(1);

#ifdef _WIN64  
                //Alignment Fault check
                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, reinterpret_cast<PVOID>(5), sizeof(debug_object), NULL);
                if ((nt_status != STATUS_DATATYPE_MISALIGNMENT && nt_status != STATUS_INVALID_INFO_CLASS) || debug_object != reinterpret_cast<HANDLE>(1))
                {
                    is_detect = TRUE;
                }
#else 
                if (inf_proc & PROCESS_32)
                {
                    //Alignment Fault check
                    nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, reinterpret_cast<PVOID>(5), sizeof(debug_object), NULL);
                    if ((nt_status != STATUS_DATATYPE_MISALIGNMENT && nt_status != STATUS_INVALID_INFO_CLASS) || debug_object != reinterpret_cast<HANDLE>(1))
                    {
                        //return TRUE;
                    }
                }
                else if (inf_proc & PROCESS_WOW64)
                {
                    // WOW_CALL()
                }
#endif // _WIN64
                 

                //- neko wife
                if (reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, &debug_object, sizeof(BOOLEAN), NULL) != STATUS_INFO_LENGTH_MISMATCH)
                    is_detect = TRUE;

                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), reinterpret_cast<PULONG>(kernel_address % 0x1000));
                if ((nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT) || debug_object != reinterpret_cast<HANDLE>(1))
                    is_detect = TRUE;
                 
                //HyperHide return STATUS_INFO_LENGTH_MISMATCH,but should be STATUS_ACCESS_VIOLATION
                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(bug_handle, ProcessDebugObjectHandle, &debug_object, NULL, reinterpret_cast<PULONG>(kernel_address % 0x1000));
                if ((nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT) || debug_object != reinterpret_cast<HANDLE>(1))
                    is_detect = TRUE;

                //TitanHide return STATUS_INVALID_HANDLE,but should be STATUS_ACCESS_VIOLATION
                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NULL, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), reinterpret_cast<PULONG>(kernel_address % 0x1000));
                if ((nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT) || debug_object != reinterpret_cast<HANDLE>(1))
                    is_detect = TRUE;
                reinterpret_cast<decltype(&NtClose)>(nt_close)(bug_handle);
                RESTORE_INFO();
            }
            else
            {
                //Try BSOD by don't check address buffer in ProcessInformation
                for (uint8_t i = NULL; i < 0x10; i++, kernel_address += (0x10000000 + __rdtsc() % 0x1000000000))
                {
                    
                    reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, reinterpret_cast<PVOID>(kernel_address), sizeof(HANDLE), NULL);
                    reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, reinterpret_cast<PVOID>(kernel_address), NULL, NULL);
                    reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, NULL, NULL, reinterpret_cast<PULONG>(kernel_address));
                    reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), reinterpret_cast<PULONG>(&debug_object));
                
                }
                debug_object = reinterpret_cast<HANDLE>(NULL);

                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), NULL);
                if (nt_status != STATUS_PORT_NOT_SET || debug_object != NULL)
                {
                    LI_FN(NtRemoveProcessDebug).nt_cached()(NtCurrentProcess, debug_object);
                    is_detect = TRUE;
                }

                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), reinterpret_cast<PULONG>(&debug_object));
                if (nt_status != STATUS_PORT_NOT_SET || reinterpret_cast<uint64_t>(debug_object) != sizeof(debug_object))
                    return TRUE;

                debug_object = reinterpret_cast<HANDLE>(1);

#ifdef _WIN64  
                //Alignment Fault check
                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, reinterpret_cast<PVOID>(5), sizeof(debug_object), NULL);
                if ((nt_status != STATUS_DATATYPE_MISALIGNMENT && nt_status != STATUS_INVALID_INFO_CLASS) || debug_object != reinterpret_cast<HANDLE>(1))
                    is_detect = TRUE;
#endif

                //- neko wife
                if (reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, sizeof(BOOLEAN), NULL) != STATUS_INFO_LENGTH_MISMATCH)
                    is_detect = TRUE;

                debug_object = reinterpret_cast<HANDLE>(1);

                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), reinterpret_cast<PULONG>(kernel_address % 0x1000));
                if ((nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT) || debug_object != reinterpret_cast<HANDLE>(1))
                    is_detect = TRUE;

                //HyperHide return STATUS_INFO_LENGTH_MISMATCH,but should be STATUS_ACCESS_VIOLATION
                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugObjectHandle, &debug_object, NULL, reinterpret_cast<PULONG>(kernel_address % 0x1000));
                if ((nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT) || debug_object != reinterpret_cast<HANDLE>(1))
                    is_detect = TRUE;

                //TitanHide return STATUS_INVALID_HANDLE,but should be STATUS_ACCESS_VIOLATION
                nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NULL, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), reinterpret_cast<PULONG>(kernel_address % 0x1000));
                if ((nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT) || debug_object != reinterpret_cast<HANDLE>(1))
                    is_detect = TRUE;
            }
            if (crt_wrapper::get_number_handle(nt_query_system_information) - self_handle_number > 0x10)
                is_detect = TRUE;
            return is_detect;

        }

    };

    class debug_flag_present
    {
    private:

        PVOID nt_close = NULL;
        PVOID nt_query_information_process = NULL;
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
        PVOID nt_set_informathion_process = NULL;

        INLINE auto init_struct() -> bool
        {
            if (nt_set_informathion_process && nt_close && nt_query_information_process)
                return TRUE;

            nt_query_information_process = LI_FN(NtQueryInformationProcess).nt_cached();
            nt_close = LI_FN(NtClose).nt_cached();
            nt_set_informathion_process = LI_FN(NtSetInformationProcess).nt_cached();
            return nt_set_informathion_process && nt_close && nt_query_information_process;
        }

    public:
    NO_INLINE auto is_debug_flag_hooked() -> bool
    {
        bool is_detect = FALSE;
        HANDLE bug_handle = NULL;
        uint32_t debug_flag = NULL;
        uint32_t  safe_value = NULL;
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
 
        if (!init_struct())
            return FALSE;

        driver_off::disable_titan_hide();

        //Crash ScyllaHide 
        nt_status = reinterpret_cast<decltype(&NtSetInformationProcess)>(nt_set_informathion_process)(NtCurrentProcess, ProcessDebugFlags, reinterpret_cast<PVOID>(1), sizeof(debug_flag));
        if (NT_SUCCESS(nt_status))
            return TRUE;

        bug_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)NtCurrentTeb()->ClientId.UniqueProcess);
        if (bug_handle)
        {
            nt_status = reinterpret_cast<decltype(&NtSetInformationProcess)>(nt_set_informathion_process)(bug_handle, ProcessDebugFlags, &debug_flag, sizeof(debug_flag));
            reinterpret_cast<decltype(&NtClose)>(nt_close)(bug_handle);
            if (NT_SUCCESS(nt_status))
                is_detect = TRUE;
        }

        nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugFlags, &debug_flag, sizeof(debug_flag), NULL);
        safe_value = debug_flag; //Safe value for present some problem 

        if (!NT_SUCCESS(nt_status))
            return is_detect;

        debug_flag = !debug_flag;

        nt_status = reinterpret_cast<decltype(&NtSetInformationProcess)>(nt_set_informathion_process)(NtCurrentProcess, ProcessDebugFlags, &debug_flag, sizeof(debug_flag));

        //Can't set value
        if (!NT_SUCCESS(nt_status))
            return is_detect;

        nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugFlags, &debug_flag, sizeof(debug_flag), NULL);
        if (NT_SUCCESS(nt_status) && debug_flag != NULL)
            is_detect = TRUE;

        reinterpret_cast<decltype(&NtSetInformationProcess)>(nt_set_informathion_process)(NtCurrentProcess, ProcessDebugFlags, &safe_value, sizeof(safe_value));

        nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_information_process)(NtCurrentProcess, ProcessDebugFlags, &debug_flag, NULL, reinterpret_cast<PULONG>(1));
        if (nt_status == STATUS_INFO_LENGTH_MISMATCH)
            is_detect = TRUE;

        return is_detect;
    }
    };

    //HyperHide don't clean
    INLINE auto check_lazy_process_parametr() -> bool
    { 
        //(NtCurrentPeb()->ProcessParameters->Flags & 0x4000) != NULL; in wWinMain
        return (NtCurrentPeb()->ProcessParameters->Flags & 0x4000) == NULL;
    }

    /*
    Anti-debug tool present set dr register.
    TitanHide/SchyllaHide and SharpOD just change ContextFlag - https://github.com/mrexodia/TitanHide/blob/6a5a68a2447ad9454adfcbd9390ec05b9dcef2d6/TitanHide/hooks.cpp#L66
    and can be easy detect.
    HyperHide do correct,but have bug(THREAD_SET_CONTEXT,but need THREAD_GET_CONTEXT)
    https://github.com/Air14/HyperHide/blob/1976e07c584ed171fc5e92407c18c485e6a608d8/HyperHideDrv/HookedFunctions.cpp#L929
    */

    class hwbp_present
    {
    private:
        PVOID nt_set_context_thread = NULL;
        PVOID nt_get_context_thread = NULL;
        PVOID add_vector_excepthion_handler = NULL;
        PVOID remove_vector_excepthion_handler = NULL; 
        PVOID nt_close = NULL;
         
        INLINE auto init_struct() -> bool
        {
            if (nt_set_context_thread && nt_get_context_thread)
                return TRUE;
            
            nt_set_context_thread = LI_FN(NtSetContextThread).nt_cached();
            nt_get_context_thread = LI_FN(NtGetContextThread).nt_cached();
            //add_vector_excepthion_handler = LI_FN(AddVectoredExceptionHandler).forwarded();
            //remove_vector_excepthion_handler = LI_FN(RemoveVectoredExceptionHandler).forwarded();
            nt_close = LI_FN(NtClose).forwarded();
            return nt_set_context_thread && nt_get_context_thread;
        }
        

    public:
        NO_INLINE auto is_bad_hwbp() -> bool
        {
            bool is_detect = FALSE;
            uint64_t random_number = 0xDeadC0de + __rdtsc() % 0x100000;
            CONTEXT ctx = { NULL };
            CONTEXT ctx_bug = { NULL };
            CONTEXT save_ctx = { NULL };
            HANDLE bug_handle = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
            PVOID guard_page = NULL;

            ctx.Dr0 = random_number;
            ctx.Dr1 = ctx.Dr0;
            ctx.Dr2 = ctx.Dr0;
            ctx.Dr3 = ctx.Dr0;
            ctx.Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);//Enable all HWBP
            save_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            ctx_bug.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            //Use SEH to first check
            __try
            {
#if defined(__clang__)
                reinterpret_cast<VOID(__cdecl*)()>(seh_filter::seh_bp_arry)();
#else
                anti_debug_bomber::seh_filter::seh_bp_functhion();
#endif
            }
            __except (seh_filter::is_set_any_bp(GetExceptionInformation(), &is_detect))
            {

            }
            if (!init_struct())
                return FALSE;


            driver_off::disable_titan_hide();

            bug_handle = OpenThread(THREAD_QUERY_INFORMATION , FALSE, reinterpret_cast<DWORD>(NtCurrentThreadId()));
            guard_page = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD);
            if (bug_handle)
            {
                if (guard_page)
                {
                    __try
                    {
                        reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context_thread)(bug_handle, reinterpret_cast<PCONTEXT>(bug_handle));
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        is_detect = TRUE;
                    }
                }
                reinterpret_cast<decltype(&NtClose)>(nt_close)(bug_handle);
            }
            if (guard_page)
                VirtualFree(guard_page, NULL, MEM_RELEASE);

            if (!NT_SUCCESS(reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context_thread)(NtCurrentThread, &save_ctx)))
                return is_detect;
            /*
            Intel & AMD:
             G0 through G3 (global breakpoint enable) flags (bits 1, 3, 5, and 7)  Enables (when set) the
            breakpoint condition for the associated breakpoint for all tasks. When a breakpoint condition is detected and its
            associated Gn flag is set, a debug exception is generated. The processor does not clear these flags on a task
            switch, allowing a breakpoint to be enabled for all tasks.
            */

            //Any HWBP ?
            if (save_ctx.Dr0 != NULL ||
                save_ctx.Dr0 != save_ctx.Dr1 ||
                save_ctx.Dr0 != save_ctx.Dr2 ||
                save_ctx.Dr0 != save_ctx.Dr3 ||
                crt_wrapper::safe_check_dr7_set_any(save_ctx.Dr7)
                )
            {
                is_detect = TRUE;
            }


            //Crash SharpOD/ScyllaHide
            if (NT_SUCCESS(reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context_thread)(NtCurrentThread, reinterpret_cast<PCONTEXT>(1))))
                return TRUE;
            if (NT_SUCCESS(reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context_thread)(NtCurrentThread, reinterpret_cast<PCONTEXT>(1))))
                return TRUE;

            if (NT_SUCCESS(LI_FN(NtContinue).nt_cached()(&ctx_bug, FALSE)))
            {
                if ((ctx_bug.ContextFlags & 0x10) == NULL)
                {
                    is_detect = TRUE;
                }
            }  

            if (!NT_SUCCESS(reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context_thread)(NtCurrentThread, &ctx)))
                return is_detect;
            if (!NT_SUCCESS(reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context_thread)(NtCurrentThread, &ctx)))
                return is_detect;


            //Is change?
            if (ctx.Dr0 != random_number ||
                ctx.Dr0 != ctx.Dr1 ||
                ctx.Dr0 != ctx.Dr2 ||
                ctx.Dr0 != ctx.Dr3 ||
                crt_wrapper::safe_check_dr7_not_set_any(ctx.Dr7)
                )
            {
                is_detect = TRUE; //TitanHide,SharpOD and SchyllaHide lul
            }


            ctx.Dr0 = 1;
            ctx.Dr1 = 1;
            ctx.Dr2 = 1;
            ctx.Dr3 = 1;
            ctx.Dr7 = NULL;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            bug_handle = OpenThread(THREAD_SET_CONTEXT, FALSE, reinterpret_cast<DWORD>(NtCurrentThreadId()));
            if (bug_handle)
            {
                BREAK_INFO();
                nt_status = reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context_thread)(bug_handle, &ctx);
                RESTORE_INFO();
                if (nt_status != STATUS_ACCESS_DENIED)
                {
                    is_detect = TRUE; //HyperHide lul
                }
                reinterpret_cast<decltype(&NtClose)>(nt_close)(bug_handle);
            }

            bug_handle = OpenThread(THREAD_GET_CONTEXT, FALSE, reinterpret_cast<DWORD>(NtCurrentThreadId()));
            if (bug_handle)
            {
                BREAK_INFO();
                nt_status = reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context_thread)(bug_handle, &ctx);
                RESTORE_INFO();
                reinterpret_cast<decltype(&NtClose)>(nt_close)(bug_handle);
            }
            if (!bug_handle || !NT_SUCCESS(nt_status))
            {
                nt_status = NT_SUCCESS(reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context_thread)(NtCurrentThread, &ctx));
            }

            //Is really change?
            if (NT_SUCCESS(nt_status))
            {
                if (ctx.Dr0 != random_number ||
                    ctx.Dr0 != ctx.Dr1 ||
                    ctx.Dr0 != ctx.Dr2 ||
                    ctx.Dr0 != ctx.Dr3 ||
                    crt_wrapper::safe_check_dr7_not_set_any(ctx.Dr7)
                    )
                {
                    is_detect = TRUE;  //TitanHide,SharpOD and SchyllaHide,lul
                }
            }
            //Start use SEH for compare
            __try
            {
#if defined(__clang__)
                reinterpret_cast<VOID(__cdecl*)()>(seh_filter::seh_bp_arry)();
#else
                anti_debug_bomber::seh_filter::seh_bp_functhion();
#endif
            }
            __except (seh_filter::compare_seh_bp(GetExceptionInformation(), &ctx, &is_detect))
            {

            }

            if (crt_wrapper::is_support_vendor()) //For check Dr6 correct(Intel/Amd only)
            {

                ctx.Dr0 = NULL;
                ctx.Dr1 = NULL;
#if defined(__clang__)
                ctx.Dr2 = reinterpret_cast<uint64_t>(seh_filter::seh_bp_arry);
#else
                ctx.Dr2 = reinterpret_cast<uint64_t>(anti_debug_bomber::seh_filter::seh_bp_functhion);
#endif
                ctx.Dr3 = NULL;
                ctx.Dr6 = NULL;//Bug in copy Dr6
                ctx.Dr7 = (1 << 4);//Enable only Dr2
                if (NT_SUCCESS(reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context_thread)(NtCurrentThread, &ctx)))
                {
                    __try
                    {
#if defined(__clang__)
                        reinterpret_cast<VOID(__cdecl*)()>(seh_filter::seh_bp_arry)();
#else
                        anti_debug_bomber::seh_filter::seh_bp_functhion();
#endif
                    }
                    __except (seh_filter::is_trigger_correct_dr(GetExceptionInformation(), &ctx, &is_detect))
                    {

                    }
                }

            }
            /*
            * 	PspGetContext
                if ( (TrapFrame->Dr7 & DR7_ACTIVE) != NULL )        // DR7_ACTIVE
                {
                  ContextRecord->Dr0 = TrapFrame->Dr0;
                  ContextRecord->Dr1 = TrapFrame->Dr1;
                  ContextRecord->Dr2 = TrapFrame->Dr2;
                  ContextRecord->Dr3 = TrapFrame->Dr3;
                  ContextRecord->Dr6 = TrapFrame->Dr6;
                  Dr7 = TrapFrame->Dr7;
                }
                else
                {
                  ContextRecord->Dr0 = NULL;
                  ContextRecord->Dr1 = NULL;
                  ContextRecord->Dr2 = NULL;
                  ContextRecord->Dr3 = NULL;
                  ContextRecord->Dr6 = NULL;
                }

            */

#ifdef _WIN64

            ctx.Dr7 = NULL;
            if (NT_SUCCESS(reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context_thread)(NtCurrentThread, &ctx)))
            {
                if (NT_SUCCESS(reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context_thread)(NtCurrentThread, &ctx)))
                {
                    if (ctx.Dr0 != NULL || ctx.Dr0 != ctx.Dr1 || ctx.Dr2 != ctx.Dr3 || ctx.Dr3 != NULL)
                    {
                        is_detect = TRUE;
                    }
                }
            }
            ctx.Dr0 = 0xFFFFF80000000000 + __rdtsc() % 0x1000000 + __COUNTER__ + crt_wrapper::get_random_number() % 0xA000000000;
            ctx.Dr1 = ctx.Dr0;
            ctx.Dr2 = ctx.Dr0 + __COUNTER__ * __LINE__ + crt_wrapper::get_random_number() % 0xA000000000;
            ctx.Dr3 = ctx.Dr2;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            ctx.Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);

            /*
             Dr0 = ContextRecord->Dr0;//SANITIZE_DRADDR macro
             if ( PreviousMode )
             {
                 dr0_real_set = NULL;//yea,will be set 0 if KM address
                 if ( Dr0 <= 0x7FFFFFFEFFFFi64 )//MmHighestUserAddress
                     dr0_real_set = ContextRecord->Dr0;
                 Dr0 = dr0_real_set;
             }
            */
            if (NT_SUCCESS(reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context_thread)(NtCurrentThread, &ctx)))
            {
                if (NT_SUCCESS(reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context_thread)(NtCurrentThread, &ctx)))
                {
                    if (ctx.Dr0 != NULL || ctx.Dr0 != ctx.Dr1 || ctx.Dr2 != ctx.Dr3 || ctx.Dr3 != NULL)
                    {
                        is_detect = TRUE;
                    }
                }
            }
#endif // _WIN64
            reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context_thread)(NtCurrentThread, &save_ctx);
            return is_detect;
        }
    };

    /*
    
    x32 0x7FFEFFFF - Max in x32 system 
    */

    class bad_hide_thread
    {
    private:
        PVOID nt_set_informathion_thread = NULL;
        PVOID nt_query_informathion_thread = NULL;
        PVOID nt_query_system_information = NULL;
        PVOID nt_close = NULL;

        INLINE auto init_struct() -> bool
        {
            if (nt_set_informathion_thread && nt_query_informathion_thread && nt_close)
                return TRUE;
            nt_query_system_information = LI_FN(NtQuerySystemInformation).nt_cached();
            nt_set_informathion_thread = LI_FN(NtSetInformationThread).nt_cached();
            nt_query_informathion_thread = LI_FN(NtQueryInformationThread).nt_cached();
            nt_close = LI_FN(NtClose).nt_cached();
            return nt_set_informathion_thread && nt_query_informathion_thread && nt_close;
        }

    public:
        NO_INLINE auto is_bad_hide_thread() -> bool
        {
            bool is_thread_hide = NULL;
            bool is_bad_hide = FALSE;
            INT mem_lenght_check = 0x101;
            ULONG return_lenght = NULL;
            HANDLE hide_thread = NULL;
            HANDLE bug_handle = NULL;
            THREAD_HIDE_INFO thread_hide_list[0xA] = { NULL };
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

            if (!init_struct())
                return FALSE;

            driver_off::disable_titan_hide();

            //Hide thread by bug (only SharpOD/ScyllaHide  via UM)
            bug_handle = OpenThread(THREAD_SET_INFORMATION, NULL, (DWORD)NtCurrentTeb()->ClientId.UniqueThread);
            if (bug_handle)
            {
                BREAK_INFO();
                nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(bug_handle, ThreadHideFromDebugger, NULL, NULL);
                RESTORE_INFO();
                reinterpret_cast<decltype(&NtClose)>(nt_close)(bug_handle);
            }
            nt_status = reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(hide_thread, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
            if (is_bad_hide == FALSE)//For macro
            {
                BREAK_INFO();
                nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(NULL, ThreadHideFromDebugger, NULL, NULL);
                RESTORE_INFO();
                if (nt_status != STATUS_INVALID_HANDLE)
                    is_bad_hide = TRUE;
            }

            auto thread_handle = CreateThread(NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL);
            if (thread_handle) //Check on lazy NtQueryInformationThread
            {
                nt_status = reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(thread_handle, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
                if ((NT_SUCCESS(nt_status) && (is_thread_hide || return_lenght != 1)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                    is_bad_hide = TRUE;

                nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(thread_handle, ThreadHideFromDebugger, NULL, NULL);
                if ((NT_SUCCESS(nt_status)))
                {
                    nt_status = reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(thread_handle, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
                    reinterpret_cast<decltype(&NtClose)>(nt_close)(bug_handle);
                    if ((NT_SUCCESS(nt_status) && (!is_thread_hide || return_lenght != 1)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                        is_bad_hide = TRUE;
                }
                reinterpret_cast<decltype(&NtClose)>(nt_close)(thread_handle);
            }

            //Bug with Access (only SharpOD/ScyllaHide  via UM)
            bug_handle = OpenThread(THREAD_QUERY_INFORMATION, NULL, (DWORD)NtCurrentTeb()->ClientId.UniqueThread);
            if (bug_handle)
            {
                nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(bug_handle, ThreadHideFromDebugger, NULL, NULL);
                reinterpret_cast<decltype(&NtClose)>(nt_close)(bug_handle);
                if (nt_status != STATUS_ACCESS_DENIED) //STATUS_ACCESS_DENIED should be by ObReferenceObjectByHandle
                    is_bad_hide = TRUE;
            }

            nt_status = LI_FN(NtCreateThreadEx).nt_cached()(&hide_thread, THREAD_ALL_ACCESS_VISTA, NULL, NtCurrentProcess, (LPTHREAD_START_ROUTINE)NULL, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, NULL, NULL, NULL, NULL);
            if (NT_SUCCESS(nt_status) && hide_thread) //Check on lazy NtCreateThreadEx  & NtQueryInformationThread
            {
                nt_status = reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(hide_thread, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
                reinterpret_cast<decltype(&NtClose)>(nt_close)(hide_thread);
                //Thread should be don't hided
                if ((NT_SUCCESS(nt_status) && (return_lenght != TRUE || is_thread_hide)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                    is_bad_hide = TRUE;
            }

            nt_status = LI_FN(NtCreateThreadEx).nt_cached()(&hide_thread, THREAD_ALL_ACCESS_VISTA, NULL, NtCurrentProcess, (LPTHREAD_START_ROUTINE)NULL, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_CREATE_SUSPENDED, NULL, NULL, NULL, NULL);
            if (NT_SUCCESS(nt_status) && hide_thread) //Check on lazy NtCreateThreadEx  & NtQueryInformationThread
            {
                nt_status = reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(hide_thread, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
                reinterpret_cast<decltype(&NtClose)>(nt_close)(hide_thread);
                //Thread should be hided
                if ((NT_SUCCESS(nt_status) && (return_lenght != TRUE || !is_thread_hide)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                    is_bad_hide = TRUE;
            }

            nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(NtCurrentThread, ThreadHideFromDebugger, reinterpret_cast<PVOID>(1), 1);
            if (nt_status != STATUS_ACCESS_VIOLATION && nt_status != STATUS_DATATYPE_MISALIGNMENT)
                is_bad_hide = TRUE;


            nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(reinterpret_cast<HANDLE>(0xFFFF), ThreadHideFromDebugger, NULL, NULL);
            if (nt_status != STATUS_INVALID_HANDLE)
                is_bad_hide = TRUE;

            nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(NtCurrentProcess, ThreadHideFromDebugger, NULL, NULL);
            if (nt_status != STATUS_OBJECT_TYPE_MISMATCH)
                is_bad_hide = TRUE;

            nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(NtCurrentThread, ThreadHideFromDebugger, NULL, sizeof(bool));
            if (nt_status != STATUS_INFO_LENGTH_MISMATCH)
                is_bad_hide = TRUE;

            nt_status = reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(NtCurrentThread, ThreadHideFromDebugger, &return_lenght, sizeof(is_thread_hide), &return_lenght);
            if ((NT_SUCCESS(nt_status) && (return_lenght != sizeof(bool))) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                is_bad_hide = TRUE;

            //Now hide own thread(we terminate created thread)
            nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(NtCurrentThread, ThreadHideFromDebugger, NULL, NULL);
            if (NT_SUCCESS(nt_status))
            {
                nt_status = reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(NtCurrentThread, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);

                //ScyllaHide and SharpOD don'h hook NtQueryInformationThread(ThreadHideFromDebugger)
                if ((NT_SUCCESS(nt_status) && (return_lenght != TRUE || !is_thread_hide)) || nt_status == STATUS_INFO_LENGTH_MISMATCH || nt_status == STATUS_DATATYPE_MISALIGNMENT)
                    is_bad_hide = TRUE;

                // try check on write BOOL(not BYTE by system) value
                nt_status = reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(NtCurrentThread, ThreadHideFromDebugger, &mem_lenght_check, sizeof(is_thread_hide), &return_lenght);
                if ((NT_SUCCESS(nt_status) && (return_lenght != TRUE || mem_lenght_check != 0x101)) || nt_status == STATUS_INFO_LENGTH_MISMATCH)
                    is_bad_hide = TRUE;
            }
            if (reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(NtCurrentThread, ThreadHideFromDebugger, &is_thread_hide, NULL, reinterpret_cast<PULONG>(1)) == STATUS_INFO_LENGTH_MISMATCH)
                is_bad_hide = TRUE;

            //Try use bug in arry
            for (INT i = NULL; i < _countof(thread_hide_list); i++)
            {
                thread_hide_list[i].thread_handle = CreateThread(NULL, NULL, NULL, NULL, CREATE_SUSPENDED, NULL);
                if (__rdtsc() % 10 > 5 && thread_hide_list[i].thread_handle)//Random value by tick(PG thanks)
                {
                    nt_status = reinterpret_cast<decltype(&NtSetInformationThread)>(nt_set_informathion_thread)(thread_hide_list[i].thread_handle, ThreadHideFromDebugger, NULL, NULL);
                    if ((NT_SUCCESS(nt_status)))
                    {
                        thread_hide_list[i].is_thread_hide = TRUE;
                    }
                }
            }
            for (INT i = NULL; i < _countof(thread_hide_list); i++)
            {
                if (thread_hide_list[i].thread_handle)
                {
                    nt_status = reinterpret_cast<decltype(&NtQueryInformationThread)>(nt_query_informathion_thread)(thread_hide_list[i].thread_handle, ThreadHideFromDebugger, &is_thread_hide, sizeof(is_thread_hide), &return_lenght);
                    if (NT_SUCCESS(nt_status) && (!is_thread_hide && thread_hide_list[i].is_thread_hide))
                        is_bad_hide = TRUE;
                    else if (NT_SUCCESS(nt_status) && (is_thread_hide && !thread_hide_list[i].is_thread_hide))
                        is_bad_hide = TRUE;
                    reinterpret_cast<decltype(&NtClose)>(nt_close)(thread_hide_list[i].thread_handle);
                }
            }
            
            if (nt_query_system_information)
            {
                util_process::hide_thread_shell(nt_query_system_information,nt_close);
            }
            return is_bad_hide;
        }
    };
    
     
    class bad_close_handle
    {

    private:
        INT build_number = NULL;
        PVOID nt_close = NULL;
        PVOID nt_set_informathion_object = NULL; 
        PVOID nt_set_informathion_process = NULL;
        PVOID nt_query_informathion_process = NULL;

        INLINE auto init_struct() -> bool
        {
            if (nt_set_informathion_process && nt_close && nt_set_informathion_object && nt_query_informathion_process)
                return TRUE;

            nt_set_informathion_process = LI_FN(NtSetInformationProcess).nt_cached();
            nt_close = LI_FN(NtClose).nt_cached();
            nt_set_informathion_object = LI_FN(NtSetInformationObject).nt_cached();
            nt_query_informathion_process = LI_FN(NtQueryInformationProcess).nt_cached();
            build_number = crt_wrapper::get_windows_number();
            return  nt_set_informathion_process && nt_close && nt_set_informathion_object && nt_query_informathion_process;
        }

    public:
        
    NO_INLINE auto is_bad_close_handle() -> bool
    {
        bool is_bad_close_detect = FALSE; 
        bool is_protect_set = FALSE;
        char buffer[0x20]; //need 0x10
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
        HANDLE event_habdle = NULL;
        PROCESS_HANDLE_TRACING_ENABLE tracing_handle = { NULL };  
        OBJECT_HANDLE_FLAG_INFORMATION object_flag_info = { NULL };

        event_habdle = CreateEventW(NULL, FALSE, FALSE, NULL); 
        object_flag_info.ProtectFromClose = TRUE; 

        if (!init_struct())
            return FALSE;

        driver_off::disable_titan_hide();

        if (event_habdle && NT_SUCCESS(reinterpret_cast<decltype(&NtSetInformationObject)>(nt_set_informathion_object)(event_habdle, ObjectHandleFlagInformation, &object_flag_info, sizeof(object_flag_info))))
            is_protect_set = TRUE;
             
        __try
        {
            nt_status = reinterpret_cast<decltype(&NtClose)>(nt_close)(reinterpret_cast<HANDLE>(0xDeadC0DE + __rdtsc() % 10000000));
              
            if (nt_status != STATUS_INVALID_HANDLE)
                is_bad_close_detect = TRUE; 
            
            nt_status = reinterpret_cast<decltype(&NtClose)>(nt_close)(event_habdle);
            if (is_protect_set && nt_status != STATUS_HANDLE_NOT_CLOSABLE)
                is_bad_close_detect = TRUE; 
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            is_bad_close_detect = TRUE;
        }
       
        nt_status = reinterpret_cast<decltype(&NtSetInformationProcess)>(nt_set_informathion_process)(NtCurrentProcess, ProcessHandleTracing, &tracing_handle, sizeof(PROCESS_HANDLE_TRACING_ENABLE));
        
        
        if (!NT_SUCCESS(nt_status))
            goto chek_system_bug;
        __try
        {
            //Should throw an exception :)
            reinterpret_cast<decltype(&NtClose)>(nt_close)(reinterpret_cast<HANDLE>(0xDeadC0DE + __rdtsc() % 10000000));
            nt_status = reinterpret_cast<decltype(&NtClose)>(nt_close)(event_habdle);
            is_bad_close_detect = TRUE; //TitanHide,SharpOD and SchyllaHide,lul
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            if (GetExceptionCode() != STATUS_INVALID_HANDLE && (is_protect_set && GetExceptionCode() != STATUS_HANDLE_NOT_CLOSABLE))
                is_bad_close_detect = TRUE;
        }  
        
        /*
            HyperHide don't call orig function - https://github.com/Air14/HyperHide/blob/1976e07c584ed171fc5e92407c18c485e6a608d8/HyperHideDrv/HookedFunctions.cpp#L529
            and have bug - https://github.com/Air14/HyperHide/blob/1976e07c584ed171fc5e92407c18c485e6a608d8/HyperHideDrv/HookedFunctions.cpp#L197
            function return STATUS_INVALID_PARAMETER by don't call orig function(NtSetInformationProcess) and do if (NT_SUCCESS(Status) == TRUE) (Lmao)
        */
        nt_status = reinterpret_cast<decltype(&NtQueryInformationProcess)>(nt_query_informathion_process)(NtCurrentProcess, ProcessHandleTracing, &buffer, sizeof(buffer), NULL);
        if (nt_status == STATUS_INVALID_PARAMETER) //HyperHide Lul
            is_bad_close_detect = TRUE;
        
        __try
        {
			//if ( Handle_1.Value >= 0xFFFFFFFFFFFFFFFAui64 || Handle_1.Value == NULL )
			//	goto LABEL_14;
            nt_status = reinterpret_cast<decltype(&NtClose)>(nt_close)(NULL);
            if (nt_status != STATUS_INVALID_HANDLE)
                is_bad_close_detect = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        { 
            is_bad_close_detect = TRUE; //HyperHide Lul
        } 
        
        //Disable tracing
        nt_status = reinterpret_cast<decltype(&NtSetInformationProcess)>(nt_set_informathion_process)(NtCurrentProcess, ProcessHandleTracing, &tracing_handle, NULL);

        object_flag_info.ProtectFromClose = FALSE;
        reinterpret_cast<decltype(&NtSetInformationObject)>(nt_set_informathion_object)(event_habdle, ObjectHandleFlagInformation, &object_flag_info, sizeof(object_flag_info));
        reinterpret_cast<decltype(&NtClose)>(nt_close)(event_habdle);
        
         chek_system_bug: 
        //In windows 10+ if Close -3 -  -6,then return STATUS_SUCCESS
        if (build_number >= WINDOWS_NUMBER_10)
        {
            __try
            {
                if (reinterpret_cast<decltype(&NtClose)>(nt_close)(reinterpret_cast<HANDLE>(-3)) == STATUS_INVALID_HANDLE)
                    is_bad_close_detect = TRUE;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                is_bad_close_detect = TRUE;
            }
        } 
        else if(build_number)
        {
            //  Winndows ?xp - 8.1 return STATUS_INVALID_HANDLE
            __try
            {
                if (reinterpret_cast<decltype(&NtClose)>(nt_close)(reinterpret_cast<HANDLE>(NtCurrentProcess)) != STATUS_INVALID_HANDLE)
                    is_bad_close_detect = TRUE;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                is_bad_close_detect = TRUE;
            }
        } 
       
        return is_bad_close_detect;
    }
    
    };
    /*
        SharpOD bad hook
        https://github.com/HighSchoolSoftwareClub/Windows-Research-Kernel-WRK-/blob/26b524b2d0f18de703018e16ec5377889afcf4ab/WRK-v1.2/base/ntos/ob/obhandle.c#L788
    */
    class dublicate_handle_check
    {
    private:
        PVOID nt_close = NULL;
        PVOID nt_set_informathion_object = NULL;
        PVOID nt_set_informathion_process = NULL;
        PVOID nt_duplicate_object = NULL;

        INLINE auto init_struct() -> bool
        {
            if (nt_set_informathion_process && nt_close && nt_set_informathion_object && nt_duplicate_object)
                return TRUE;

            nt_set_informathion_process = LI_FN(NtSetInformationProcess).nt_cached();
            nt_close = LI_FN(NtClose).nt_cached();
            nt_set_informathion_object = LI_FN(NtSetInformationObject).nt_cached();
            nt_duplicate_object = LI_FN(NtDuplicateObject).nt_cached();
            return  nt_set_informathion_process && nt_close && nt_set_informathion_object && nt_duplicate_object;
        }
    public:
        NO_INLINE auto is_dublicate_handle_bad() -> bool
        {
            bool is_detect = FALSE;
            HANDLE dublicate_handle = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
            PROCESS_HANDLE_TRACING_ENABLE tracing_handle = { NULL };
            OBJECT_HANDLE_FLAG_INFORMATION object_flag_info = { NULL };

            if (!init_struct())
                return FALSE;

            driver_off::disable_titan_hide();

            //STATUS_ACCESS_VIOLATION should be(rip SharpOD)
            if (STATUS_INVALID_HANDLE == reinterpret_cast<decltype(&NtDuplicateObject)>(nt_duplicate_object)(NtCurrentProcess, NULL, NtCurrentProcess, reinterpret_cast<PHANDLE>(1), NULL, FALSE, DUPLICATE_CLOSE_SOURCE))
                is_detect = TRUE;

            __try
            {
                object_flag_info.ProtectFromClose = TRUE;
                reinterpret_cast<decltype(&NtDuplicateObject)>(nt_duplicate_object)(NtCurrentProcess, NtCurrentProcess, NtCurrentProcess, &dublicate_handle, NULL, FALSE, NULL);
                reinterpret_cast<decltype(&NtSetInformationObject)>(nt_set_informathion_object)(dublicate_handle, ObjectHandleFlagInformation, &object_flag_info, sizeof(object_flag_info));
                reinterpret_cast<decltype(&NtDuplicateObject)>(nt_duplicate_object)(NtCurrentProcess, dublicate_handle, NtCurrentProcess, &dublicate_handle, NULL, FALSE, DUPLICATE_CLOSE_SOURCE);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                is_detect = TRUE;
            }
            object_flag_info.ProtectFromClose = FALSE;
            reinterpret_cast<decltype(&NtSetInformationObject)>(nt_set_informathion_object)(dublicate_handle, ObjectHandleFlagInformation, &object_flag_info, sizeof(object_flag_info));
            reinterpret_cast<decltype(&NtClose)>(nt_close)(dublicate_handle);

            if (!NT_SUCCESS(reinterpret_cast<decltype(&NtSetInformationProcess)>(nt_set_informathion_process)(NtCurrentProcess, ProcessHandleTracing, &tracing_handle, sizeof(PROCESS_HANDLE_TRACING_ENABLE))))
                return is_detect;

            __try
            {
                object_flag_info.ProtectFromClose = TRUE;
                reinterpret_cast<decltype(&NtDuplicateObject)>(nt_duplicate_object)(NtCurrentProcess, NtCurrentProcess, NtCurrentProcess, &dublicate_handle, NULL, FALSE, NULL);
                reinterpret_cast<decltype(&NtSetInformationObject)>(nt_set_informathion_object)(dublicate_handle, ObjectHandleFlagInformation, &object_flag_info, sizeof(object_flag_info));
                reinterpret_cast<decltype(&NtDuplicateObject)>(nt_duplicate_object)(NtCurrentProcess, dublicate_handle, NtCurrentProcess, &dublicate_handle, NULL, FALSE, DUPLICATE_CLOSE_SOURCE);
                is_detect = TRUE;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                if (GetExceptionCode() != STATUS_HANDLE_NOT_CLOSABLE)
                    is_detect = TRUE;
            }

            //Disable tracing
            reinterpret_cast<decltype(&NtSetInformationProcess)>(nt_set_informathion_process)(NtCurrentProcess, ProcessHandleTracing, &tracing_handle, NULL);
            
            object_flag_info.ProtectFromClose = FALSE;
            reinterpret_cast<decltype(&NtSetInformationObject)>(nt_set_informathion_object)(dublicate_handle, ObjectHandleFlagInformation, &object_flag_info, sizeof(object_flag_info));
            reinterpret_cast<decltype(&NtClose)>(nt_close)(dublicate_handle);
            return is_detect;
        }
    };
    /*
    HyperHide don't check address and we overwrite buffer by return lenght
    https://github.com/Air14/HyperHide/blob/1976e07c584ed171fc5e92407c18c485e6a608d8/HyperHideDrv/HookedFunctions.cpp#L589
    so,it's just call BSOD 
    */ 
    
    NO_INLINE auto is_bad_number_object_system() -> bool
    { 
        bool is_detect = FALSE;
        HANDLE debug_object = NULL;
        uint8_t* object_location = NULL;
        uint64_t number_debug_object_system = NULL;
        uint64_t number_debug_handle_system = NULL;
        uint64_t number_debug_object_process = NULL;
        uint64_t number_debug_handle_process = NULL;
        uint64_t tmp = NULL;
        ULONG lenght = NULL;
        PVOID buffer = NULL;
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
        OBJECT_ATTRIBUTES object_attrib;
        POBJECT_TYPE_INFORMATION object_process = NULL;
        POBJECT_TYPE_INFORMATION object_type_info = NULL;
        POBJECT_ALL_INFORMATION  object_all_info = NULL;


        driver_off::disable_titan_hide();

        InitializeObjectAttributes(&object_attrib, NULL, NULL, NULL, NULL);
        nt_status = LI_FN(NtCreateDebugObject).nt_cached()(&debug_object, DEBUG_QUERY_INFORMATION, &object_attrib, NULL);
        if (NT_SUCCESS(nt_status))
        { 
            //TitanHide very bad hook https://github.com/mrexodia/TitanHide/blob/fb7085e5956bc04c4e3add3fbaf73b1bcd432728/TitanHide/hooks.cpp#L397

            //Get correct lenght
            nt_status = LI_FN(NtQueryObject).nt_cached()(debug_object, ObjectTypeInformation, &lenght, sizeof(ULONG), &lenght);

            buffer = crt_wrapper::malloc(lenght);
            if (buffer == NULL)
            {
                LI_FN(NtClose).nt_cached()(debug_object);
                return is_detect;
            }
            nt_status = LI_FN(NtQueryObject).nt_cached()(debug_object, ObjectTypeInformation, buffer, lenght, &lenght);
            object_process = reinterpret_cast<POBJECT_TYPE_INFORMATION>(buffer);
            //SharpOD don't hook ObjectTypeInformation 
            if (object_process->TotalNumberOfObjects != 1 && crt_wrapper::wstricmp(L"DebugObject", object_process->TypeName.Buffer) == NULL)
            {  
                is_detect = TRUE;
            }   
            number_debug_handle_process = object_process->TotalNumberOfHandles;
            number_debug_object_process = object_process->TotalNumberOfObjects; 
            crt_wrapper::free(buffer); 
              
            //Get correct lenght
            nt_status = LI_FN(NtQueryObject).nt_cached()(NULL, ObjectTypesInformation, &lenght, sizeof(ULONG), &lenght);
            buffer = crt_wrapper::malloc(lenght);
            if (buffer == NULL)
            { 
                return is_detect;
            }
            //https://github.com/HighSchoolSoftwareClub/Windows-Research-Kernel-WRK-/blob/26b524b2d0f18de703018e16ec5377889afcf4ab/WRK-v1.2/base/ntos/ob/obquery.c#L406
            nt_status = LI_FN(NtQueryObject).nt_cached()(NtCurrentProcess, ObjectTypesInformation, buffer, lenght, NULL);

            if (!NT_SUCCESS(nt_status))
            {
                LI_FN(NtClose).nt_cached()(debug_object);
                crt_wrapper::free(buffer);
                return is_detect;
            } 

            object_all_info = reinterpret_cast<POBJECT_ALL_INFORMATION>(buffer);
            object_location = reinterpret_cast<UCHAR*>(object_all_info->ObjectTypeInformation);
            for (ULONG i = NULL; i < object_all_info->NumberOfObjectsTypes; i++)
            {
                object_type_info = reinterpret_cast<POBJECT_TYPE_INFORMATION>(object_location);
                 
                // The debug object will always be present
                if (crt_wrapper::wstricmp(L"DebugObject", object_type_info->TypeName.Buffer) == NULL)
                {
                    if (object_type_info->TotalNumberOfObjects > NULL)
                        number_debug_object_system += object_type_info->TotalNumberOfObjects;
                    if (object_type_info->TotalNumberOfHandles > NULL)
                        number_debug_handle_system += object_type_info->TotalNumberOfHandles;
                }  
                object_location = (uint8_t*)object_type_info->TypeName.Buffer;
                object_location += object_type_info->TypeName.MaximumLength;
                tmp = ((uint64_t)object_location) & -(INT)sizeof(PVOID);

                if ((uint64_t)tmp != (uint64_t)object_location)
                    tmp += sizeof(PVOID);
                object_location = ((uint8_t*)tmp);
            }
            crt_wrapper::free(buffer);

            nt_status = LI_FN(NtQueryObject).nt_cached()(NULL, ObjectTypesInformation, &lenght, sizeof(ULONG), &lenght);

            if (nt_status != STATUS_INFO_LENGTH_MISMATCH)
            {
                LI_FN(NtClose).nt_cached()(debug_object);
                if (number_debug_object_system < 1 ||
                    number_debug_object_system < number_debug_object_process ||
                    number_debug_handle_system < number_debug_handle_process)
                {
                    is_detect = TRUE;
                    return is_detect;
                }
            }

            buffer = crt_wrapper::malloc(lenght);

            /*
                BSOD HyperHide
                return lenght ~= size all wallking struct manual
                we change return lenght && HyperHide don't use SEH -> GG
            */
            LI_FN(NtQueryObject).nt_cached()(NtCurrentProcess, ObjectTypesInformation, buffer, lenght, reinterpret_cast<PULONG>(buffer));
            crt_wrapper::free(buffer);  
            LI_FN(NtClose).nt_cached()(debug_object); 

            if (number_debug_object_system < 1 ||
                number_debug_object_system < number_debug_object_process ||
                number_debug_handle_system < number_debug_handle_process)
            {
                is_detect = TRUE;
            }
        }
        return is_detect;
    }
    
    //Only mutate code
    class handle_attached
    {
    private:

        PVOID nt_close = NULL;
        PVOID nt_query_system_information = NULL;
        PVOID nt_query_object = NULL;
        PVOID nt_dublicate_object = NULL;   
        OBJECT_FULL_HANDLE_INFORMATION thread_query_inf = { NULL };
        OBJECT_FULL_HANDLE_INFORMATION event_handle_inf = { NULL };
        OBJECT_FULL_HANDLE_INFORMATION process_query_inf = { NULL };
        OBJECT_FULL_HANDLE_INFORMATION debug_object_inf = { NULL };
        OBJECT_FULL_HANDLE_INFORMATION file_object_inf = { NULL };


        INLINE auto init_struct() -> bool
        {
            if (nt_close && nt_query_system_information)
                return TRUE;
             
            nt_close = LI_FN(NtClose).nt_cached();
            nt_query_system_information = LI_FN(NtQuerySystemInformation).nt_cached();
            nt_query_object = LI_FN(NtQueryObject).nt_cached();
            nt_dublicate_object = LI_FN(NtDuplicateObject).nt_cached();
            return nt_close  && nt_query_system_information && nt_query_object && nt_dublicate_object;
        }
    public:

        NO_INLINE auto is_handle_attached(PINT debugger_pid)  -> bool
        {
            
            bool is_detect = FALSE; 
            ULONG access_thread = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;
            ULONG access_process = PROCESS_VM_WRITE | PROCESS_VM_READ;

            INT old_pid = NULL;
            ULONG ret_lenght = NULL;
            ULONG ret_lenght_arry = sizeof(ULONG);    //ULONG NumberOfHandles;
            ULONG max_size_file = NULL;
            ULONG min_size_file = NULL;
            PVOID buffer = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
            OBJECT_ATTRIBUTES object_attrib;

            if (!init_struct())
                return FALSE;

            if (debugger_pid)
                *debugger_pid = NULL;

            if (event_handle_inf.ObjectTypeIndex &&
                process_query_inf.ObjectTypeIndex &&
                thread_query_inf.ObjectTypeIndex &&
                debug_object_inf.ObjectTypeIndex &&
                file_object_inf.ObjectTypeIndex  
                )
            {
                event_handle_inf.handle = NULL;
                process_query_inf.handle = NULL;
                thread_query_inf.handle = NULL;
                debug_object_inf.handle = NULL;
                file_object_inf.handle = NULL;
                goto start_check;
            }
           
           event_handle_inf.handle = CreateEvent(NULL, TRUE, FALSE, NULL);
           thread_query_inf.handle = OpenThread(THREAD_QUERY_INFORMATION, NULL, (DWORD)NtCurrentTeb()->ClientId.UniqueThread);
           process_query_inf.handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)NtCurrentTeb()->ClientId.UniqueProcess);
           file_object_inf.handle = CreateFileW(crt_wrapper::get_name_file(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
           
           InitializeObjectAttributes(&object_attrib, NULL, NULL, NULL, NULL);
           nt_status = LI_FN(NtCreateDebugObject).nt_cached()(&debug_object_inf.handle, DEBUG_QUERY_INFORMATION, &object_attrib, NULL);
             
            if (NT_SUCCESS(nt_status) && file_object_inf.handle && process_query_inf.handle && thread_query_inf.handle && event_handle_inf.handle)
            {
            start_check:

                BREAK_INFO();

                nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemHandleInformation, &ret_lenght, ret_lenght, &ret_lenght);
                while (nt_status == STATUS_INFO_LENGTH_MISMATCH) 
                {
                    if (buffer != NULL)
                        crt_wrapper::free(buffer);

                    buffer = crt_wrapper::malloc(ret_lenght);
                    nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemHandleInformation, buffer, ret_lenght, &ret_lenght);
                }
                RESTORE_INFO();

                if (!NT_SUCCESS(nt_status))
                {
                    goto close_handle;
                }
                //Get  informathion about object  
                auto handle_info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer);
                
                //We have type
                if (
                    !event_handle_inf.ObjectTypeIndex ||
                    !process_query_inf.ObjectTypeIndex ||
                    !thread_query_inf.ObjectTypeIndex ||
                    !debug_object_inf.ObjectTypeIndex || 
                    !file_object_inf.ObjectTypeIndex
                    )
                {
                    for (ULONG i = NULL; i < handle_info->NumberOfHandles; i++)
                    {
                        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handle_info->Handles[i];
                        if (handleInfo.UniqueProcessId == reinterpret_cast<USHORT>(uniq_process_id))
                        {
                            if (handleInfo.HandleValue == reinterpret_cast<USHORT>(event_handle_inf.handle))
                            {
                                event_handle_inf.ObjectTypeIndex = handleInfo.ObjectTypeIndex;
                                event_handle_inf.Object = handleInfo.Object;
                            }

                            if (handleInfo.HandleValue == reinterpret_cast<USHORT>(process_query_inf.handle))
                            {
                                process_query_inf.ObjectTypeIndex = handleInfo.ObjectTypeIndex;
                                process_query_inf.Object = handleInfo.Object;
                            }

                            if (handleInfo.HandleValue == reinterpret_cast<USHORT>(thread_query_inf.handle))
                            {
                                thread_query_inf.ObjectTypeIndex = handleInfo.ObjectTypeIndex;
                                thread_query_inf.Object = handleInfo.Object;
                            }
                            if (handleInfo.HandleValue == reinterpret_cast<USHORT>(debug_object_inf.handle))
                            {
                                debug_object_inf.ObjectTypeIndex = handleInfo.ObjectTypeIndex;
                                debug_object_inf.Object = handleInfo.Object;
                            }
                            if (handleInfo.HandleValue == reinterpret_cast<USHORT>(file_object_inf.handle))
                            {
                                file_object_inf.ObjectTypeIndex = handleInfo.ObjectTypeIndex;
                                file_object_inf.Object = handleInfo.Object;
                            } 
                        }

                    }
                }

                handle_info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer);
                for (ULONG i = NULL; i < handle_info->NumberOfHandles; i++)
                {
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handle_info->Handles[i];
                    if (old_pid != handleInfo.UniqueProcessId && handleInfo.UniqueProcessId != reinterpret_cast<USHORT>(NtCurrentTeb()->ClientId.UniqueProcess))//Try optimizathion by don't check not corrupted PID
                    {
                        old_pid = handleInfo.UniqueProcessId; 
                        if
                        (   crt_wrapper::is_object_exist_proc(handle_info, process_query_inf.Object, handleInfo.UniqueProcessId, access_process) &&
                            crt_wrapper::is_object_exist_proc(handle_info, thread_query_inf.Object, handleInfo.UniqueProcessId, access_thread) &&
                            //Exist open file or DebugObject
                            (       crt_wrapper::is_object_type_exist_proc(handle_info, debug_object_inf.ObjectTypeIndex, handleInfo.UniqueProcessId, DEBUG_ALL_ACCESS) ||
                                    crt_wrapper::is_object_type_present_name(nt_dublicate_object,nt_close,nt_query_object,handle_info, file_object_inf.ObjectTypeIndex, handleInfo.UniqueProcessId, FILE_GENERIC_READ)
                            )
                         )
                        {
                            
                            //Try remove DebugObject
                            crt_wrapper::remove_object_dublicate(nt_dublicate_object,nt_close, handle_info, debug_object_inf.ObjectTypeIndex, handleInfo.UniqueProcessId, DEBUG_ALL_ACCESS);
                            if (debugger_pid)
                                *debugger_pid = handleInfo.UniqueProcessId;
                            is_detect = TRUE;
                            goto close_handle;
                            
                        }
                    }

                    if (!handleInfo.CreatorBackTraceIndex && !handleInfo.GrantedAccess && !handleInfo.Object)
                        ret_lenght_arry -= sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO);
                    else
                        ret_lenght_arry += sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO);
                } 

                handle_info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer);
                for (ULONG i = NULL; i < handle_info->NumberOfHandles; i++)
                {
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handle_info->Handles[i];
                    if (old_pid != handleInfo.UniqueProcessId && handleInfo.UniqueProcessId != reinterpret_cast<USHORT>(NtCurrentTeb()->ClientId.UniqueProcess))//Try optimizathion by don't check not corrupted PID
                    {

                        old_pid = handleInfo.UniqueProcessId;
                        if (crt_wrapper::is_object_type_exist_proc(handle_info, event_handle_inf.ObjectTypeIndex, handleInfo.UniqueProcessId) &&
                            !crt_wrapper::is_object_type_exist_proc(handle_info, thread_query_inf.ObjectTypeIndex, handleInfo.UniqueProcessId) &&
                            !crt_wrapper::is_object_type_exist_proc(handle_info, process_query_inf.ObjectTypeIndex, handleInfo.UniqueProcessId)
                            )
                        {
							
                            if (crt_wrapper::remove_dbg_reserved(nt_close,handleInfo.UniqueProcessId) ||
                                crt_wrapper::is_object_type_present_name(nt_dublicate_object,nt_close, nt_query_object,handle_info, file_object_inf.ObjectTypeIndex, handleInfo.UniqueProcessId, FILE_GENERIC_READ)
                                )
                            {
                                
                                if (debugger_pid)
                                    *debugger_pid = handleInfo.UniqueProcessId;
                                is_detect = TRUE;//Try hide process
                                break;
                                
                            }
                        }
                    }
                }

                /*
                https://github.com/Air14/HyperHide/blob/0042fe8420adbe54150b376e5aa55dd34dc87482/HyperHideDrv/HookedFunctions.cpp#L825
                We check manual correct return ReturnLength and size struct
                */
                if (ret_lenght > ret_lenght_arry && ret_lenght - ret_lenght_arry > sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) * 100)
                    is_detect = TRUE;
                
            }
             
        close_handle: 

            crt_wrapper::free(buffer);
            if (event_handle_inf.handle)
                reinterpret_cast<decltype(&NtClose)>(nt_close)(event_handle_inf.handle);
            if (process_query_inf.handle)
                reinterpret_cast<decltype(&NtClose)>(nt_close)(process_query_inf.handle);
            if (thread_query_inf.handle)
                reinterpret_cast<decltype(&NtClose)>(nt_close)(thread_query_inf.handle);
            if (debug_object_inf.handle)
                reinterpret_cast<decltype(&NtClose)>(nt_close)(debug_object_inf.handle);
            if (file_object_inf.handle)
                reinterpret_cast<decltype(&NtClose)>(nt_close)(file_object_inf.handle);
              
            return is_detect;
        }
    };

     namespace bug_debugger
     { 
         namespace x64_dbg
         {

             NO_INLINE auto call_seh(PVOID alloce_buffer) -> VOID
             {

                 __try
                 {
                     reinterpret_cast<PVOID(*)()>(alloce_buffer)();
                 }
                 __except (EXCEPTION_EXECUTE_HANDLER)
                 { 

                 }
             }

             NO_INLINE auto is_change(PBUG_PROTECT_CHECK bug_prot) -> VOID
             {
                 MEMORY_BASIC_INFORMATION mbi = { NULL };

                 while (bug_prot->is_active_thread == TRUE)
                 {
                     if (VirtualQuery(call_seh, &mbi, sizeof(mbi)))
                     {
                         if (mbi.Protect & PAGE_EXECUTE_READ ||
                             mbi.Protect & PAGE_EXECUTE_READWRITE
                             )
                         {
                             bug_prot->is_change_prot = TRUE;
                         } 
                     }
                 }
             }

             //Windows don't block read memory
             NO_INLINE auto check_change_prot() -> bool
             {
                 DWORD prot = NULL;
                 PVOID alloce_buffer = NULL;
                 HANDLE thread[0x3] = { NULL };
                 BUG_PROTECT_CHECK bug_prot = { NULL };
                 
                 alloce_buffer = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
                  
                 if (nullptr == alloce_buffer)
                     return FALSE; 

                 crt_wrapper::memset(alloce_buffer, 0xCC, PAGE_SIZE);

                 if (!VirtualProtect(alloce_buffer, PAGE_SIZE, PAGE_EXECUTE, &prot))
                 {
                     VirtualFree(alloce_buffer, NULL, MEM_RELEASE);
                     return FALSE;
                 }

                 bug_prot.is_active_thread = TRUE;

                 for (uint8_t i = NULL; i < _countof(thread); i++)
                 {
                     thread[i] = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)is_change, &bug_prot, NULL, NULL);
                 }
                 uint8_t buffer = NULL;
                 for (INT i = NULL; i < 25 && bug_prot.is_change_prot == FALSE; i++)
                 {  
                     if (ReadProcessMemory(NtCurrentProcess, alloce_buffer,&buffer,sizeof(buffer),NULL))
                     {
                         printf("OK!\n");
                     }
                     call_seh(alloce_buffer);
                 }

                 bug_prot.is_active_thread = FALSE;
 
                 if (nullptr != alloce_buffer)
                     VirtualFree(alloce_buffer, NULL, MEM_RELEASE);
                 return bug_prot.is_change_prot;
             }

         }

    }


}

#endif // !BOMBER_ANTI_DEBUG
