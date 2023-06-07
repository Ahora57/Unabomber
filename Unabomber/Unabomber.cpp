
 
#include "anti_debug_bomber.hpp"

int main()
{    
    bool is_checked = FALSE;
    
    INT pid_debugger = NULL;
    anti_debug_bomber::debug_object_present deb_obj_present; 
    anti_debug_bomber::debug_flag_present deb_flag;
    anti_debug_bomber::bad_hide_thread is_hide_thread;
    anti_debug_bomber::bad_close_handle close_handle;
    anti_debug_bomber::hwbp_present hwbp_check;
    anti_debug_bomber::dublicate_handle_check dub_handle_bad;
    anti_debug_bomber::handle_attached is_attached_handle; 
     

    
    while (true)
    {
        if (GetAsyncKeyState(VK_SPACE))
        {
            
           printf("is debug object bad ->\t%x\n", deb_obj_present.is_debug_object_present());
           if (!is_checked)
                printf("Is process parameters ->\t%x\n", anti_debug_bomber::check_lazy_process_parametr());
            is_checked = TRUE;
            
            printf("is debug flag bad ->\t%x\n", deb_flag.is_debug_flag_hooked());
            printf("is bad hide thread ->\t%x\n", is_hide_thread.is_bad_hide_thread());
            printf("is bad hwbp ->\t%x\n", hwbp_check.is_bad_hwbp());
            printf("is bad close handle ->\t%x\n", close_handle.is_bad_close_handle());
            printf("is dublicate bad ->\t%x\n", dub_handle_bad.is_dublicate_handle_bad());
            printf("is bad object ->\t%x\n", anti_debug_bomber::is_bad_number_object_system());
            printf("is attach handle debugger ->\t%x\n", is_attached_handle.is_handle_attached(&pid_debugger));
            if (pid_debugger)
            {
                printf("pid debugger ->\t%d\n", pid_debugger);
            }
            
            printf("is change protecthion(bug) ->\t%x\n", anti_debug_bomber::bug_debugger::x64_dbg::check_change_prot());
             
            Sleep(7500);
            system("cls");
        }
        
    } 
    
    Sleep(300);
    std::cin.get();
    return STATUS_SUCCESS;

}
