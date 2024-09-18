use retour::static_detour;
use std::ffi::{c_void, CString};
use std::mem::transmute;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{
    GetLastError, SetLastError, BOOL, ERROR_ALREADY_EXISTS, HANDLE, NO_ERROR,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
};

static_detour! {
    static CREATE_MUTEX_W_HOOK: extern "system" fn(*const SECURITY_ATTRIBUTES, BOOL,PCWSTR) -> HANDLE;
}

fn hooked_create_mutex_w(
    lp_mutex_attributes: *const SECURITY_ATTRIBUTES,
    b_initial_owner: BOOL,
    lp_name: PCWSTR,
) -> HANDLE {
    let result = CREATE_MUTEX_W_HOOK.call(lp_mutex_attributes, b_initial_owner, lp_name);
    if lp_name.is_null() {
        return result;
    }
    unsafe {
        let name = lp_name.to_string().unwrap();
        if name == "Global\\SekiroMutex" && GetLastError() == ERROR_ALREADY_EXISTS {
            SetLastError(NO_ERROR);
        }
    }
    result
}

fn get_module_symbol_address(module: &str, symbol: &str) -> Option<usize> {
    let module = CString::new(module).unwrap();
    let symbol = CString::new(symbol).unwrap();
    unsafe {
        match GetModuleHandleA(PCSTR(module.as_ptr() as _)) {
            Ok(handle) => match GetProcAddress(handle, PCSTR(symbol.as_ptr() as _)) {
                Some(func) => Some(func as usize),
                None => None,
            },
            _ => None,
        }
    }
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(_hinst: HANDLE, reason: u32, _reserved: *mut c_void) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            let address = get_module_symbol_address("kernel32.dll", "CreateMutexW").unwrap();
            CREATE_MUTEX_W_HOOK
                .initialize(transmute(address), hooked_create_mutex_w)
                .unwrap();

            CREATE_MUTEX_W_HOOK.enable().unwrap();
        }
        DLL_PROCESS_DETACH => {}
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    };
    return BOOL::from(true);
}
