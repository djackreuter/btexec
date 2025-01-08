# btexec

In offices and coffee shops, there are likely going to be many Bluetooth devices nearby like TVs, headphones, speakers, etc. Why not use them to execute shellcode? Btexec is a shellcode loader that triggers a nearby Bluetooth device to silently authenticate to the users machine, which will execute the shellcode.

## How does it work?
* The program first checks if Bluetooth is enabled on the victim machine. This is also good for anti-emulation because sandboxes and VMs may not have the hardware for Bluetooth, where as user laptops and workstations will.
* It will then perform a search for nearby Bluetooth devices. Just something discoverable in the area. If no discoverable devices are found, it will exit. Again, good for anti-emulation.
* It will register an authentication callback containing a function pointer to the shellcode to execute.
* It triggers the discovered device to authenticate to the victim machine which will execute the callback and run the shellcode. No user interaction is required for the device authentication to occur, and no popups are displayed to the user.


## Usage instructions
1. [XOR encrypt](https://github.com/djackreuter/shellcode-encryption) your shellcode and save in `src/sc.bin`.
2. Update the XOR decryption key on line 12 with your key.
3. Compile.
4. ???
5. Profit.

![btexecdemo](https://github.com/user-attachments/assets/f5919539-8c03-412c-b4a3-056775e2f739)
