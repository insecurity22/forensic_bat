@echo off

::
:: Code by bogyeong
:: Incident Response Collect Script for Live Response
:: Version 0.0.1, 2019.09.21 (last modified)
::

title Incident Response Collect Script for Live Response

:: set : variable
set _ver=0.0.1

:: Color config
cls
color 0E

:: Banner
@echo ***********************************************
@echo *******     Incident Response %_ver%    *******
@echo ***********************************************

:: Date
:: Computer name
:: Window C Drive text
:: Tool path
:: 32 bit / 64bit

goto :main

:main
set _date=%date%
set _HOSTNAME=%COMPUTERNAME%
set _SYSDRIVE=%SYSTEMDRIVE%\

:: Path
set _ToolPath=.\tool-list
set _ToolPath_sys=.\tool-list\SysinternalsSuite
set _ToolPath_memory=.\tool-list\memory
set _ToolPath_packet=.\tool-list\packet
if "%PROCESSOR_ARCHITECTURE%" == "x86" set arch=32
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" set arch=64

:: Artifact outputPath
set /p folderName=[+] Artifact output folder name:

:: Memory Dump
set /p isMemoryDump=[+] Memory Dump Execute? (y/n):
if "%isMemoryDump%" == "y" (
	set isMemoryDump=yes
) else (
	set isMemoryDump=no
)

:: Network Packet Dump Yes or No
set /p isPacketDump=[+] Packet Dump Execute? (y/n):
if "%isPacketDump%" == "y" (
	set isPacketDump=yes
) else (
	set isPacketDump=no
)

:: Examiner Name
set /p examiner=[+] Examiner:
set _path=%folderName%\%_HOSTNAME%_%date%_%examiner%
mkdir %_path%

:: Volatile
goto :volatile

:volatile
::
:: file
::
:: folderName\Hostname_date_examiner\network\
:: folderName\Hostname_date_examiner\process\
:: folderName\Hostname_date_examiner\memory\
:: folderName\Hostname_date_examiner\Packet_Dump\


:: ------------ Network
if not exist %_path%\network (
	mkdir %_path%\network
	set network_PATH=%_path%\network
)

:: Collect network information
echo 1_ Checking for Promiscuous Mode Detector, promqry.exe
%_ToolPath_sys%\promqry.exe > %network_PATH%\Promiscuous_detect_promqry.txt

:: Collect arp information
echo 2_ Checking for ARP Cache
%_ToolPath%\arpwin10\ARP.EXE -a > %network_PATH%\arp_a.txt
::
:: arp -a > %network_PATH%\arp_a.txt
:: arp -a와 같은 시스템 명령들은 해커에 의해 변조되었을 수도 있기 때문에 실무에서는 사용하면 안된다.
::
:: ★ C:\Windows\System32\ARP.EXE
:: 여기서 가져오기
::
:: http://forensic-proof.com/archives/2958

echo 3_ Checking for Net user
%_ToolPath_sys%\net.exe user > %network_PATH%\net_user.txt


:: ------------ Process
if not exist %_path%\process (
	mkdir %_path%\process
	set process_PATH=%_path%\process
)

echo 4_ Checking for process list
%_ToolPath_sys%\pslist.exe /accepteula > %process_PATH%\pslist.txt

:: autorunsc
if not exist %_path%\autorunsc (
	mkdir %_path%\autorunsc
	set autorunsc_PATH=%_path%\autorunsc
)

echo 5_ Checking for autorunsc
%_ToolPath_sys%\autorunsc.exe > %autorunsc_PATH%\autorunsc.txt
%_ToolPath_sys%\autorunsc.exe -h > %autorunsc_PATH%\autorunsc-hash.txt


:: ------------ Memory
:: [+] Memory Dump Execute? (y/n): y
if not exist %_path%\memory (
   mkdir  %_path%\memory
   set memory_PATH=%_path%\memory
)

echo 6_ Dumping Memory
if "%isMemoryDump%" == "yes" ( 
   goto :acquire_memoryDump
) else (
   goto :exit
)

:acquire_memoryDump
%_ToolPath_memory%\FDPro.exe %memory_PATH%\memdump.dd


:: ------------ Pakcet Dump
if not exist %_path%\Packet_Dump (
   mkdir  %_path%\Packet_Dump
   set Packet_Dump_PATH=%_path%\Packet_Dump
)
 
echo 7_ Dumping Packet
if "%isPacketDump%" == "yes" (
   goto :acquire_packetDump
) else (
   goto :exit
)
 
:acquire_packetDump
%_ToolPath_packet%\tcpdump.exe -D

:SELECT_NIC
set /p_NIC=What's the NIC number you want to acquire (1,2,3...)? || goto :SELECT_NIC
 
echo %DATE% %TIME% - created "Packet_Dump" directory in %packetDump_PATH%\
echo %DATE% %TIME% - Packet Dump Start
 
%_ToolPath_packet%\tcpdump.exe _D > %Packet_Dump_PATH%\NIC_list.txt
%_ToolPath_packet%\tcpdump.exe -i %_NIC% -c 3000 -w %Packet_Dump_PATH\%COMPUTERNAME%_NIC_%_NIC.pcap


echo %isPacketDump%
echo %isMemoryDump%
echo %outputPath%
echo %_date%
echo %_HOSTNAME%
echo %_SYSDRIVE%
echo %_ToolPath%
echo %arch%

pause

