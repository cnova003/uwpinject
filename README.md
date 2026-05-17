# uwpinject

Launches UWP apps and injects DLLs into them as early as possible by posing as
a debugger and launching the app suspended.

If you need a sample DLL, here's one that hooks some UWP interfaces for
debugging and reverse engineering:

https://github.com/Francesco149/uwpspy

A GUI to let you pick apps to launch may be added eventually, but it is not a
priority at the moment.

Binaries will be provided when the project is more polished.

## Compiling

Install Visual C++ Build Tools 2017 and the Windows 10 SDK.

Open PowerShell and navigate to the `uwpinject` directory:

```ps1
.\vcvarsall17.ps1
.\build.ps1
```

## Usage

Open PowerShell and navigate to the `uwpinject` directory.

### Basic usage

The original command-line form is still supported:

```ps1
.\uwpinject.exe $((Get-AppxPackage uwp-template).PackageFullName)
```

Replace `uwp-template` with the package name of your target app.

This launches the app and injects all DLLs in the `dlls` folder. The `dlls`
folder must be located in the same directory as `uwpinject.exe`.

This legacy form derives the app launch ID as:

```text
PackageFamilyName!App
```

That works for UWP packages whose application ID is `App`.

### Advanced usage with an explicit AppID / AUMID

Some UWP packages do not use `!App` as their application ID. For those apps,
pass the app's full AppID / AUMID explicitly with `-a`:

```ps1
.\uwpinject.exe <PackageFullName> -a <AppID>
```

Example:

```ps1
.\uwpinject.exe `
  Microsoft.Chelan_1.3528.0.0_x64__8wekyb3d8bbwe `
  -a "Microsoft.Chelan_8wekyb3d8bbwe!HaloMCCShippingNoEAC"
```

`PackageFullName` is used for setting up UWP debugging with
`IPackageDebugSettings::EnableDebugging`.

`AppID` / `AUMID` is used for launching the app with
`IApplicationActivationManager::ActivateApplication`.

These are not always the same thing.

### Finding PackageFullName

You can get a package full name with PowerShell:

```ps1
Get-AppxPackage uwp-template
```

or directly pass it to `uwpinject`:

```ps1
.\uwpinject.exe $((Get-AppxPackage uwp-template).PackageFullName)
```

### Finding AppID / AUMID

If the basic one-argument command does not launch the right app, or if the
target package uses a custom application ID, look up the AppID / AUMID and pass
it with `-a`.

One way to search installed Start menu apps is:

```ps1
Get-StartApps | Where-Object { $_.Name -like "*Halo*" }
```

Then use the `AppID` value returned by PowerShell:

```ps1
$pkg = Get-AppxPackage Microsoft.Chelan
$app = Get-StartApps | Where-Object { $_.Name -like "*Halo*" }

.\uwpinject.exe $pkg.PackageFullName -a $app.AppID
```

If more than one result is returned, choose the AppID for the app you want to
launch.

## DLL folder

`uwpinject` injects every `.dll` file in the `dlls` folder next to
`uwpinject.exe`.

Example layout:

```text
uwpinject/
  uwpinject.exe
  dlls/
    myhook.dll
    anotherhook.dll
```

Before injection, `uwpinject` updates permissions so the UWP app can read the
DLLs.

## Troubleshooting

If it does not work, try running PowerShell as administrator. Injecting as a
regular user may work for some apps, but administrator permissions can help with
permission or process-access issues.

If the app does not launch with the basic command, it may not use the default
`PackageFamilyName!App` launch ID. In that case, find the app's AppID / AUMID
and use the explicit `-a` form:

```ps1
.\uwpinject.exe <PackageFullName> -a <AppID>
```

If no DLLs are injected, make sure:

- the `dlls` folder exists next to `uwpinject.exe`
- the files in `dlls` end with `.dll`
- the DLL architecture matches the target app architecture
- the target UWP app can be launched normally outside of `uwpinject`

### Remote LoadLibrary timeout

During injection, `uwpinject` starts a remote thread in the target process that
calls `LoadLibraryW` for each DLL. Some UWP launcher processes can load the DLL
successfully but still fail to signal that remote thread before the timeout.

When that happens, `uwpinject` prints a warning and continues instead of
treating the timeout as a hard injection failure. Check the injected DLL's own
log file or debug output to confirm whether it actually ran.

The old behavior could also print a second, misleading wait error after the
timeout. That second error was caused by timeout handling falling through into
the failure case.

## Command-line reference

```text
uwpinject.exe PackageFullName
uwpinject.exe PackageFullName -a AppID
uwpinject.exe -p PID
```

The `-p PID` form is used internally when Windows launches `uwpinject` as the
debugger for the suspended UWP process. You normally do not need to run that
command manually.

## Resources on UWP and WinRT internals

- https://reverseengineering.stackexchange.com/questions/17127/how-to-reverse-engineer-a-windows-10-uwp-app
- https://docs.microsoft.com/en-us/windows/desktop/api/appmodel/
- https://docs.microsoft.com/en-us/windows/uwp/xbox-apps/automate-launching-uwp-apps
- https://github.com/GPUOpen-Tools/OCAT/blob/2226171673f3c89369f4b70cf72f12daa94bf5c1/UWPOverlay/UWPOverlay.cpp
- https://docs.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/interop-winrt-abi
- https://docs.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/interop-winrt-cx
