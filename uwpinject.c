#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#define COBJMACROS
#include <windows.h>
#include <winternl.h>
#include <objbase.h>
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>
#include <shobjidl.h>
#include <appmodel.h>
#include <tlhelp32.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#pragma comment (lib, "ole32.lib")
#pragma comment (lib, "advapi32.lib")

#include <stdio.h>

#define INJECT_REMOTE_THREAD_TIMEOUT_MS 30000
#define SECONDARY_PROCESS_WAIT_MS 30000
#define SECONDARY_PROCESS_POLL_MS 1000
#define MAX_TRACKED_INJECTED_PIDS 128

typedef struct process_info {
  DWORD pid;
  DWORD parent_pid;
} process_info;

int uwp_fileperm(wchar_t* file);

int win32_perror(int err, wchar_t* msg) {
  int res;
  wchar_t* buf = 0;
  int flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER;
  FormatMessageW(flags, 0, err, 0, (LPWSTR)&buf, 0, 0);
  res = fwprintf(stderr, L"%s: error [%08X] %s\n", msg, err, buf);
  if (buf) {
    LocalFree((HLOCAL)buf);
  }
  return res;
}

int win32_addr(char* module_name, char* name, void** dst) {
  HMODULE lib = GetModuleHandleA(module_name);
  void* addr;
  if (!lib) {
    win32_perror((int)GetLastError(), L"GetModuleHandleA failed");
    return 0;
  }
  addr = (void*)GetProcAddress(lib, name);
  if (dst) {
    *dst = addr;
  }
  if (!addr) {
    win32_perror((int)GetLastError(), L"GetProcAddress failed");
    return 0;
  }
  return 1;
}

HANDLE win32_process(int pid) {
  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!process) {
    win32_perror((int)GetLastError(), L"OpenProcess failed");
  }
  return process;
}

void* win32_ralloc(int pid, size_t n) {
  void* p;
  HANDLE process = win32_process(pid);
  if (!process) {
    return 0;
  }
  p = VirtualAllocEx(process, 0, n, MEM_RESERVE | MEM_COMMIT,
    PAGE_READWRITE);
  if (!p) {
    win32_perror((int)GetLastError(), L"VirtualAllocEx failed");
  }
  CloseHandle(process);
  return p;
}

int win32_rfree(int pid, void* p) {
  HANDLE process = win32_process(pid);
  if (!process) {
    return 0;
  }
  if (!VirtualFreeEx(process, p, 0, MEM_RELEASE)) {
    win32_perror((int)GetLastError(), L"VirtualFreeEx failed");
    return 0;
  }
  return 1;
}

int win32_rmemcpy(int pid, void* dst, void* src, size_t n) {
  BOOL succ;
  size_t n_written;
  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!process) {
    win32_perror((int)GetLastError(), L"OpenProcess failed");
    return 0;
  }
  succ = WriteProcessMemory(process, dst, src, n, &n_written);
  if (!succ) {
    win32_perror((int)GetLastError(), L"WriteProcessMemory failed");
  }
  if (n_written != n) {
    win32_perror((int)GetLastError(), L"WriteProcessMemory partial write");
  }
  CloseHandle(process);
  return succ == TRUE;
}

int win32_process_image_path(int pid, wchar_t* path, DWORD path_len) {
  DWORD len = path_len;
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!process) {
    return 0;
  }
  if (!QueryFullProcessImageNameW(process, 0, path, &len)) {
    CloseHandle(process);
    return 0;
  }
  CloseHandle(process);
  return 1;
}

int win32_path_starts_with(wchar_t* path, wchar_t* prefix) {
  size_t prefix_len;
  if (!path || !prefix || !prefix[0]) {
    return 0;
  }
  prefix_len = wcslen(prefix);
  if (wcslen(path) < prefix_len) {
    return 0;
  }

  /*
   * CompareStringOrdinal compares Unicode text without caring about the
   * process locale. Passing TRUE makes the comparison case-insensitive, which
   * is useful for Windows paths because drive letters and folder names may not
   * always use the same casing.
   */
  if (CompareStringOrdinal(path, (int)prefix_len, prefix, (int)prefix_len, TRUE) != CSTR_EQUAL) {
    return 0;
  }

  /*
   * Treat the prefix as a directory boundary. Without this check,
   * "C:\Apps\PackageA2" would accidentally match "C:\Apps\PackageA".
   */
  return path[prefix_len] == 0 || path[prefix_len] == '\\';
}

void* win32_rwstrdup(int pid, wchar_t* s) {
  size_t n = (wcslen(s) + 1) * sizeof(s[0]);
  void* remote_s = win32_ralloc(pid, n);
  if (!remote_s) {
    return 0;
  }
  if (!win32_rmemcpy(pid, remote_s, s, n)) {
    win32_rfree(pid, remote_s);
    return 0;
  }
  return remote_s;
}

int win32_wait_for_remote_thread(int pid, void* routine, void* param) {
  int res = 1;
  DWORD wait_res;
  HANDLE remote_thread = 0;
  HANDLE process = win32_process(pid);
  if (!process) {
    return 0;
  }
  remote_thread = CreateRemoteThread(process, 0, 0,
    (LPTHREAD_START_ROUTINE)routine, param, 0, 0);
  if (!remote_thread) {
    win32_perror((int)GetLastError(), L"CreateRemoteThread failed");
    res = 0;
    goto cleanup;
  }

  /*
   * This thread runs LoadLibraryW inside the UWP process. In the simple case,
   * LoadLibraryW returns quickly and the thread becomes signaled.
   *
   * Some UWP launcher processes can load the DLL successfully but still leave
   * this remote thread unsignaled long enough to hit our timeout. The injected
   * DLL can prove it ran by writing its own log, so treat timeout as a warning
   * and continue to resume the app instead of parking this debugger callback
   * forever.
   */
  wait_res = WaitForSingleObject(remote_thread, INJECT_REMOTE_THREAD_TIMEOUT_MS);
  switch (wait_res) {
    case WAIT_TIMEOUT:
      win32_perror(ERROR_TIMEOUT, L"WaitForSingleObject failed");
      fwprintf(stderr,
        L"warning: remote LoadLibraryW thread timed out; continuing because the DLL may have loaded successfully.\n");
      res = 1;
      break;
    case WAIT_FAILED:
      win32_perror(GetLastError(), L"WaitForSingleObject failed");
      res = 0;
      break;
    case WAIT_OBJECT_0:
      res = 1;
      break;
    default:
      fwprintf(stderr, L"WaitForSingleObject returned unexpected status [%08X]\n", wait_res);
      res = 0;
      break;
  }
cleanup:
  if (remote_thread) {
    CloseHandle(remote_thread);
  }
  CloseHandle(process);
  return res;
}

/*
 * using the local LoadLibraryA address might seem wrong,
 * but in practice kernel32 is mapped to the same address in all processes
 * so it works
 */

int win32_inject(int pid, wchar_t* path) {
  void* pfnLoadLibraryW;
  void *remote_path;
  int res;
  if (!win32_addr("kernel32.dll", "LoadLibraryW", &pfnLoadLibraryW)) {
    return 0;
  }
  remote_path = win32_rwstrdup(pid, path);
  if (!remote_path) {
    return 0;
  }
  res = win32_wait_for_remote_thread(pid, pfnLoadLibraryW, remote_path);
  win32_rfree(pid, remote_path);
  return res;
}

int cli_pid_already_injected(int* injected_pids, int injected_count, int pid) {
  int i;
  for (i = 0; i < injected_count; ++i) {
    if (injected_pids[i] == pid) {
      return 1;
    }
  }
  return 0;
}

void cli_track_injected_pid(int* injected_pids, int* injected_count, int pid) {
  if (*injected_count >= MAX_TRACKED_INJECTED_PIDS) {
    return;
  }
  if (cli_pid_already_injected(injected_pids, *injected_count, pid)) {
    return;
  }
  injected_pids[*injected_count] = pid;
  *injected_count += 1;
}

int cli_dll_dir(wchar_t* self, wchar_t* dll_dir, size_t dll_dir_len) {
  wchar_t* p;

  /*
   * The DLL folder lives next to uwpinject.exe. argv[0] is the path Windows
   * used to launch this program, so strip the executable name and append
   * "\dlls".
   */
  wcscpy_s(dll_dir, dll_dir_len, self);
  p = &dll_dir[wcslen(dll_dir) - 1];
  for (; p > dll_dir && *p != '\\'; --p);
  if (p <= dll_dir) {
    return 0;
  }
  *p = 0;
  wcscat_s(dll_dir, dll_dir_len, L"\\dlls");
  return 1;
}

int cli_inject_dlls_into_pid(int pid, wchar_t* dll_dir) {
  wchar_t pattern[MAX_PATH];
  wchar_t fullpath[MAX_PATH];
  HANDLE find;
  WIN32_FIND_DATAW fd;
  DWORD err;
  int success = 1;

  wcscpy_s(pattern, MAX_PATH, dll_dir);
  wcscat_s(pattern, MAX_PATH, L"\\*.dll");

  find = FindFirstFileW(pattern, &fd);
  if (find == INVALID_HANDLE_VALUE) {
    win32_perror((int)GetLastError(), L"FindFirstFileW failed");
    return 0;
  }

  do {
    wprintf(L"%s\n", fd.cFileName);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      continue;
    }

    wcscpy_s(fullpath, MAX_PATH, dll_dir);
    wcscat_s(fullpath, MAX_PATH, L"\\");
    wcscat_s(fullpath, MAX_PATH, fd.cFileName);

    wprintf(L"injecting %s into process %d\n", fullpath, pid);
    uwp_fileperm(fullpath);
    if (!win32_inject(pid, fullpath)) {
      success = 0;
      break;
    }
  } while (FindNextFileW(find, &fd));

  err = GetLastError();
  if (success && err != ERROR_NO_MORE_FILES) {
    win32_perror((int)err, L"FindNextFileW failed");
    success = 0;
  }

  FindClose(find);
  return success;
}

int cli_collect_processes(process_info* processes, int capacity) {
  int count = 0;
  HANDLE snapshot;
  PROCESSENTRY32W entry;

  snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    win32_perror((int)GetLastError(), L"CreateToolhelp32Snapshot failed");
    return 0;
  }

  ZeroMemory(&entry, sizeof(entry));
  entry.dwSize = sizeof(entry);
  if (!Process32FirstW(snapshot, &entry)) {
    win32_perror((int)GetLastError(), L"Process32FirstW failed");
    CloseHandle(snapshot);
    return 0;
  }

  do {
    if (count >= capacity) {
      break;
    }
    processes[count].pid = entry.th32ProcessID;
    processes[count].parent_pid = entry.th32ParentProcessID;
    ++count;
  } while (Process32NextW(snapshot, &entry));

  CloseHandle(snapshot);
  return count;
}

DWORD cli_find_parent_pid(process_info* processes, int process_count, DWORD pid) {
  int i;
  for (i = 0; i < process_count; ++i) {
    if (processes[i].pid == pid) {
      return processes[i].parent_pid;
    }
  }
  return 0;
}

int cli_is_descendant_pid(process_info* processes, int process_count, DWORD pid, DWORD root_pid) {
  int depth;
  DWORD current = pid;

  /*
   * Walk the parent-process chain to see whether this process came from the
   * original UWP launcher process. The depth limit prevents a bad or recycled
   * parent chain from turning into an endless loop.
   */
  for (depth = 0; depth < 32; ++depth) {
    current = cli_find_parent_pid(processes, process_count, current);
    if (!current) {
      return 0;
    }
    if (current == root_pid) {
      return 1;
    }
  }
  return 0;
}

void cli_package_dir_from_image(wchar_t* image_path, wchar_t* package_dir, size_t package_dir_len) {
  wchar_t* p;
  wcscpy_s(package_dir, package_dir_len, image_path);
  p = &package_dir[wcslen(package_dir) - 1];
  for (; p > package_dir && *p != '\\'; --p);
  *p = 0;
}

void cli_inject_secondary_processes(
  int root_pid,
  wchar_t* dll_dir,
  int* injected_pids,
  int* injected_count) {
  ULONGLONG deadline = GetTickCount64() + SECONDARY_PROCESS_WAIT_MS;
  wchar_t root_path[MAX_PATH];
  wchar_t package_dir[MAX_PATH];
  int have_package_dir = 0;

  if (win32_process_image_path(root_pid, root_path, MAX_PATH)) {
    cli_package_dir_from_image(root_path, package_dir, MAX_PATH);
    have_package_dir = 1;
    wprintf(L"watching package directory for secondary processes: %s\n", package_dir);
  } else {
    wprintf(L"watching child processes of %d for secondary injection targets\n", root_pid);
  }

  while (GetTickCount64() < deadline) {
    process_info processes[4096];
    int process_count = cli_collect_processes(processes, 4096);
    int i;

    for (i = 0; i < process_count; ++i) {
      int candidate_pid = (int)processes[i].pid;
      wchar_t image_path[MAX_PATH];
      int same_package = 0;
      int descendant = 0;

      if (candidate_pid <= 0 || candidate_pid == root_pid) {
        continue;
      }
      if (cli_pid_already_injected(injected_pids, *injected_count, candidate_pid)) {
        continue;
      }

      descendant = cli_is_descendant_pid(processes, process_count, processes[i].pid, (DWORD)root_pid);
      if (have_package_dir && win32_process_image_path(candidate_pid, image_path, MAX_PATH)) {
        same_package = win32_path_starts_with(image_path, package_dir);
      }

      /*
       * Generic secondary-process detection:
       * - descendants catch apps that spawn their real worker/game process
       * - same package directory catches UWP packages where Windows does not
       *   preserve a simple parent-child relationship
       */
      if (!descendant && !same_package) {
        continue;
      }

      if (same_package) {
        wprintf(L"found secondary package process %d: %s\n", candidate_pid, image_path);
      } else {
        wprintf(L"found secondary child process %d\n", candidate_pid);
      }

      if (cli_inject_dlls_into_pid(candidate_pid, dll_dir)) {
        cli_track_injected_pid(injected_pids, injected_count, candidate_pid);
      }
    }

    Sleep(SECONDARY_PROCESS_POLL_MS);
  }
}

int win32_resume(int pid) {
  HANDLE process;
  typedef LONG NTAPI fnNtResumeProcess(HANDLE);
  fnNtResumeProcess* resume = 0;
  LONG status;
  if (!win32_addr("ntdll.dll", "NtResumeProcess", (void**)&resume)) {
    return 0;
  }
  process = win32_process(pid);
  if (!process) {
    return 0;
  }
  status = resume(process);
  if (!NT_SUCCESS(status)) {
    win32_perror(status, L"NtResumeProcess failed");
  }
  CloseHandle(process);
  return NT_SUCCESS(status);
}

int win32_coinit() {
  /* it's fine to init multiple times if flags are the same */
  int flags = COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE;
  HRESULT hr = CoInitializeEx(0, flags);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"CoInitializeEx failed");
    return 0;
  }
  return 1;
}

int win32_couninit() {
  CoUninitialize();
  return 1;
}

/* dlls need certain permissions to be visible to uwp processes */
int uwp_fileperm(wchar_t* file) {
  PACL old_acl = 0;
  PACL new_acl = 0;
  PSECURITY_DESCRIPTOR sd = 0;
  EXPLICIT_ACCESS_W access;
  SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
  DWORD res = ERROR_SUCCESS;
  PSID sid;

  /* get current acl */
  res = GetNamedSecurityInfoW(file, SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION, 0, 0, &old_acl, 0, &sd);
  if (res != ERROR_SUCCESS) {
    win32_perror(res, L"GetNamedSecurityInfoW failed");
    goto cleanup;
  }

  /* sid for all application packages */
  ConvertStringSidToSidW(L"S-1-15-2-1", &sid);
  if (!sid) {
    win32_perror(GetLastError(), L"ConvertStringSidToSid failed");
    goto cleanup;
  }

  ZeroMemory(&access, sizeof(access));
  access.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
  access.grfAccessMode = SET_ACCESS;
  access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  access.Trustee.ptstrName = (LPWSTR)sid;

  /* merge new ace into old acl */
  res = SetEntriesInAclW(1, &access, old_acl, &new_acl);
  if (res != ERROR_SUCCESS) {
    win32_perror(res, L"SetEntriesInAcl failed");
    goto cleanup;
  }

  /* attach new acl */
  res = SetNamedSecurityInfoW(file, SE_FILE_OBJECT, si, 0, 0, new_acl, 0);
  if (res != ERROR_SUCCESS) {
    win32_perror(res, L"SetNamedSecurityInfo failed");
    goto cleanup;
  }

cleanup:
  if (sd) {
    LocalFree((HLOCAL)sd);
  }
  if (new_acl) {
    LocalFree((HLOCAL)new_acl);
  }
  return res == ERROR_SUCCESS;
}

/* class is FamilyName!ClassName */
int uwp_launch_class(wchar_t* class, int* pid) {
  DWORD dwpid = 0;
  IApplicationActivationManager* mgr;
  HRESULT hr;

  if (!win32_coinit()) {
    return 0;
  }

  hr = CoCreateInstance(&CLSID_ApplicationActivationManager, 0,
    CLSCTX_ALL, &IID_IApplicationActivationManager, (void**)&mgr);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"CoCreateInstance failed");
    goto cleanup;
  }

  /* this seems to fail on win10 /shrug */
  CoAllowSetForegroundWindow((IUnknown*)mgr, 0);

  hr = IApplicationActivationManager_ActivateApplication(mgr, class, 0,
    AO_NONE, &dwpid);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"ActivateApplication failed");
    goto cleanup;
  }

  if (pid) {
    *pid = (int)dwpid;
  }

cleanup:
  if (mgr) {
    IApplicationActivationManager_Release(mgr);
  }
  win32_couninit();
  return SUCCEEDED(hr);
}

int uwp_family(wchar_t* app, wchar_t* buf, size_t buflen) {
  UINT32 len = (UINT32)buflen;
  DWORD err = PackageFamilyNameFromFullName(app, &len, buf);
  if (err != ERROR_SUCCESS) {
    win32_perror((int)err, L"PackageFamilyNameFromFullName failed");
    return 0;
  }
  return 1;
}

int uwp_class(wchar_t* app, wchar_t* buf, size_t buflen) {
  if (!uwp_family(app, buf, buflen)) {
    return 0;
  }
  wcscat_s(buf, buflen - 1, L"!App");
  return 1;
}

int uwp_launch(wchar_t* app, int* pid) {
  WCHAR class[512];
  if (!uwp_class(app, class, sizeof(class))) {
    return 0;
  }
  return uwp_launch_class(class, pid);
}

int uwp_debug(wchar_t* debugger, wchar_t* packageFullName, wchar_t* appId) {
  int res = 1;
  HRESULT hr;
  IPackageDebugSettings* settings = 0;
  int pid = 0;

  if (!win32_coinit()) {
    return 0;
  }

  hr = CoCreateInstance(&CLSID_PackageDebugSettings, 0, CLSCTX_ALL,
    &IID_IPackageDebugSettings, (void**)&settings);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"CoCreateInstance failed");
    res = 0;
    goto cleanup;
  }

  /*
   * EnableDebugging needs the PackageFullName:
   *
   *   Microsoft.Chelan_1.3528.0.0_x64__8wekyb3d8bbwe
   */
  hr = IPackageDebugSettings_EnableDebugging(settings, packageFullName, debugger, 0);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"EnableDebugging failed");
    res = 0;
    goto cleanup;
  }

  /*
   * ActivateApplication needs the AppID / AUMID:
   *
   *   Microsoft.Chelan_8wekyb3d8bbwe!HaloMCCShippingNoEAC
   */
  if (!uwp_launch_class(appId, &pid)) {
    res = 0;
    goto cleanup;
  }

  wprintf(L"launched as %d\n", pid);
  hr = IPackageDebugSettings_DisableDebugging(settings, packageFullName);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"DisableDebugging failed");
    res = 0;
    goto cleanup;
  }

cleanup:
  if (settings) {
    IPackageDebugSettings_Release(settings);
  }

  win32_couninit();
  return res;
}

// ------------------------------------------------------------------------

void cli_printargs(int argc, wchar_t* argv[]) {
  int i;
  for (i = 0; i < argc; ++i) {
    wprintf(L"%s ", argv[i]);
  }
  wprintf(L"\n");
}

void cli_start(wchar_t* self, wchar_t* packageFullName, wchar_t* appId) {
  wprintf(L"package: %s\n", packageFullName);
  wprintf(L"app id:  %s\n", appId);
  wprintf(L"starting app in debug mode\n");

  uwp_debug(self, packageFullName, appId);
}

void cli_start_legacy(wchar_t* self, wchar_t* packageFullName) {
  WCHAR appId[512];

  if (!uwp_class(packageFullName, appId, sizeof(appId))) {
    return;
  }

  wprintf(L"package: %s\n", packageFullName);
  wprintf(L"app id:  %s\n", appId);
  wprintf(L"starting app in debug mode using legacy !App id\n");

  uwp_debug(self, packageFullName, appId);
}

/* TODO: make this function more readable */
/* windows will suspend the app's process and call us back with "-p pid" */
void cli_inject(int argc, wchar_t* argv[]) {
  wchar_t dll_dir[MAX_PATH];
  int injected_pids[MAX_TRACKED_INJECTED_PIDS];
  int injected_count = 0;
  int pid = 0;
  int i;
  int success = 1;

  ZeroMemory(injected_pids, sizeof(injected_pids));

  for (i = 1; i < argc - 1; ++i) {
    if (!wcscmp(argv[i], L"-p")) {
      pid = _wtoi(argv[i + 1]);
      break;
    }
  }

  if (!cli_dll_dir(argv[0], dll_dir, MAX_PATH)) {
    fwprintf(stderr, L"failed to resolve dlls directory from %s\n", argv[0]);
    success = 0;
    goto cleanup;
  }

  if (!cli_inject_dlls_into_pid(pid, dll_dir)) {
    success = 0;
    goto cleanup;
  }
  cli_track_injected_pid(injected_pids, &injected_count, pid);

cleanup:
  if (!win32_resume(pid) || !success) {
    for (;;) {
      Sleep(1000);
    }
  }

  /*
   * Some UWP packages first launch a small helper process, then spawn the real
   * app process after the package is resumed. After the early injection is done,
   * keep this debugger callback alive briefly and inject the same DLLs into
   * related secondary processes as they appear.
   */
  cli_inject_secondary_processes(pid, dll_dir, injected_pids, &injected_count);
}

int wmain(int argc, wchar_t* argv[]) {
  cli_printargs(argc, argv);

  /*
   * Callback mode.
   *
   * Windows relaunches this program as the debugger with:
   *
   *   uwpinject.exe -p PID
   */
  if (argc >= 3 && !wcscmp(argv[1], L"-p")) {
    cli_inject(argc, argv);
    return 0;
  }

  /*
   * Backward-compatible launch mode:
   *
   *   uwpinject.exe PackageFullName
   *
   * This preserves the old behavior by deriving the AppID as:
   *
   *   PackageFamilyName!App
   */
  if (argc == 2) {
    cli_start_legacy(argv[0], argv[1]);
    return 0;
  }

  /*
   * Explicit AppID / AUMID launch mode:
   *
   *   uwpinject.exe PackageFullName -a AppID
   */
  if (argc == 4 && !wcscmp(argv[2], L"-a")) {
    cli_start(argv[0], argv[1], argv[3]);
    return 0;
  }

  fwprintf(
    stderr,
    L"usage:\n"
    L"  %s PackageFullName\n"
    L"  %s PackageFullName -a AppID\n",
    argv[0],
    argv[0]
  );

  return 1;
}
