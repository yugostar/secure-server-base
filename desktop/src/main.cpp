#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <rpc.h>
#include <shlobj.h>
#include <commdlg.h>

#include "SakuraShieldRpc.h"

#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kWindowClassName[] = L"SakuraShieldWindowClass";
constexpr wchar_t kWindowTitle[] = L"Sakura Shield";
constexpr wchar_t kTrayTooltip[] = L"Sakura Shield";
constexpr wchar_t kServiceName[] = L"SakuraShieldService";
constexpr wchar_t kServiceProcessName[] = L"SakuraShieldService.exe";
constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"SakuraShieldRpcEndpoint";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayCallbackMessage = WM_APP + 1;
constexpr UINT_PTR kCommandTrayOpen = 1001;
constexpr UINT_PTR kCommandTrayExit = 1002;
constexpr UINT_PTR kCommandFileExit = 1003;
constexpr UINT_PTR kTimerStateRefresh = 1004;
constexpr int kControlUsername = 2001;
constexpr int kControlPassword = 2002;
constexpr int kControlLogin = 2003;
constexpr int kControlActivation = 2004;
constexpr int kControlActivate = 2005;
constexpr int kControlLogout = 2006;
constexpr int kControlRefresh = 2007;
constexpr int kControlScanFile = 2008;
constexpr int kControlScanFolder = 2009;
constexpr int kControlClearScan = 2010;
constexpr int kControlScanDrives = 2011;
constexpr int kControlScheduleScan = 2012;
constexpr int kControlStartMonitor = 2013;
constexpr int kControlStopMonitor = 2014;

HINSTANCE g_instance = nullptr;
HWND g_mainWindow = nullptr;
HANDLE g_singleInstanceMutex = nullptr;
NOTIFYICONDATAW g_trayIconData{};
UINT g_taskbarCreatedMessage = 0;
bool g_isExiting = false;
bool g_trayIconAdded = false;
HFONT g_titleFont = nullptr;
HFONT g_statusFont = nullptr;
HFONT g_smallFont = nullptr;
HBRUSH g_backgroundBrush = nullptr;
HBRUSH g_panelBrush = nullptr;
HICON g_trayIcon = nullptr;
HWND g_usernameEdit = nullptr;
HWND g_passwordEdit = nullptr;
HWND g_loginButton = nullptr;
HWND g_activationEdit = nullptr;
HWND g_activateButton = nullptr;
HWND g_logoutButton = nullptr;
HWND g_refreshButton = nullptr;
HWND g_scanFileButton = nullptr;
HWND g_scanFolderButton = nullptr;
HWND g_clearScanButton = nullptr;
HWND g_scanDrivesButton = nullptr;
HWND g_scheduleScanButton = nullptr;
HWND g_startMonitorButton = nullptr;
HWND g_stopMonitorButton = nullptr;

struct ClientState {
    bool rpcOnline = false;
    bool authenticated = false;
    bool antivirusEnabled = false;
    bool hasLicense = false;
    bool licenseValid = false;
    std::wstring username;
    std::wstring licenseExpiresAt;
    std::wstring message;
    std::wstring avDatabaseReleaseDate;
    long avRecordCount = 0;
};

ClientState g_state;
std::wstring g_localMessage;
std::wstring g_scanReport;

enum class ViewMode {
    Login,
    Activation,
    Main
};

ViewMode g_viewMode = ViewMode::Login;

std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

bool ContainsFlag(const std::wstring& commandLine, const wchar_t* flag) {
    return ToLower(commandLine).find(flag) != std::wstring::npos;
}

bool ShouldStartHidden(LPWSTR commandLine) {
    const std::wstring args = commandLine == nullptr ? L"" : commandLine;
    return ContainsFlag(args, L"--hidden")
        || ContainsFlag(args, L"/hidden")
        || ContainsFlag(args, L"--background")
        || ContainsFlag(args, L"/background")
        || ContainsFlag(args, L"--tray")
        || ContainsFlag(args, L"/tray");
}

std::wstring GetFileNameFromPath(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

bool EqualsIgnoreCase(const std::wstring& left, const std::wstring& right) {
    return ToLower(left) == ToLower(right);
}

DWORD GetParentProcessId() {
    const DWORD currentProcessId = GetCurrentProcessId();
    DWORD parentProcessId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == currentProcessId) {
                parentProcessId = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return parentProcessId;
}

bool IsParentServiceProcess() {
    const DWORD parentProcessId = GetParentProcessId();
    if (parentProcessId == 0) {
        return false;
    }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    bool result = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == parentProcessId) {
                result = EqualsIgnoreCase(entry.szExeFile, kServiceProcessName);
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

DWORD QueryServiceState(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded) == FALSE) {
        return 0;
    }
    return status.dwCurrentState;
}

bool WaitForServiceRunning(SC_HANDLE service, DWORD timeoutMs) {
    const DWORD started = GetTickCount();
    while (GetTickCount() - started < timeoutMs) {
        const DWORD state = QueryServiceState(service);
        if (state == SERVICE_RUNNING) {
            return true;
        }
        if (state == SERVICE_STOPPED) {
            return false;
        }
        Sleep(300);
    }
    return QueryServiceState(service) == SERVICE_RUNNING;
}

bool ShouldExitAfterServiceBootstrap() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) {
        return true;
    }
    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        CloseServiceHandle(manager);
        return true;
    }
    const DWORD state = QueryServiceState(service);
    bool shouldExit = true;
    if (state == SERVICE_RUNNING) {
        shouldExit = false;
    } else if (state == SERVICE_START_PENDING) {
        shouldExit = !WaitForServiceRunning(service, 30000);
    } else if (state == SERVICE_STOPPED) {
        CloseServiceHandle(service);
        service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
        if (service != nullptr) {
            StartServiceW(service, 0, nullptr);
            WaitForServiceRunning(service, 30000);
        }
    }
    if (service != nullptr) {
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
    return shouldExit;
}

bool CreateSingleInstanceGuard() {
    wchar_t userName[256]{};
    DWORD userNameLength = 256;
    if (GetUserNameW(userName, &userNameLength) == FALSE) {
        wcscpy_s(userName, L"DefaultUser");
    }
    std::wstring mutexName = L"Local\\SakuraShieldTray_" + std::wstring(userName);
    g_singleInstanceMutex = CreateMutexW(nullptr, TRUE, mutexName.c_str());
    if (g_singleInstanceMutex == nullptr) {
        return false;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_singleInstanceMutex);
        g_singleInstanceMutex = nullptr;
        return false;
    }
    return true;
}

void ReleaseSingleInstanceGuard() {
    if (g_singleInstanceMutex != nullptr) {
        ReleaseMutex(g_singleInstanceMutex);
        CloseHandle(g_singleInstanceMutex);
        g_singleInstanceMutex = nullptr;
    }
}

bool CreateRpcBinding(handle_t* binding) {
    if (binding == nullptr) {
        return false;
    }
    *binding = nullptr;
    RPC_WSTR stringBinding = nullptr;
    RPC_STATUS status = RpcStringBindingComposeW(nullptr, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)), nullptr, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)), nullptr, &stringBinding);
    if (status != RPC_S_OK) {
        return false;
    }
    status = RpcBindingFromStringBindingW(stringBinding, binding);
    RpcStringFreeW(&stringBinding);
    return status == RPC_S_OK;
}


RPC_STATUS RpcStopServiceSafe(handle_t binding) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        SakuraShieldStopService(binding);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcGetStateSafe(handle_t binding, long* authenticated, wchar_t** username, long* antivirusEnabled, long* hasLicense, long* licenseValid, wchar_t** licenseExpiresAt, wchar_t** message, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldGetState(binding, authenticated, username, antivirusEnabled, hasLicense, licenseValid, licenseExpiresAt, message);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcLoginSafe(handle_t binding, wchar_t* username, wchar_t* password, wchar_t** message, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldLogin(binding, username, password, message);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcLogoutSafe(handle_t binding, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldLogout(binding);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcActivateSafe(handle_t binding, wchar_t* activationCode, wchar_t** message, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldActivate(binding, activationCode, message);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}


RPC_STATUS RpcGetAvDatabaseInfoSafe(handle_t binding, wchar_t** releaseDate, long* recordCount, wchar_t** message, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldGetAvDatabaseInfo(binding, releaseDate, recordCount, message);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcScanFileSafe(handle_t binding, wchar_t* path, long* malicious, wchar_t** report, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldScanFile(binding, path, malicious, report);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcScanDirectorySafe(handle_t binding, wchar_t* path, long* scannedCount, long* detectedCount, wchar_t** report, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldScanDirectory(binding, path, scannedCount, detectedCount, report);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcScanFixedDrivesSafe(handle_t binding, long* scannedCount, long* detectedCount, wchar_t** report, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldScanFixedDrives(binding, scannedCount, detectedCount, report);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcSetScheduledScanSafe(handle_t binding, long enabled, long intervalSeconds, wchar_t** message, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldSetScheduledScan(binding, enabled, intervalSeconds, message);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcGetScheduledScanInfoSafe(handle_t binding, long* enabled, long* intervalSeconds, wchar_t** lastReport, wchar_t** message, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldGetScheduledScanInfo(binding, enabled, intervalSeconds, lastReport, message);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcStartDirectoryMonitorSafe(handle_t binding, wchar_t* path, wchar_t** message, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldStartDirectoryMonitor(binding, path, message);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcStopDirectoryMonitorSafe(handle_t binding, wchar_t** message, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldStopDirectoryMonitor(binding, message);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

RPC_STATUS RpcGetDirectoryMonitorInfoSafe(handle_t binding, long* enabled, wchar_t** monitoredPath, wchar_t** lastReport, wchar_t** message, long* result) {
    RPC_STATUS status = RPC_S_OK;
    RpcTryExcept
    {
        *result = SakuraShieldGetDirectoryMonitorInfo(binding, enabled, monitoredPath, lastReport, message);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept
    return status;
}

bool RequestServiceStop() {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        return false;
    }
    RPC_STATUS status = RpcStopServiceSafe(binding);
    RpcBindingFree(&binding);
    return status == RPC_S_OK;
}

void FreeRpcString(wchar_t*& value) {
    if (value != nullptr) {
        midl_user_free(value);
        value = nullptr;
    }
}

bool RefreshStateFromService() {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        g_state = {};
        g_state.message = L"RPC-служба недоступна";
        return false;
    }

    long authenticated = 0;
    long antivirusEnabled = 0;
    long hasLicense = 0;
    long licenseValid = 0;
    wchar_t* username = nullptr;
    wchar_t* expires = nullptr;
    wchar_t* message = nullptr;
    long result = 1;
    RPC_STATUS rpcStatus = RpcGetStateSafe(binding, &authenticated, &username, &antivirusEnabled, &hasLicense, &licenseValid, &expires, &message, &result);

    if (rpcStatus != RPC_S_OK || result != 0) {
        RpcBindingFree(&binding);
        FreeRpcString(username);
        FreeRpcString(expires);
        FreeRpcString(message);
        g_state = {};
        g_state.message = L"Не удалось получить состояние службы";
        return false;
    }

    wchar_t* databaseReleaseDate = nullptr;
    wchar_t* databaseMessage = nullptr;
    long recordCount = 0;
    long databaseResult = 1;
    RPC_STATUS databaseRpcStatus = RpcGetAvDatabaseInfoSafe(binding, &databaseReleaseDate, &recordCount, &databaseMessage, &databaseResult);

    RpcBindingFree(&binding);

    g_state.rpcOnline = true;
    g_state.authenticated = authenticated != 0;
    g_state.antivirusEnabled = antivirusEnabled != 0;
    g_state.hasLicense = hasLicense != 0;
    g_state.licenseValid = licenseValid != 0;
    g_state.username = username == nullptr ? L"" : username;
    g_state.licenseExpiresAt = expires == nullptr ? L"" : expires;
    g_state.message = message == nullptr ? L"" : message;
    if (databaseRpcStatus == RPC_S_OK && databaseResult == 0) {
        g_state.avDatabaseReleaseDate = databaseReleaseDate == nullptr ? L"" : databaseReleaseDate;
        g_state.avRecordCount = recordCount;
    }

    FreeRpcString(username);
    FreeRpcString(expires);
    FreeRpcString(message);
    FreeRpcString(databaseReleaseDate);
    FreeRpcString(databaseMessage);
    return true;
}

long CallLogin(const std::wstring& username, const std::wstring& password, std::wstring& messageText) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        messageText = L"RPC-служба недоступна";
        return 1;
    }
    wchar_t* message = nullptr;
    long result = 1;
    std::wstring mutableUsername = username;
    std::wstring mutablePassword = password;
    RPC_STATUS rpcStatus = RpcLoginSafe(binding, mutableUsername.data(), mutablePassword.data(), &message, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        messageText = L"Ошибка RPC при входе";
        FreeRpcString(message);
        return 1;
    }
    messageText = message == nullptr ? L"" : message;
    FreeRpcString(message);
    return result;
}

long CallLogout() {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        return 1;
    }
    long result = 1;
    RPC_STATUS rpcStatus = RpcLogoutSafe(binding, &result);
    RpcBindingFree(&binding);
    return rpcStatus == RPC_S_OK ? result : 1;
}

long CallActivate(const std::wstring& activationCode, std::wstring& messageText) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        messageText = L"RPC-служба недоступна";
        return 1;
    }
    wchar_t* message = nullptr;
    long result = 1;
    std::wstring mutableCode = activationCode;
    RPC_STATUS rpcStatus = RpcActivateSafe(binding, mutableCode.data(), &message, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        messageText = L"Ошибка RPC при активации";
        FreeRpcString(message);
        return 1;
    }
    messageText = message == nullptr ? L"" : message;
    FreeRpcString(message);
    return result;
}


long CallScanFile(const std::wstring& path, long& malicious, std::wstring& report) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        report = L"RPC-служба недоступна";
        return 1;
    }
    wchar_t* rpcReport = nullptr;
    long result = 1;
    malicious = 0;
    std::wstring mutablePath = path;
    RPC_STATUS rpcStatus = RpcScanFileSafe(binding, mutablePath.data(), &malicious, &rpcReport, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        report = L"Ошибка RPC при сканировании файла";
        FreeRpcString(rpcReport);
        return 1;
    }
    report = rpcReport == nullptr ? L"" : rpcReport;
    FreeRpcString(rpcReport);
    return result;
}

long CallScanDirectory(const std::wstring& path, long& scannedCount, long& detectedCount, std::wstring& report) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        report = L"RPC-служба недоступна";
        return 1;
    }
    wchar_t* rpcReport = nullptr;
    long result = 1;
    scannedCount = 0;
    detectedCount = 0;
    std::wstring mutablePath = path;
    RPC_STATUS rpcStatus = RpcScanDirectorySafe(binding, mutablePath.data(), &scannedCount, &detectedCount, &rpcReport, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        report = L"Ошибка RPC при сканировании папки";
        FreeRpcString(rpcReport);
        return 1;
    }
    report = rpcReport == nullptr ? L"" : rpcReport;
    FreeRpcString(rpcReport);
    return result;
}

long CallScanFixedDrives(long& scannedCount, long& detectedCount, std::wstring& report) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        report = L"RPC-служба недоступна";
        return 1;
    }
    wchar_t* rpcReport = nullptr;
    long result = 1;
    scannedCount = 0;
    detectedCount = 0;
    RPC_STATUS rpcStatus = RpcScanFixedDrivesSafe(binding, &scannedCount, &detectedCount, &rpcReport, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        report = L"Ошибка RPC при сканировании дисков";
        FreeRpcString(rpcReport);
        return 1;
    }
    report = rpcReport == nullptr ? L"" : rpcReport;
    FreeRpcString(rpcReport);
    return result;
}

long CallSetScheduledScan(bool enabled, long intervalSeconds, std::wstring& messageText) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        messageText = L"RPC-служба недоступна";
        return 1;
    }
    wchar_t* message = nullptr;
    long result = 1;
    RPC_STATUS rpcStatus = RpcSetScheduledScanSafe(binding, enabled ? 1 : 0, intervalSeconds, &message, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        messageText = L"Ошибка RPC при настройке расписания";
        FreeRpcString(message);
        return 1;
    }
    messageText = message == nullptr ? L"" : message;
    FreeRpcString(message);
    return result;
}

long CallGetScheduledScanInfo(std::wstring& report) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        report = L"RPC-служба недоступна";
        return 1;
    }
    long enabled = 0;
    long interval = 0;
    wchar_t* lastReport = nullptr;
    wchar_t* message = nullptr;
    long result = 1;
    RPC_STATUS rpcStatus = RpcGetScheduledScanInfoSafe(binding, &enabled, &interval, &lastReport, &message, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        report = L"Ошибка RPC при получении расписания";
        FreeRpcString(lastReport);
        FreeRpcString(message);
        return 1;
    }
    report = std::wstring(L"Расписание: ") + (enabled ? L"включено" : L"отключено") + L"\r\nИнтервал: " + std::to_wstring(interval) + L" сек.\r\n" + (lastReport == nullptr ? L"" : lastReport);
    FreeRpcString(lastReport);
    FreeRpcString(message);
    return result;
}

long CallStartDirectoryMonitor(const std::wstring& path, std::wstring& messageText) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        messageText = L"RPC-служба недоступна";
        return 1;
    }
    wchar_t* message = nullptr;
    long result = 1;
    std::wstring mutablePath = path;
    RPC_STATUS rpcStatus = RpcStartDirectoryMonitorSafe(binding, mutablePath.data(), &message, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        messageText = L"Ошибка RPC при запуске мониторинга";
        FreeRpcString(message);
        return 1;
    }
    messageText = message == nullptr ? L"" : message;
    FreeRpcString(message);
    return result;
}

long CallStopDirectoryMonitor(std::wstring& messageText) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        messageText = L"RPC-служба недоступна";
        return 1;
    }
    wchar_t* message = nullptr;
    long result = 1;
    RPC_STATUS rpcStatus = RpcStopDirectoryMonitorSafe(binding, &message, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        messageText = L"Ошибка RPC при остановке мониторинга";
        FreeRpcString(message);
        return 1;
    }
    messageText = message == nullptr ? L"" : message;
    FreeRpcString(message);
    return result;
}

long CallGetDirectoryMonitorInfo(std::wstring& report) {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        report = L"RPC-служба недоступна";
        return 1;
    }
    long enabled = 0;
    wchar_t* monitoredPath = nullptr;
    wchar_t* lastReport = nullptr;
    wchar_t* message = nullptr;
    long result = 1;
    RPC_STATUS rpcStatus = RpcGetDirectoryMonitorInfoSafe(binding, &enabled, &monitoredPath, &lastReport, &message, &result);
    RpcBindingFree(&binding);
    if (rpcStatus != RPC_S_OK) {
        report = L"Ошибка RPC при получении мониторинга";
        FreeRpcString(monitoredPath);
        FreeRpcString(lastReport);
        FreeRpcString(message);
        return 1;
    }
    report = std::wstring(L"Мониторинг: ") + (enabled ? L"включен" : L"отключен") + L"\r\nПапка: " + (monitoredPath == nullptr ? L"" : monitoredPath) + L"\r\n" + (lastReport == nullptr ? L"" : lastReport);
    FreeRpcString(monitoredPath);
    FreeRpcString(lastReport);
    FreeRpcString(message);
    return result;
}

std::wstring SelectFilePath(HWND owner) {
    wchar_t path[MAX_PATH]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner;
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrFilter = L"Все файлы\0*.*\0";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    return GetOpenFileNameW(&dialog) == TRUE ? std::wstring(path) : L"";
}

std::wstring SelectFolderPath(HWND owner) {
    BROWSEINFOW info{};
    info.hwndOwner = owner;
    info.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    info.lpszTitle = L"Выберите папку для сканирования";
    PIDLIST_ABSOLUTE item = SHBrowseForFolderW(&info);
    if (item == nullptr) {
        return L"";
    }
    wchar_t path[MAX_PATH]{};
    BOOL ok = SHGetPathFromIDListW(item, path);
    CoTaskMemFree(item);
    return ok == TRUE ? std::wstring(path) : L"";
}

std::wstring GetWindowTextString(HWND control) {
    int length = GetWindowTextLengthW(control);
    std::wstring result(length + 1, L'\0');
    GetWindowTextW(control, result.data(), length + 1);
    result.resize(length);
    return result;
}

void ShowMainWindow(HWND window) {
    ShowWindow(window, SW_SHOW);
    SetForegroundWindow(window);
}

HICON CreateSakuraIcon() {
    const int size = 32;
    HDC screen = GetDC(nullptr);
    HDC memory = CreateCompatibleDC(screen);
    HBITMAP colorBitmap = CreateCompatibleBitmap(screen, size, size);
    HGDIOBJ oldBitmap = SelectObject(memory, colorBitmap);

    HBRUSH background = CreateSolidBrush(RGB(255, 217, 237));
    RECT full{ 0, 0, size, size };
    FillRect(memory, &full, background);
    DeleteObject(background);

    HBRUSH coreBrush = CreateSolidBrush(RGB(255, 117, 188));
    HGDIOBJ oldBrush = SelectObject(memory, coreBrush);
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(158, 50, 118));
    HGDIOBJ oldPen = SelectObject(memory, pen);
    Ellipse(memory, 5, 5, 27, 27);
    SelectObject(memory, oldBrush);
    SelectObject(memory, oldPen);
    DeleteObject(coreBrush);
    DeleteObject(pen);

    SetBkMode(memory, TRANSPARENT);
    SetTextColor(memory, RGB(255, 255, 255));
    HFONT font = CreateFontW(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
    HGDIOBJ oldFont = SelectObject(memory, font);
    DrawTextW(memory, L"S", -1, &full, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(memory, oldFont);
    DeleteObject(font);

    const int maskStride = ((size + 15) / 16) * 2;
    std::vector<BYTE> maskBits(maskStride * size, 0);
    HBITMAP maskBitmap = CreateBitmap(size, size, 1, 1, maskBits.data());

    ICONINFO iconInfo{};
    iconInfo.fIcon = TRUE;
    iconInfo.hbmMask = maskBitmap;
    iconInfo.hbmColor = colorBitmap;
    HICON icon = CreateIconIndirect(&iconInfo);

    SelectObject(memory, oldBitmap);
    DeleteObject(maskBitmap);
    DeleteObject(colorBitmap);
    DeleteDC(memory);
    ReleaseDC(nullptr, screen);
    return icon;
}

void CreateUiResources() {
    g_backgroundBrush = CreateSolidBrush(RGB(255, 229, 243));
    g_panelBrush = CreateSolidBrush(RGB(255, 247, 251));
    g_titleFont = CreateFontW(34, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
    g_statusFont = CreateFontW(20, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Yu Gothic UI");
    g_smallFont = CreateFontW(17, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");
    g_trayIcon = CreateSakuraIcon();
    if (g_trayIcon == nullptr) {
        g_trayIcon = LoadIconW(nullptr, IDI_APPLICATION);
    }
}

void ReleaseUiResources() {
    if (g_titleFont != nullptr) { DeleteObject(g_titleFont); g_titleFont = nullptr; }
    if (g_statusFont != nullptr) { DeleteObject(g_statusFont); g_statusFont = nullptr; }
    if (g_smallFont != nullptr) { DeleteObject(g_smallFont); g_smallFont = nullptr; }
    if (g_backgroundBrush != nullptr) { DeleteObject(g_backgroundBrush); g_backgroundBrush = nullptr; }
    if (g_panelBrush != nullptr) { DeleteObject(g_panelBrush); g_panelBrush = nullptr; }
    if (g_trayIcon != nullptr) { DestroyIcon(g_trayIcon); g_trayIcon = nullptr; }
}

void AddTrayIcon(HWND window) {
    ZeroMemory(&g_trayIconData, sizeof(g_trayIconData));
    g_trayIconData.cbSize = sizeof(g_trayIconData);
    g_trayIconData.hWnd = window;
    g_trayIconData.uID = kTrayIconId;
    g_trayIconData.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_trayIconData.uCallbackMessage = kTrayCallbackMessage;
    g_trayIconData.hIcon = g_trayIcon != nullptr ? g_trayIcon : LoadIconW(nullptr, IDI_APPLICATION);
    wcscpy_s(g_trayIconData.szTip, kTrayTooltip);
    if (Shell_NotifyIconW(NIM_ADD, &g_trayIconData) == TRUE) {
        g_trayIconAdded = true;
        return;
    }
    if (Shell_NotifyIconW(NIM_MODIFY, &g_trayIconData) == TRUE) {
        g_trayIconAdded = true;
    }
}

void RemoveTrayIcon() {
    if (g_trayIconAdded) {
        Shell_NotifyIconW(NIM_DELETE, &g_trayIconData);
        g_trayIconAdded = false;
    }
}

void ShowTrayContextMenu(HWND window) {
    POINT cursorPosition{};
    GetCursorPos(&cursorPosition);
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, kCommandTrayOpen, L"Открыть");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kCommandTrayExit, L"Выход");
    SetForegroundWindow(window);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_BOTTOMALIGN, cursorPosition.x, cursorPosition.y, 0, window, nullptr);
    DestroyMenu(menu);
    PostMessageW(window, WM_NULL, 0, 0);
}

void ExitApplication(HWND window) {
    g_isExiting = true;
    if (!RequestServiceStop()) {
        RemoveTrayIcon();
        DestroyWindow(window);
    }
}

void CreateMainMenu(HWND window) {
    HMENU mainMenu = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();
    AppendMenuW(fileMenu, MF_STRING, kCommandFileExit, L"Выход");
    AppendMenuW(mainMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"Файл");
    SetMenu(window, mainMenu);
}

HWND CreateChild(const wchar_t* className, const wchar_t* text, DWORD style, DWORD exStyle, int id) {
    HWND control = CreateWindowExW(exStyle, className, text, WS_CHILD | style, 0, 0, 0, 0, g_mainWindow, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_instance, nullptr);
    if (control != nullptr && g_smallFont != nullptr) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_smallFont), TRUE);
    }
    return control;
}

void CreateChildControls(HWND window) {
    g_mainWindow = window;
    g_usernameEdit = CreateChild(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, kControlUsername);
    g_passwordEdit = CreateChild(L"EDIT", L"", WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, kControlPassword);
    g_loginButton = CreateChild(L"BUTTON", L"Войти", BS_PUSHBUTTON, 0, kControlLogin);
    g_activationEdit = CreateChild(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, kControlActivation);
    g_activateButton = CreateChild(L"BUTTON", L"Активировать", BS_PUSHBUTTON, 0, kControlActivate);
    g_logoutButton = CreateChild(L"BUTTON", L"Выйти из аккаунта", BS_PUSHBUTTON, 0, kControlLogout);
    g_refreshButton = CreateChild(L"BUTTON", L"Обновить статус", BS_PUSHBUTTON, 0, kControlRefresh);
    g_scanFileButton = CreateChild(L"BUTTON", L"Сканировать файл", BS_PUSHBUTTON, 0, kControlScanFile);
    g_scanFolderButton = CreateChild(L"BUTTON", L"Сканировать папку", BS_PUSHBUTTON, 0, kControlScanFolder);
    g_clearScanButton = CreateChild(L"BUTTON", L"Очистить результат", BS_PUSHBUTTON, 0, kControlClearScan);
    g_scanDrivesButton = CreateChild(L"BUTTON", L"Все диски", BS_PUSHBUTTON, 0, kControlScanDrives);
    g_scheduleScanButton = CreateChild(L"BUTTON", L"Расписание", BS_PUSHBUTTON, 0, kControlScheduleScan);
    g_startMonitorButton = CreateChild(L"BUTTON", L"Мониторинг", BS_PUSHBUTTON, 0, kControlStartMonitor);
    g_stopMonitorButton = CreateChild(L"BUTTON", L"Стоп монитор", BS_PUSHBUTTON, 0, kControlStopMonitor);
}

void PositionControls() {
    RECT client{};
    GetClientRect(g_mainWindow, &client);
    const int panelWidth = 620;
    const int left = (client.right - panelWidth) / 2;
    MoveWindow(g_usernameEdit, left + 170, 205, 280, 28, TRUE);
    MoveWindow(g_passwordEdit, left + 170, 245, 280, 28, TRUE);
    MoveWindow(g_loginButton, left + 235, 288, 150, 34, TRUE);
    MoveWindow(g_activationEdit, left + 140, 235, 340, 28, TRUE);
    MoveWindow(g_activateButton, left + 225, 278, 170, 34, TRUE);
    MoveWindow(g_logoutButton, left + 200, 555, 220, 34, TRUE);
    MoveWindow(g_refreshButton, left + 20, 295, 130, 32, TRUE);
    MoveWindow(g_scanFileButton, left + 160, 295, 130, 32, TRUE);
    MoveWindow(g_scanFolderButton, left + 300, 295, 130, 32, TRUE);
    MoveWindow(g_scanDrivesButton, left + 440, 295, 130, 32, TRUE);
    MoveWindow(g_scheduleScanButton, left + 40, 335, 130, 32, TRUE);
    MoveWindow(g_startMonitorButton, left + 180, 335, 130, 32, TRUE);
    MoveWindow(g_stopMonitorButton, left + 320, 335, 130, 32, TRUE);
    MoveWindow(g_clearScanButton, left + 460, 335, 130, 32, TRUE);
}

void UpdateViewMode() {
    if (!g_state.authenticated) {
        g_viewMode = ViewMode::Login;
    } else if (!g_state.licenseValid) {
        g_viewMode = ViewMode::Activation;
    } else {
        g_viewMode = ViewMode::Main;
    }

    const BOOL loginVisible = g_viewMode == ViewMode::Login ? SW_SHOW : SW_HIDE;
    const BOOL activationVisible = g_viewMode == ViewMode::Activation ? SW_SHOW : SW_HIDE;
    const BOOL mainVisible = g_viewMode == ViewMode::Main ? SW_SHOW : SW_HIDE;

    ShowWindow(g_usernameEdit, loginVisible);
    ShowWindow(g_passwordEdit, loginVisible);
    ShowWindow(g_loginButton, loginVisible);
    ShowWindow(g_activationEdit, activationVisible);
    ShowWindow(g_activateButton, activationVisible);
    ShowWindow(g_logoutButton, g_state.authenticated ? SW_SHOW : SW_HIDE);
    ShowWindow(g_refreshButton, mainVisible);
    ShowWindow(g_scanFileButton, mainVisible);
    ShowWindow(g_scanFolderButton, mainVisible);
    ShowWindow(g_clearScanButton, mainVisible);
    ShowWindow(g_scanDrivesButton, mainVisible);
    ShowWindow(g_scheduleScanButton, mainVisible);
    ShowWindow(g_startMonitorButton, mainVisible);
    ShowWindow(g_stopMonitorButton, mainVisible);
}

void RefreshStateAndUi() {
    RefreshStateFromService();
    UpdateViewMode();
    InvalidateRect(g_mainWindow, nullptr, TRUE);
}

void DrawRoundedPanel(HDC deviceContext, const RECT& rect) {
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(237, 164, 210));
    HGDIOBJ oldPen = SelectObject(deviceContext, pen);
    HGDIOBJ oldBrush = SelectObject(deviceContext, g_panelBrush);
    RoundRect(deviceContext, rect.left, rect.top, rect.right, rect.bottom, 26, 26);
    SelectObject(deviceContext, oldBrush);
    SelectObject(deviceContext, oldPen);
    DeleteObject(pen);
}

std::wstring VisibleMessage() {
    if (!g_localMessage.empty()) {
        return g_localMessage;
    }
    return g_state.message;
}

void DrawCenteredText(HDC dc, const std::wstring& text, RECT rect, HFONT font, COLORREF color, UINT flags = DT_CENTER | DT_WORDBREAK | DT_VCENTER) {
    SelectObject(dc, font);
    SetTextColor(dc, color);
    DrawTextW(dc, text.c_str(), -1, &rect, flags);
}

void PaintMainWindow(HWND window) {
    PAINTSTRUCT paintStruct{};
    HDC deviceContext = BeginPaint(window, &paintStruct);
    RECT clientRect{};
    GetClientRect(window, &clientRect);
    FillRect(deviceContext, &clientRect, g_backgroundBrush);
    SetBkMode(deviceContext, TRANSPARENT);

    DrawCenteredText(deviceContext, L"Sakura Shield ♡", RECT{ 0, 26, clientRect.right, 76 }, g_titleFont, RGB(128, 42, 98), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    DrawCenteredText(deviceContext, L"account guard / activation / scan mode", RECT{ 0, 72, clientRect.right, 102 }, g_smallFont, RGB(154, 77, 126), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    const int panelWidth = 620;
    const int panelHeight = 520;
    const int left = (clientRect.right - panelWidth) / 2;
    RECT panelRect{ left, 122, left + panelWidth, 122 + panelHeight };
    DrawRoundedPanel(deviceContext, panelRect);

    if (g_viewMode == ViewMode::Login) {
        DrawCenteredText(deviceContext, L"Вход в учетную запись", RECT{ panelRect.left + 30, panelRect.top + 24, panelRect.right - 30, panelRect.top + 60 }, g_statusFont, RGB(91, 48, 83));
        DrawCenteredText(deviceContext, L"Логин", RECT{ panelRect.left + 75, 201, panelRect.left + 145, 232 }, g_smallFont, RGB(143, 73, 119), DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        DrawCenteredText(deviceContext, L"Пароль", RECT{ panelRect.left + 75, 241, panelRect.left + 145, 272 }, g_smallFont, RGB(143, 73, 119), DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        DrawCenteredText(deviceContext, L"Антивирус заблокирован до входа в аккаунт", RECT{ panelRect.left + 40, 335, panelRect.right - 40, 365 }, g_smallFont, RGB(150, 58, 105));
    } else if (g_viewMode == ViewMode::Activation) {
        DrawCenteredText(deviceContext, L"Активация продукта", RECT{ panelRect.left + 30, panelRect.top + 22, panelRect.right - 30, panelRect.top + 58 }, g_statusFont, RGB(91, 48, 83));
        std::wstring userLine = L"Пользователь: " + g_state.username;
        DrawCenteredText(deviceContext, userLine, RECT{ panelRect.left + 40, 175, panelRect.right - 40, 205 }, g_smallFont, RGB(91, 48, 83));
        DrawCenteredText(deviceContext, L"Код активации", RECT{ panelRect.left + 120, 205, panelRect.right - 120, 232 }, g_smallFont, RGB(143, 73, 119));
        DrawCenteredText(deviceContext, L"Лицензия отсутствует, истекла или заблокирована. Антивирус заблокирован.", RECT{ panelRect.left + 40, 335, panelRect.right - 40, 372 }, g_smallFont, RGB(150, 58, 105));
    } else {
        DrawCenteredText(deviceContext, L"Антивирус разблокирован", RECT{ panelRect.left + 30, panelRect.top + 20, panelRect.right - 30, panelRect.top + 55 }, g_statusFont, RGB(91, 48, 83));
        std::wstring text = L"Пользователь: " + g_state.username + L"\r\nЛицензия активна до: " + g_state.licenseExpiresAt + L"\r\nБазы выпущены: " + g_state.avDatabaseReleaseDate + L"\r\nЗаписей в базе: " + std::to_wstring(g_state.avRecordCount) + L"\r\n\r\n[ OK ] license ........ active\r\n[ OK ] av database .... loaded\r\n[ OK ] scan engine .... ready ♡";
        DrawCenteredText(deviceContext, text, RECT{ panelRect.left + 38, 155, panelRect.right - 38, 285 }, g_smallFont, RGB(91, 48, 83), DT_CENTER | DT_WORDBREAK);
        std::wstring scanText = g_scanReport.empty() ? L"Результаты сканирования появятся здесь" : g_scanReport;
        DrawCenteredText(deviceContext, scanText, RECT{ panelRect.left + 35, 385, panelRect.right - 35, panelRect.bottom - 58 }, g_smallFont, RGB(91, 48, 83), DT_CENTER | DT_WORDBREAK | DT_TOP);
    }

    std::wstring message = VisibleMessage();
    if (!message.empty()) {
        DrawCenteredText(deviceContext, message, RECT{ panelRect.left + 38, panelRect.bottom - 48, panelRect.right - 38, panelRect.bottom - 12 }, g_smallFont, RGB(176, 47, 98));
    }

    EndPaint(window, &paintStruct);
}

void HandleLogin() {
    std::wstring username = GetWindowTextString(g_usernameEdit);
    std::wstring password = GetWindowTextString(g_passwordEdit);
    std::wstring message;
    long result = CallLogin(username, password, message);
    g_localMessage = result == 0 ? L"Вход выполнен" : message;
    SetWindowTextW(g_passwordEdit, L"");
    RefreshStateAndUi();
}

void HandleActivation() {
    std::wstring activationCode = GetWindowTextString(g_activationEdit);
    std::wstring message;
    long result = CallActivate(activationCode, message);
    g_localMessage = result == 0 ? L"Продукт активирован" : message;
    if (result == 0) {
        SetWindowTextW(g_activationEdit, L"");
    }
    RefreshStateAndUi();
}

void HandleLogout() {
    CallLogout();
    g_localMessage = L"Выполнен выход из аккаунта";
    RefreshStateAndUi();
}


void HandleScanFile() {
    std::wstring path = SelectFilePath(g_mainWindow);
    if (path.empty()) {
        return;
    }
    long malicious = 0;
    std::wstring report;
    long result = CallScanFile(path, malicious, report);
    g_scanReport = report;
    g_localMessage = result == 0 ? (malicious ? L"Файл вредоносный" : L"Файл чистый") : report;
    RefreshStateAndUi();
}

void HandleScanFolder() {
    std::wstring path = SelectFolderPath(g_mainWindow);
    if (path.empty()) {
        return;
    }
    long scanned = 0;
    long detected = 0;
    std::wstring report;
    long result = CallScanDirectory(path, scanned, detected, report);
    g_scanReport = report;
    g_localMessage = result == 0 ? L"Сканирование папки завершено" : report;
    RefreshStateAndUi();
}

void HandleScanDrives() {
    long scanned = 0;
    long detected = 0;
    std::wstring report;
    long result = CallScanFixedDrives(scanned, detected, report);
    g_scanReport = report;
    g_localMessage = result == 0 ? L"Сканирование дисков завершено" : report;
    RefreshStateAndUi();
}

void HandleScheduleScan() {
    std::wstring message;
    long result = CallSetScheduledScan(true, 60, message);
    std::wstring info;
    CallGetScheduledScanInfo(info);
    g_scanReport = info;
    g_localMessage = result == 0 ? message : message;
    RefreshStateAndUi();
}

void HandleStartMonitor() {
    std::wstring path = SelectFolderPath(g_mainWindow);
    if (path.empty()) {
        return;
    }
    std::wstring message;
    long result = CallStartDirectoryMonitor(path, message);
    std::wstring info;
    CallGetDirectoryMonitorInfo(info);
    g_scanReport = info;
    g_localMessage = result == 0 ? message : message;
    RefreshStateAndUi();
}

void HandleStopMonitor() {
    std::wstring message;
    long result = CallStopDirectoryMonitor(message);
    std::wstring info;
    CallGetDirectoryMonitorInfo(info);
    g_scanReport = info;
    g_localMessage = result == 0 ? message : message;
    RefreshStateAndUi();
}

LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == g_taskbarCreatedMessage) {
        AddTrayIcon(window);
        return 0;
    }

    switch (message) {
    case WM_CREATE:
        CreateUiResources();
        CreateMainMenu(window);
        CreateChildControls(window);
        PositionControls();
        RefreshStateAndUi();
        SetTimer(window, kTimerStateRefresh, 10000, nullptr);
        return 0;

    case WM_SIZE:
        PositionControls();
        return 0;

    case WM_TIMER:
        if (wParam == kTimerStateRefresh) {
            g_localMessage.clear();
            RefreshStateAndUi();
            return 0;
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case kCommandTrayOpen:
            RefreshStateAndUi();
            ShowMainWindow(window);
            return 0;
        case kCommandTrayExit:
        case kCommandFileExit:
            ExitApplication(window);
            return 0;
        case kControlLogin:
            HandleLogin();
            return 0;
        case kControlActivate:
            HandleActivation();
            return 0;
        case kControlLogout:
            HandleLogout();
            return 0;
        case kControlRefresh:
            g_localMessage = L"Статус обновлен";
            RefreshStateAndUi();
            return 0;
        case kControlScanFile:
            HandleScanFile();
            return 0;
        case kControlScanFolder:
            HandleScanFolder();
            return 0;
        case kControlScanDrives:
            HandleScanDrives();
            return 0;
        case kControlScheduleScan:
            HandleScheduleScan();
            return 0;
        case kControlStartMonitor:
            HandleStartMonitor();
            return 0;
        case kControlStopMonitor:
            HandleStopMonitor();
            return 0;
        case kControlClearScan:
            g_scanReport.clear();
            g_localMessage = L"Результат очищен";
            RefreshStateAndUi();
            return 0;
        default:
            break;
        }
        break;

    case kTrayCallbackMessage:
        switch (LOWORD(lParam)) {
        case WM_LBUTTONUP:
            RefreshStateAndUi();
            ShowMainWindow(window);
            return 0;
        case WM_RBUTTONUP:
            ShowTrayContextMenu(window);
            return 0;
        default:
            break;
        }
        break;

    case WM_CLOSE:
        if (!g_isExiting) {
            ShowWindow(window, SW_HIDE);
            return 0;
        }
        break;

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT:
        PaintMainWindow(window);
        return 0;

    case WM_DESTROY:
        KillTimer(window, kTimerStateRefresh);
        RemoveTrayIcon();
        ReleaseUiResources();
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProcW(window, message, wParam, lParam);
}

bool RegisterMainWindowClass() {
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(WNDCLASSEXW);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = g_instance;
    windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = kWindowClassName;
    windowClass.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    return RegisterClassExW(&windowClass) != 0;
}

HWND CreateMainWindow() {
    return CreateWindowExW(0, kWindowClassName, kWindowTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 930, 760, nullptr, nullptr, g_instance, nullptr);
}

}

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR commandLine, int) {
    g_instance = instance;

    if (ShouldExitAfterServiceBootstrap()) {
        return 0;
    }

    if (!IsParentServiceProcess()) {
        return 0;
    }

    if (!CreateSingleInstanceGuard()) {
        return 0;
    }

    g_taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    if (!RegisterMainWindowClass()) {
        ReleaseSingleInstanceGuard();
        return 1;
    }

    g_mainWindow = CreateMainWindow();
    if (g_mainWindow == nullptr) {
        ReleaseSingleInstanceGuard();
        return 1;
    }

    AddTrayIcon(g_mainWindow);

    if (!ShouldStartHidden(commandLine)) {
        ShowMainWindow(g_mainWindow);
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    ReleaseSingleInstanceGuard();
    return static_cast<int>(message.wParam);
}
