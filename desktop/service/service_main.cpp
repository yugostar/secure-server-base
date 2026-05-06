#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>

#include "SakuraShieldRpc.h"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <sstream>
#include <cwctype>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kServiceName[] = L"SakuraShieldService";
constexpr wchar_t kServiceDisplayName[] = L"Sakura Shield Service";
constexpr wchar_t kGuiExecutableName[] = L"SakuraShield.exe";
constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"SakuraShieldRpcEndpoint";

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_serviceStatus{};
std::mutex g_processMutex;
std::map<DWORD, PROCESS_INFORMATION> g_guiProcesses;
std::atomic_bool g_rpcStopRequested = false;


std::wstring GetLogPath() {
    CreateDirectoryW(L"C:\\ProgramData\\SakuraShield", nullptr);
    return L"C:\\ProgramData\\SakuraShield\\service.log";
}

void LogLine(const std::wstring& message) {
    std::wofstream log(GetLogPath(), std::ios::app);
    if (log.is_open()) {
        SYSTEMTIME time{};
        GetLocalTime(&time);
        log << L"[" << time.wYear << L"-" << time.wMonth << L"-" << time.wDay
            << L" " << time.wHour << L":" << time.wMinute << L":" << time.wSecond
            << L"] " << message << std::endl;
    }
}

void LogWin32Error(const std::wstring& stage, DWORD error) {
    std::wstringstream stream;
    stream << stage << L" failed, error=" << error;
    LogLine(stream.str());
}


std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

bool EqualsIgnoreCase(const std::wstring& left, const std::wstring& right) {
    return ToLower(left) == ToLower(right);
}

bool ContainsFlag(const std::wstring& value, const wchar_t* flag) {
    return ToLower(value).find(flag) != std::wstring::npos;
}

std::wstring QuotePath(const std::wstring& path) {
    return L"\"" + path + L"\"";
}

std::wstring GetModulePath() {
    std::wstring path(MAX_PATH, L'\0');

    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            return L"";
        }

        if (length < path.size() - 1) {
            path.resize(length);
            return path;
        }

        path.resize(path.size() * 2);
    }
}

std::wstring GetDirectoryName(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return L".";
    }
    return path.substr(0, slash);
}

std::wstring GetGuiExecutablePath() {
    const std::wstring servicePath = GetModulePath();
    if (servicePath.empty()) {
        return L"";
    }

    return GetDirectoryName(servicePath) + L"\\" + kGuiExecutableName;
}

void CloseProcessInformation(PROCESS_INFORMATION& processInformation) {
    if (processInformation.hProcess != nullptr) {
        CloseHandle(processInformation.hProcess);
        processInformation.hProcess = nullptr;
    }

    if (processInformation.hThread != nullptr) {
        CloseHandle(processInformation.hThread);
        processInformation.hThread = nullptr;
    }
}

bool IsProcessRunning(HANDLE process) {
    if (process == nullptr) {
        return false;
    }

    DWORD exitCode = 0;
    if (GetExitCodeProcess(process, &exitCode) == FALSE) {
        return false;
    }

    return exitCode == STILL_ACTIVE;
}

void RemoveExitedGuiProcessesLocked() {
    for (auto iterator = g_guiProcesses.begin(); iterator != g_guiProcesses.end();) {
        if (!IsProcessRunning(iterator->second.hProcess)) {
            CloseProcessInformation(iterator->second);
            iterator = g_guiProcesses.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

bool HasGuiProcessForSession(DWORD sessionId) {
    std::lock_guard<std::mutex> lock(g_processMutex);
    RemoveExitedGuiProcessesLocked();
    return g_guiProcesses.find(sessionId) != g_guiProcesses.end();
}


size_t GetGuiProcessCount() {
    std::lock_guard<std::mutex> lock(g_processMutex);
    RemoveExitedGuiProcessesLocked();
    return g_guiProcesses.size();
}


void StoreGuiProcess(DWORD sessionId, PROCESS_INFORMATION processInformation) {
    std::lock_guard<std::mutex> lock(g_processMutex);
    RemoveExitedGuiProcessesLocked();

    auto existing = g_guiProcesses.find(sessionId);
    if (existing != g_guiProcesses.end()) {
        if (IsProcessRunning(existing->second.hProcess)) {
            TerminateProcess(existing->second.hProcess, 0);
        }
        CloseProcessInformation(existing->second);
        g_guiProcesses.erase(existing);
    }

    g_guiProcesses.emplace(sessionId, processInformation);
}

void TerminateAllGuiProcesses() {
    std::lock_guard<std::mutex> lock(g_processMutex);

    for (auto& entry : g_guiProcesses) {
        if (IsProcessRunning(entry.second.hProcess)) {
            TerminateProcess(entry.second.hProcess, 0);
        }
        CloseProcessInformation(entry.second);
    }

    g_guiProcesses.clear();
}

bool DuplicateSessionUserToken(HANDLE userToken, HANDLE& primaryToken) {
    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);

    return DuplicateTokenEx(
        userToken,
        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_GROUPS,
        &securityAttributes,
        SecurityIdentification,
        TokenPrimary,
        &primaryToken
    ) == TRUE;
}

void LaunchGuiForSession(DWORD sessionId) {
    if (sessionId == 0 || HasGuiProcessForSession(sessionId)) {
        return;
    }

    {
        std::wstringstream stream;
        stream << L"launch request for session " << sessionId;
        LogLine(stream.str());
    }

    HANDLE userToken = nullptr;
    if (WTSQueryUserToken(sessionId, &userToken) == FALSE) {
        LogWin32Error(L"WTSQueryUserToken", GetLastError());
        return;
    }

    HANDLE duplicatedToken = nullptr;
    HANDLE launchToken = userToken;

    if (DuplicateTokenEx(
        userToken,
        MAXIMUM_ALLOWED,
        nullptr,
        SecurityImpersonation,
        TokenPrimary,
        &duplicatedToken) == TRUE) {
        launchToken = duplicatedToken;
    } else {
        LogWin32Error(L"DuplicateTokenEx", GetLastError());
    }

    LPVOID environment = nullptr;
    const BOOL environmentCreated = CreateEnvironmentBlock(&environment, launchToken, FALSE);
    if (environmentCreated == FALSE) {
        LogWin32Error(L"CreateEnvironmentBlock", GetLastError());
    }

    const std::wstring guiPath = GetGuiExecutablePath();
    if (guiPath.empty()) {
        LogLine(L"GUI path is empty");
        if (environmentCreated) {
            DestroyEnvironmentBlock(environment);
        }
        if (duplicatedToken != nullptr) {
            CloseHandle(duplicatedToken);
        }
        CloseHandle(userToken);
        return;
    }

    const std::wstring workingDirectory = GetDirectoryName(guiPath);
    std::wstring commandLine = QuotePath(guiPath) + L" --hidden";

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInformation{};

    const BOOL created = CreateProcessAsUserW(
        launchToken,
        nullptr,
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS,
        environmentCreated ? environment : nullptr,
        workingDirectory.c_str(),
        &startupInfo,
        &processInformation
    );

    if (created == FALSE) {
        LogWin32Error(L"CreateProcessAsUserW", GetLastError());
    } else {
        std::wstringstream stream;
        stream << L"GUI started, pid=" << processInformation.dwProcessId << L", session=" << sessionId;
        LogLine(stream.str());
        StoreGuiProcess(sessionId, processInformation);
    }

    if (environmentCreated) {
        DestroyEnvironmentBlock(environment);
    }

    if (duplicatedToken != nullptr) {
        CloseHandle(duplicatedToken);
    }

    CloseHandle(userToken);
}

void LaunchGuiForExistingSessions() {
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;

    LogLine(L"enumerating terminal sessions");

    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count) == FALSE) {
        LogWin32Error(L"WTSEnumerateSessionsW", GetLastError());
    } else {
        for (DWORD index = 0; index < count; ++index) {
            std::wstringstream stream;
            stream << L"session " << sessions[index].SessionId << L", state=" << sessions[index].State;
            LogLine(stream.str());

            if (sessions[index].SessionId != 0) {
                LaunchGuiForSession(sessions[index].SessionId);
            }
        }

        WTSFreeMemory(sessions);
    }

    if (GetGuiProcessCount() == 0) {
        const DWORD activeSessionId = WTSGetActiveConsoleSessionId();
        if (activeSessionId != 0 && activeSessionId != 0xFFFFFFFF) {
            std::wstringstream stream;
            stream << L"fallback active console session " << activeSessionId;
            LogLine(stream.str());
            LaunchGuiForSession(activeSessionId);
        }
    }
}

void SetServiceState(DWORD state, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0) {
    static DWORD checkpoint = 1;

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = state;
    g_serviceStatus.dwWin32ExitCode = win32ExitCode;
    g_serviceStatus.dwWaitHint = waitHint;

    if (state == SERVICE_RUNNING) {
        g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;
        g_serviceStatus.dwCheckPoint = 0;
    } else if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        g_serviceStatus.dwControlsAccepted = 0;
        g_serviceStatus.dwCheckPoint = checkpoint++;
    } else {
        g_serviceStatus.dwControlsAccepted = 0;
        g_serviceStatus.dwCheckPoint = 0;
    }

    if (g_statusHandle != nullptr) {
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
    }
}

bool StartRpcServer() {
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr
    );

    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
        return false;
    }

    status = RpcServerRegisterIf2(
        SakuraShieldRpc_v1_0_s_ifspec,
        nullptr,
        nullptr,
        RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        static_cast<unsigned int>(-1),
        nullptr
    );

    return status == RPC_S_OK || status == RPC_S_TYPE_ALREADY_REGISTERED;
}

void StopRpcServer() {
    RpcServerUnregisterIf(SakuraShieldRpc_v1_0_s_ifspec, nullptr, FALSE);
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID) {
    if (control == SERVICE_CONTROL_SESSIONCHANGE && eventData != nullptr) {
        const auto* sessionNotification = static_cast<WTSSESSION_NOTIFICATION*>(eventData);

        if (eventType == WTS_SESSION_LOGON
            || eventType == WTS_CONSOLE_CONNECT
            || eventType == WTS_REMOTE_CONNECT) {
            LaunchGuiForSession(sessionNotification->dwSessionId);
        }
    }

    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    LogLine(L"service main entered");
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandler, nullptr);
    if (g_statusHandle == nullptr) {
        return;
    }

    SetServiceState(SERVICE_START_PENDING, NO_ERROR, 3000);

    if (!StartRpcServer()) {
        SetServiceState(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    SetServiceState(SERVICE_RUNNING);
    LogLine(L"service state running");
    LaunchGuiForExistingSessions();

    LogLine(L"RPC server listening");
    RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);

    LogLine(L"service stopping");
    SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    g_rpcStopRequested = true;
    TerminateAllGuiProcesses();
    StopRpcServer();
    SetServiceState(SERVICE_STOPPED);
}

bool InstallService() {
    const std::wstring modulePath = GetModulePath();
    if (modulePath.empty()) {
        return false;
    }

    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (manager == nullptr) {
        return false;
    }

    SC_HANDLE service = CreateServiceW(
        manager,
        kServiceName,
        kServiceDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        QuotePath(modulePath).c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (service == nullptr && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(manager, kServiceName, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS);
        if (service != nullptr) {
            ChangeServiceConfigW(
                service,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                QuotePath(modulePath).c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                kServiceDisplayName
            );
        }
    }

    const bool installed = service != nullptr;

    if (service != nullptr) {
        CloseServiceHandle(service);
    }

    CloseServiceHandle(manager);
    return installed;
}

bool UninstallService() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(manager, kServiceName, DELETE | SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        CloseServiceHandle(manager);
        return false;
    }

    const BOOL deleted = DeleteService(service);

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return deleted == TRUE;
}

bool StartInstalledService() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        CloseServiceHandle(manager);
        return false;
    }

    const BOOL started = StartServiceW(service, 0, nullptr);
    const DWORD error = GetLastError();

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return started == TRUE || error == ERROR_SERVICE_ALREADY_RUNNING;
}

bool StopRpcServerByClient() {
    RPC_WSTR stringBinding = nullptr;
    handle_t binding = nullptr;

    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr,
        &stringBinding
    );

    if (status != RPC_S_OK) {
        return false;
    }

    status = RpcBindingFromStringBindingW(stringBinding, &binding);
    RpcStringFreeW(&stringBinding);

    if (status != RPC_S_OK) {
        return false;
    }

    status = RpcMgmtStopServerListening(binding);
    RpcBindingFree(&binding);
    return status == RPC_S_OK;
}

}

extern "C" void SakuraShieldStopService(handle_t) {
    g_rpcStopRequested = true;
    RpcMgmtStopServerListening(nullptr);
}

int wmain(int argc, wchar_t** argv) {
    if (argc > 1) {
        const std::wstring argument = argv[1] == nullptr ? L"" : argv[1];

        if (ContainsFlag(argument, L"--install") || ContainsFlag(argument, L"/install")) {
            return InstallService() ? 0 : 1;
        }

        if (ContainsFlag(argument, L"--uninstall") || ContainsFlag(argument, L"/uninstall")) {
            return UninstallService() ? 0 : 1;
        }

        if (ContainsFlag(argument, L"--start") || ContainsFlag(argument, L"/start")) {
            return StartInstalledService() ? 0 : 1;
        }

        if (ContainsFlag(argument, L"--stop") || ContainsFlag(argument, L"/stop")) {
            return StopRpcServerByClient() ? 0 : 1;
        }
    }

    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    return StartServiceCtrlDispatcherW(serviceTable) ? 0 : 1;
}
