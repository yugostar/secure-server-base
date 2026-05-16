#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <rpc.h>

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

struct ClientState {
    bool rpcOnline = false;
    bool authenticated = false;
    bool antivirusEnabled = false;
    bool hasLicense = false;
    bool licenseValid = false;
    std::wstring username;
    std::wstring licenseExpiresAt;
    std::wstring message;
};

ClientState g_state;
std::wstring g_localMessage;

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

bool RequestServiceStop() {
    handle_t binding = nullptr;
    if (!CreateRpcBinding(&binding)) {
        return false;
    }
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
    RPC_STATUS rpcStatus = RPC_S_OK;

    RpcTryExcept
    {
        result = SakuraShieldGetState(binding, &authenticated, &username, &antivirusEnabled, &hasLicense, &licenseValid, &expires, &message);
    }
    RpcExcept(1)
    {
        rpcStatus = RpcExceptionCode();
    }
    RpcEndExcept

    RpcBindingFree(&binding);

    if (rpcStatus != RPC_S_OK || result != 0) {
        FreeRpcString(username);
        FreeRpcString(expires);
        FreeRpcString(message);
        g_state = {};
        g_state.message = L"Не удалось получить состояние службы";
        return false;
    }

    g_state.rpcOnline = true;
    g_state.authenticated = authenticated != 0;
    g_state.antivirusEnabled = antivirusEnabled != 0;
    g_state.hasLicense = hasLicense != 0;
    g_state.licenseValid = licenseValid != 0;
    g_state.username = username == nullptr ? L"" : username;
    g_state.licenseExpiresAt = expires == nullptr ? L"" : expires;
    g_state.message = message == nullptr ? L"" : message;

    FreeRpcString(username);
    FreeRpcString(expires);
    FreeRpcString(message);
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
    RPC_STATUS rpcStatus = RPC_S_OK;
    std::wstring mutableUsername = username;
    std::wstring mutablePassword = password;
    RpcTryExcept
    {
        result = SakuraShieldLogin(binding, mutableUsername.data(), mutablePassword.data(), &message);
    }
    RpcExcept(1)
    {
        rpcStatus = RpcExceptionCode();
    }
    RpcEndExcept
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
    RPC_STATUS rpcStatus = RPC_S_OK;
    RpcTryExcept
    {
        result = SakuraShieldLogout(binding);
    }
    RpcExcept(1)
    {
        rpcStatus = RpcExceptionCode();
    }
    RpcEndExcept
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
    RPC_STATUS rpcStatus = RPC_S_OK;
    std::wstring mutableCode = activationCode;
    RpcTryExcept
    {
        result = SakuraShieldActivate(binding, mutableCode.data(), &message);
    }
    RpcExcept(1)
    {
        rpcStatus = RpcExceptionCode();
    }
    RpcEndExcept
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
}

void PositionControls() {
    RECT client{};
    GetClientRect(g_mainWindow, &client);
    const int panelWidth = 560;
    const int left = (client.right - panelWidth) / 2;
    MoveWindow(g_usernameEdit, left + 150, 205, 260, 28, TRUE);
    MoveWindow(g_passwordEdit, left + 150, 245, 260, 28, TRUE);
    MoveWindow(g_loginButton, left + 205, 288, 150, 34, TRUE);
    MoveWindow(g_activationEdit, left + 120, 235, 320, 28, TRUE);
    MoveWindow(g_activateButton, left + 195, 278, 170, 34, TRUE);
    MoveWindow(g_logoutButton, left + 170, 307, 220, 34, TRUE);
    MoveWindow(g_refreshButton, left + 185, 260, 190, 34, TRUE);
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
    DrawCenteredText(deviceContext, L"account guard / activation mode", RECT{ 0, 72, clientRect.right, 102 }, g_smallFont, RGB(154, 77, 126), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    const int panelWidth = 560;
    const int panelHeight = 290;
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
        DrawCenteredText(deviceContext, L"Антивирус разблокирован", RECT{ panelRect.left + 30, panelRect.top + 28, panelRect.right - 30, panelRect.top + 65 }, g_statusFont, RGB(91, 48, 83));
        std::wstring text = L"Пользователь: " + g_state.username + L"\r\nЛицензия активна до:\r\n" + g_state.licenseExpiresAt + L"\r\n\r\n[ OK ] account ........ authenticated\r\n[ OK ] license ........ active\r\n[ OK ] guard mode ..... enabled ♡";
        DrawCenteredText(deviceContext, text, RECT{ panelRect.left + 48, 176, panelRect.right - 48, 330 }, g_smallFont, RGB(91, 48, 83), DT_CENTER | DT_WORDBREAK);
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
    return CreateWindowExW(0, kWindowClassName, kWindowTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 860, 560, nullptr, nullptr, g_instance, nullptr);
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
