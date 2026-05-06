#include <windows.h>
#include <shellapi.h>
#include <lmcons.h>
#include <tlhelp32.h>
#include <rpc.h>

#include "SakuraShieldRpc.h"

#include <algorithm>
#include <cwchar>
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

std::wstring GetProcessImagePath(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (process == nullptr) {
        return L"";
    }

    std::wstring path(MAX_PATH, L'\0');
    DWORD size = static_cast<DWORD>(path.size());

    if (QueryFullProcessImageNameW(process, 0, path.data(), &size) == FALSE) {
        CloseHandle(process);
        return L"";
    }

    path.resize(size);
    CloseHandle(process);
    return path;
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

    if (QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytesNeeded) == FALSE) {
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

    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
    if (service == nullptr) {
        CloseServiceHandle(manager);
        return true;
    }

    const DWORD state = QueryServiceState(service);
    bool shouldExit = true;

    if (state == SERVICE_RUNNING) {
        shouldExit = false;
    } else if (state == SERVICE_STOPPED) {
        StartServiceW(service, 0, nullptr);
        WaitForServiceRunning(service, 30000);
    } else if (state == SERVICE_START_PENDING) {
        WaitForServiceRunning(service, 30000);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return shouldExit;
}

bool RequestServiceStop() {
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

    status = RPC_S_OK;

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

std::wstring BuildMutexName() {
    wchar_t userName[UNLEN + 1]{};
    DWORD userNameLength = UNLEN + 1;

    if (GetUserNameW(userName, &userNameLength) == FALSE) {
        return L"Local\\SakuraShield.SingleInstance";
    }

    std::wstring safeUserName = userName;
    for (wchar_t& ch : safeUserName) {
        if (ch == L'\\') {
            ch = L'_';
        }
    }

    return L"Local\\SakuraShield.SingleInstance." + safeUserName;
}

bool CreateSingleInstanceGuard() {
    const std::wstring mutexName = BuildMutexName();
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

void ShowMainWindow(HWND window) {
    if (IsIconic(window)) {
        ShowWindow(window, SW_RESTORE);
    } else {
        ShowWindow(window, SW_SHOW);
    }

    SetForegroundWindow(window);
}

HICON CreateSakuraIcon() {
    constexpr int size = 32;
    HDC screen = GetDC(nullptr);
    HDC memory = CreateCompatibleDC(screen);
    HBITMAP colorBitmap = CreateCompatibleBitmap(screen, size, size);
    HGDIOBJ oldBitmap = SelectObject(memory, colorBitmap);

    HBRUSH background = CreateSolidBrush(RGB(255, 221, 239));
    RECT iconRect{ 0, 0, size, size };
    FillRect(memory, &iconRect, background);
    DeleteObject(background);

    HPEN borderPen = CreatePen(PS_SOLID, 2, RGB(211, 80, 151));
    HBRUSH shieldBrush = CreateSolidBrush(RGB(255, 136, 196));
    HGDIOBJ oldPen = SelectObject(memory, borderPen);
    HGDIOBJ oldBrush = SelectObject(memory, shieldBrush);
    RoundRect(memory, 5, 4, 27, 28, 9, 9);
    SelectObject(memory, oldBrush);
    SelectObject(memory, oldPen);
    DeleteObject(shieldBrush);
    DeleteObject(borderPen);

    HFONT iconFont = CreateFontW(
        22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI Symbol"
    );
    HGDIOBJ oldFont = SelectObject(memory, iconFont);
    SetBkMode(memory, TRANSPARENT);
    SetTextColor(memory, RGB(255, 255, 255));
    RECT heartRect{ 0, 3, size, 30 };
    DrawTextW(memory, L"♡", -1, &heartRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(memory, oldFont);
    DeleteObject(iconFont);

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

    g_titleFont = CreateFontW(
        34, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI"
    );

    g_statusFont = CreateFontW(
        20, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Yu Gothic UI"
    );

    g_smallFont = CreateFontW(
        17, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI"
    );

    g_trayIcon = CreateSakuraIcon();
    if (g_trayIcon == nullptr) {
        g_trayIcon = LoadIconW(nullptr, IDI_APPLICATION);
    }
}

void ReleaseUiResources() {
    if (g_titleFont != nullptr) {
        DeleteObject(g_titleFont);
        g_titleFont = nullptr;
    }

    if (g_statusFont != nullptr) {
        DeleteObject(g_statusFont);
        g_statusFont = nullptr;
    }

    if (g_smallFont != nullptr) {
        DeleteObject(g_smallFont);
        g_smallFont = nullptr;
    }

    if (g_backgroundBrush != nullptr) {
        DeleteObject(g_backgroundBrush);
        g_backgroundBrush = nullptr;
    }

    if (g_panelBrush != nullptr) {
        DeleteObject(g_panelBrush);
        g_panelBrush = nullptr;
    }

    if (g_trayIcon != nullptr) {
        DestroyIcon(g_trayIcon);
        g_trayIcon = nullptr;
    }
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
    TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_BOTTOMALIGN,
        cursorPosition.x,
        cursorPosition.y,
        0,
        window,
        nullptr
    );

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

void DrawRoundedPanel(HDC deviceContext, const RECT& rect) {
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(237, 164, 210));
    HGDIOBJ oldPen = SelectObject(deviceContext, pen);
    HGDIOBJ oldBrush = SelectObject(deviceContext, g_panelBrush);
    RoundRect(deviceContext, rect.left, rect.top, rect.right, rect.bottom, 26, 26);
    SelectObject(deviceContext, oldBrush);
    SelectObject(deviceContext, oldPen);
    DeleteObject(pen);
}

void PaintMainWindow(HWND window) {
    PAINTSTRUCT paintStruct{};
    HDC deviceContext = BeginPaint(window, &paintStruct);

    RECT clientRect{};
    GetClientRect(window, &clientRect);

    FillRect(deviceContext, &clientRect, g_backgroundBrush);
    SetBkMode(deviceContext, TRANSPARENT);

    SelectObject(deviceContext, g_titleFont);
    SetTextColor(deviceContext, RGB(128, 42, 98));
    RECT titleRect{ 0, 28, clientRect.right, 80 };
    DrawTextW(deviceContext, L"Sakura Shield ♡", -1, &titleRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(deviceContext, g_smallFont);
    SetTextColor(deviceContext, RGB(154, 77, 126));
    RECT subtitleRect{ 0, 73, clientRect.right, 103 };
    DrawTextW(deviceContext, L"pastel service guard / さくらモード", -1, &subtitleRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    const int panelWidth = 560;
    const int panelHeight = 255;
    const int left = (clientRect.right - panelWidth) / 2;
    RECT panelRect{ left, 122, left + panelWidth, 122 + panelHeight };
    DrawRoundedPanel(deviceContext, panelRect);

    SelectObject(deviceContext, g_statusFont);
    SetTextColor(deviceContext, RGB(91, 48, 83));
    RECT statusRect{ panelRect.left + 44, panelRect.top + 28, panelRect.right - 44, panelRect.bottom - 54 };

    const wchar_t statusText[] =
        L"状態 / STATUS\r\n\r\n"
        L"[ OK ] service link ..... active ♡\r\n"
        L"[ OK ] rpc channel ...... online\r\n"
        L"[ OK ] background ....... running\r\n"
        L"[ .. ] scan mood ........ (｡•̀ᴗ-)✧";

    DrawTextW(deviceContext, statusText, -1, &statusRect, DT_CENTER | DT_WORDBREAK);

    SelectObject(deviceContext, g_smallFont);
    SetTextColor(deviceContext, RGB(143, 73, 119));
    RECT hintRect{ panelRect.left + 38, panelRect.bottom - 48, panelRect.right - 38, panelRect.bottom - 14 };
    DrawTextW(deviceContext, L"Закрытие окна прячет приложение в трей. Выход останавливает службу.", -1, &hintRect, DT_CENTER | DT_WORDBREAK);

    EndPaint(window, &paintStruct);
}

void CreateMainMenu(HWND window) {
    HMENU mainMenu = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();

    AppendMenuW(fileMenu, MF_STRING, kCommandFileExit, L"Выход");
    AppendMenuW(mainMenu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"Файл");

    SetMenu(window, mainMenu);
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
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case kCommandTrayOpen:
            ShowMainWindow(window);
            return 0;

        case kCommandTrayExit:
        case kCommandFileExit:
            ExitApplication(window);
            return 0;

        default:
            break;
        }
        break;

    case kTrayCallbackMessage:
        switch (LOWORD(lParam)) {
        case WM_LBUTTONUP:
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
    return CreateWindowExW(
        0,
        kWindowClassName,
        kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        860,
        520,
        nullptr,
        nullptr,
        g_instance,
        nullptr
    );
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
