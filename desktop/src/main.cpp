#include <windows.h>
#include <shellapi.h>
#include <lmcons.h>

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <string>

namespace {

constexpr wchar_t kWindowClassName[] = L"SecureServerTrayWindowClass";
constexpr wchar_t kWindowTitle[] = L"Secure Server Base";
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

std::wstring BuildMutexName() {
    wchar_t userName[UNLEN + 1]{};
    DWORD userNameLength = UNLEN + 1;

    if (GetUserNameW(userName, &userNameLength) == FALSE) {
        return L"Local\\SecureServerBaseTray.SingleInstance";
    }

    std::wstring safeUserName = userName;
    for (wchar_t& ch : safeUserName) {
        if (ch == L'\\') {
            ch = L'_';
        }
    }

    return L"Local\\SecureServerBaseTray.SingleInstance." + safeUserName;
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

void AddTrayIcon(HWND window) {
    ZeroMemory(&g_trayIconData, sizeof(g_trayIconData));
    g_trayIconData.cbSize = sizeof(g_trayIconData);
    g_trayIconData.hWnd = window;
    g_trayIconData.uID = kTrayIconId;
    g_trayIconData.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_trayIconData.uCallbackMessage = kTrayCallbackMessage;
    g_trayIconData.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcscpy_s(g_trayIconData.szTip, L"Secure Server Base");

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
    RemoveTrayIcon();
    DestroyWindow(window);
}

void PaintMainWindow(HWND window) {
    PAINTSTRUCT paintStruct{};
    HDC deviceContext = BeginPaint(window, &paintStruct);

    RECT clientRect{};
    GetClientRect(window, &clientRect);

    const wchar_t text[] =
        L"Secure Server Base GUI\n\n"
        L"Приложение работает в трее.\n"
        L"Закрытие окна скрывает его, но не завершает процесс.\n\n"
        L"Для выхода используйте Файл -> Выход или меню иконки в трее.";

    DrawTextW(
        deviceContext,
        text,
        -1,
        &clientRect,
        DT_CENTER | DT_VCENTER | DT_WORDBREAK
    );

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

    case WM_PAINT:
        PaintMainWindow(window);
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
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
        720,
        420,
        nullptr,
        nullptr,
        g_instance,
        nullptr
    );
}

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR commandLine, int) {
    g_instance = instance;

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
