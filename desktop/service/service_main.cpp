#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <winhttp.h>
#include <rpc.h>

#include "SakuraShieldRpc.h"

#include <algorithm>
#include <filesystem>
#include <cstdint>
#include <array>
#include <atomic>
#include <cstdlib>
#include <cwctype>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kServiceName[] = L"SakuraShieldService";
constexpr wchar_t kServiceDisplayName[] = L"Sakura Shield Service";
constexpr wchar_t kGuiExecutableName[] = L"SakuraShield.exe";
constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
constexpr wchar_t kRpcEndpoint[] = L"SakuraShieldRpcEndpoint";
constexpr wchar_t kDefaultApiBaseUrl[] = L"https://localhost:8443";
constexpr wchar_t kDefaultDeviceMac[] = L"AA-BB-CC-DD-EE-01";

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_serviceStatus{};
std::mutex g_processMutex;
std::map<DWORD, PROCESS_INFORMATION> g_guiProcesses;
std::atomic_bool g_rpcStopRequested = false;
std::atomic_bool g_backgroundStopRequested = false;
HANDLE g_backgroundThread = nullptr;

struct HttpResponse {
    DWORD statusCode = 0;
    std::wstring body;
    std::wstring error;
};

struct AccountState {
    bool authenticated = false;
    std::wstring username;
    std::wstring accessToken;
    std::wstring refreshToken;
    ULONGLONG tokenRefreshAt = 0;
    bool hasLicense = false;
    bool licenseValid = false;
    bool antivirusEnabled = false;
    std::wstring licenseExpiresAt;
    long ticketTtlSeconds = 0;
    ULONGLONG licenseRefreshAt = 0;
    std::wstring activationCode;
    std::wstring message;
};

std::mutex g_accountMutex;
AccountState g_account;

enum class AvObjectType : long {
    Unknown = 0,
    PeFile = 1,
    PowerShellScript = 2
};

struct AvRecord {
    unsigned long long objectSignaturePrefix = 0;
    unsigned long objectSignatureLength = 0;
    std::vector<unsigned char> objectSignature;
    unsigned long long offsetBegin = 0;
    unsigned long long offsetEnd = 0;
    AvObjectType objectType = AvObjectType::Unknown;
    std::vector<unsigned char> avRecordSignature;
    std::wstring threatName;
};

struct AvScanResult {
    bool scanned = false;
    bool malicious = false;
    std::wstring path;
    std::wstring objectType;
    std::wstring threatName;
    unsigned long long offset = 0;
    std::wstring message;
};

std::mutex g_avMutex;
std::map<unsigned long long, std::vector<AvRecord>> g_avDatabase;
std::wstring g_avDatabaseReleaseDate;

std::mutex g_extraMutex;
bool g_scheduledScanEnabled = false;
long g_scheduledScanIntervalSeconds = 300;
ULONGLONG g_nextScheduledScanAt = 0;
std::wstring g_scheduledScanLastReport;
bool g_directoryMonitorEnabled = false;
std::wstring g_monitoredDirectory;
ULONGLONG g_nextMonitorScanAt = 0;
std::wstring g_directoryMonitorLastReport;


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

std::wstring GetEnvironmentString(const wchar_t* name, const wchar_t* fallbackValue) {
    DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size == 0) {
        return fallbackValue;
    }
    std::wstring value(size, L'\0');
    DWORD copied = GetEnvironmentVariableW(name, value.data(), size);
    if (copied == 0) {
        return fallbackValue;
    }
    value.resize(copied);
    return value.empty() ? fallbackValue : value;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        return {};
    }
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

std::wstring JsonEscape(const std::wstring& value) {
    std::wstring result;
    for (wchar_t ch : value) {
        switch (ch) {
        case L'\\': result += L"\\\\"; break;
        case L'\"': result += L"\\\""; break;
        case L'\r': result += L"\\r"; break;
        case L'\n': result += L"\\n"; break;
        case L'\t': result += L"\\t"; break;
        default: result += ch; break;
        }
    }
    return result;
}

std::wstring ExtractJsonString(const std::wstring& json, const std::wstring& key) {
    const std::wstring needle = L"\"" + key + L"\"";
    size_t pos = json.find(needle);
    if (pos == std::wstring::npos) {
        return L"";
    }
    pos = json.find(L':', pos + needle.size());
    if (pos == std::wstring::npos) {
        return L"";
    }
    pos = json.find(L'\"', pos + 1);
    if (pos == std::wstring::npos) {
        return L"";
    }
    std::wstring result;
    bool escaped = false;
    for (size_t index = pos + 1; index < json.size(); ++index) {
        wchar_t ch = json[index];
        if (escaped) {
            switch (ch) {
            case L'n': result += L'\n'; break;
            case L'r': result += L'\r'; break;
            case L't': result += L'\t'; break;
            default: result += ch; break;
            }
            escaped = false;
            continue;
        }
        if (ch == L'\\') {
            escaped = true;
            continue;
        }
        if (ch == L'\"') {
            break;
        }
        result += ch;
    }
    return result;
}

long ExtractJsonLong(const std::wstring& json, const std::wstring& key, long fallbackValue) {
    const std::wstring needle = L"\"" + key + L"\"";
    size_t pos = json.find(needle);
    if (pos == std::wstring::npos) {
        return fallbackValue;
    }
    pos = json.find(L':', pos + needle.size());
    if (pos == std::wstring::npos) {
        return fallbackValue;
    }
    ++pos;
    while (pos < json.size() && iswspace(json[pos])) {
        ++pos;
    }
    wchar_t* end = nullptr;
    long value = std::wcstol(json.c_str() + pos, &end, 10);
    return end == json.c_str() + pos ? fallbackValue : value;
}

bool ExtractJsonBool(const std::wstring& json, const std::wstring& key, bool fallbackValue) {
    const std::wstring needle = L"\"" + key + L"\"";
    size_t pos = json.find(needle);
    if (pos == std::wstring::npos) {
        return fallbackValue;
    }
    pos = json.find(L':', pos + needle.size());
    if (pos == std::wstring::npos) {
        return fallbackValue;
    }
    ++pos;
    while (pos < json.size() && iswspace(json[pos])) {
        ++pos;
    }
    if (json.compare(pos, 4, L"true") == 0) {
        return true;
    }
    if (json.compare(pos, 5, L"false") == 0) {
        return false;
    }
    return fallbackValue;
}

std::wstring ExtractApiError(const std::wstring& body, const std::wstring& fallbackValue) {
    std::wstring message = ExtractJsonString(body, L"message");
    if (!message.empty()) {
        return message;
    }
    message = ExtractJsonString(body, L"error");
    if (!message.empty()) {
        return message;
    }
    return fallbackValue;
}

ULONGLONG GetTickCount64Safe() {
    return GetTickCount64();
}

ULONGLONG ScheduleAfterSeconds(long seconds) {
    long delay = seconds - 30;
    if (delay < 10) {
        delay = seconds > 5 ? seconds - 2 : 5;
    }
    if (delay < 5) {
        delay = 5;
    }
    return GetTickCount64Safe() + static_cast<ULONGLONG>(delay) * 1000ULL;
}

bool TryParseIsoInstant(const std::wstring& value, FILETIME& fileTime) {
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    if (swscanf_s(value.c_str(), L"%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) != 6) {
        return false;
    }
    SYSTEMTIME systemTime{};
    systemTime.wYear = static_cast<WORD>(year);
    systemTime.wMonth = static_cast<WORD>(month);
    systemTime.wDay = static_cast<WORD>(day);
    systemTime.wHour = static_cast<WORD>(hour);
    systemTime.wMinute = static_cast<WORD>(minute);
    systemTime.wSecond = static_cast<WORD>(second);
    return SystemTimeToFileTime(&systemTime, &fileTime) == TRUE;
}

bool IsExpiredUtc(const std::wstring& isoInstant) {
    FILETIME expiration{};
    if (!TryParseIsoInstant(isoInstant, expiration)) {
        return false;
    }
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER expirationValue{};
    expirationValue.LowPart = expiration.dwLowDateTime;
    expirationValue.HighPart = expiration.dwHighDateTime;
    ULARGE_INTEGER nowValue{};
    nowValue.LowPart = now.dwLowDateTime;
    nowValue.HighPart = now.dwHighDateTime;
    return expirationValue.QuadPart <= nowValue.QuadPart;
}

std::wstring GetDeviceName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(buffer, &size) == FALSE || size == 0) {
        return L"Windows device";
    }
    return std::wstring(buffer, size);
}

bool ParseUrl(const std::wstring& url, URL_COMPONENTSW& components, std::wstring& host, std::wstring& path) {
    ZeroMemory(&components, sizeof(components));
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &components) == FALSE) {
        return false;
    }
    host.assign(components.lpszHostName, components.dwHostNameLength);
    path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    if (components.dwExtraInfoLength > 0) {
        path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    if (path.empty()) {
        path = L"/";
    }
    return true;
}

std::wstring BuildUrl(const std::wstring& endpoint) {
    std::wstring base = GetEnvironmentString(L"SAKURA_SHIELD_API_BASE_URL", kDefaultApiBaseUrl);
    while (!base.empty() && base.back() == L'/') {
        base.pop_back();
    }
    if (!endpoint.empty() && endpoint.front() == L'/') {
        return base + endpoint;
    }
    return base + L"/" + endpoint;
}

HttpResponse SendJsonRequest(const std::wstring& method, const std::wstring& endpoint, const std::wstring& jsonBody, const std::wstring& bearerToken = L"") {
    HttpResponse response;
    const std::wstring url = BuildUrl(endpoint);
    URL_COMPONENTSW components{};
    std::wstring host;
    std::wstring path;
    if (!ParseUrl(url, components, host, path)) {
        response.error = L"Некорректный адрес сервера";
        return response;
    }

    HINTERNET session = WinHttpOpen(L"SakuraShield/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) {
        response.error = L"Не удалось создать HTTP-сессию";
        return response;
    }

    HINTERNET connection = WinHttpConnect(session, host.c_str(), components.nPort, 0);
    if (connection == nullptr) {
        response.error = L"Не удалось подключиться к серверу";
        WinHttpCloseHandle(session);
        return response;
    }

    DWORD flags = components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connection, method.c_str(), path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (request == nullptr) {
        response.error = L"Не удалось создать HTTP-запрос";
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    if (flags != 0) {
        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));
    }

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearerToken.empty()) {
        headers += L"Authorization: Bearer " + bearerToken + L"\r\n";
    }

    const std::string body = WideToUtf8(jsonBody);
    BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0
    );

    if (sent == FALSE || WinHttpReceiveResponse(request, nullptr) == FALSE) {
        response.error = L"Сервер недоступен";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    response.statusCode = statusCode;

    std::string responseBytes;
    for (;;) {
        DWORD available = 0;
        if (WinHttpQueryDataAvailable(request, &available) == FALSE || available == 0) {
            break;
        }
        std::string chunk(available, '\0');
        DWORD read = 0;
        if (WinHttpReadData(request, chunk.data(), available, &read) == FALSE || read == 0) {
            break;
        }
        chunk.resize(read);
        responseBytes += chunk;
    }

    response.body = Utf8ToWide(responseBytes);
    if (response.statusCode < 200 || response.statusCode >= 300) {
        response.error = ExtractApiError(response.body, L"Запрос завершился ошибкой");
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return response;
}


unsigned long long ReadPrefixLe(const std::vector<unsigned char>& bytes, size_t offset) {
    unsigned long long value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= static_cast<unsigned long long>(bytes[offset + index]) << (index * 8);
    }
    return value;
}

std::vector<unsigned char> BytesFromAscii(const char* text) {
    std::vector<unsigned char> result;
    while (*text != '\0') {
        result.push_back(static_cast<unsigned char>(*text));
        ++text;
    }
    return result;
}

unsigned long long HashFnv64(const std::vector<unsigned char>& bytes) {
    unsigned long long hash = 14695981039346656037ULL;
    for (unsigned char value : bytes) {
        hash ^= value;
        hash *= 1099511628211ULL;
    }
    return hash;
}

void AppendUInt64(std::vector<unsigned char>& output, unsigned long long value) {
    for (int shift = 0; shift < 64; shift += 8) {
        output.push_back(static_cast<unsigned char>((value >> shift) & 0xFF));
    }
}

void AppendUInt32(std::vector<unsigned char>& output, unsigned long value) {
    for (int shift = 0; shift < 32; shift += 8) {
        output.push_back(static_cast<unsigned char>((value >> shift) & 0xFF));
    }
}

std::vector<unsigned char> HashToBytes(unsigned long long hash) {
    std::vector<unsigned char> result;
    AppendUInt64(result, hash);
    return result;
}

std::vector<unsigned char> BuildRecordSignatureBytes(const AvRecord& record) {
    std::vector<unsigned char> data;
    AppendUInt64(data, record.objectSignaturePrefix);
    AppendUInt32(data, record.objectSignatureLength);
    data.insert(data.end(), record.objectSignature.begin(), record.objectSignature.end());
    AppendUInt64(data, record.offsetBegin);
    AppendUInt64(data, record.offsetEnd);
    AppendUInt64(data, static_cast<unsigned long long>(record.objectType));
    return HashToBytes(HashFnv64(data));
}

AvRecord MakeAvRecord(const std::wstring& threatName, const std::vector<unsigned char>& signature, unsigned long long offsetBegin, unsigned long long offsetEnd, AvObjectType objectType) {
    AvRecord record;
    record.objectSignaturePrefix = ReadPrefixLe(signature, 0);
    record.objectSignatureLength = static_cast<unsigned long>(signature.size());
    record.objectSignature = HashToBytes(HashFnv64(signature));
    record.offsetBegin = offsetBegin;
    record.offsetEnd = offsetEnd;
    record.objectType = objectType;
    record.threatName = threatName;
    record.avRecordSignature = BuildRecordSignatureBytes(record);
    return record;
}

void AddAvRecordLocked(const AvRecord& record) {
    g_avDatabase[record.objectSignaturePrefix].push_back(record);
}

void LoadAvDatabase() {
    std::lock_guard<std::mutex> lock(g_avMutex);
    g_avDatabase.clear();
    AddAvRecordLocked(MakeAvRecord(L"Demo.PE.Sakura", BytesFromAscii("MZSAKURA_PE_DEMO_PAYLOAD"), 0, 64, AvObjectType::PeFile));
    AddAvRecordLocked(MakeAvRecord(L"Demo.PowerShell.Sakura", BytesFromAscii("SakuraShield-Demo-PowerShell-Threat"), 0, 64, AvObjectType::PowerShellScript));
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t buffer[64]{};
    swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u:%02u", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    g_avDatabaseReleaseDate = buffer;
}

long GetAvRecordCount() {
    std::lock_guard<std::mutex> lock(g_avMutex);
    long count = 0;
    for (const auto& pair : g_avDatabase) {
        count += static_cast<long>(pair.second.size());
    }
    return count;
}

std::wstring GetAvReleaseDate() {
    std::lock_guard<std::mutex> lock(g_avMutex);
    return g_avDatabaseReleaseDate;
}

bool IsAntivirusReady() {
    std::lock_guard<std::mutex> lock(g_accountMutex);
    return g_account.authenticated && g_account.antivirusEnabled;
}

std::wstring GetExtensionLower(const std::wstring& path) {
    const size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos) {
        return L"";
    }
    return ToLower(path.substr(dot));
}

AvObjectType DetectObjectType(const std::wstring& path, const std::vector<unsigned char>& bytes) {
    if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
        return AvObjectType::PeFile;
    }
    const std::wstring extension = GetExtensionLower(path);
    if (extension == L".exe" || extension == L".dll" || extension == L".sys") {
        return AvObjectType::PeFile;
    }
    if (extension == L".ps1" || extension == L".psm1") {
        return AvObjectType::PowerShellScript;
    }
    return AvObjectType::Unknown;
}

std::wstring ObjectTypeName(AvObjectType type) {
    switch (type) {
    case AvObjectType::PeFile: return L"PE файл";
    case AvObjectType::PowerShellScript: return L"PowerShell Script";
    default: return L"Неизвестный тип";
    }
}

bool ReadFileBytes(const std::wstring& path, std::vector<unsigned char>& bytes) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER size{};
    if (GetFileSizeEx(file, &size) == FALSE || size.QuadPart < 0 || size.QuadPart > 64LL * 1024LL * 1024LL) {
        CloseHandle(file);
        return false;
    }
    bytes.resize(static_cast<size_t>(size.QuadPart));
    DWORD totalRead = 0;
    if (!bytes.empty()) {
        if (ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &totalRead, nullptr) == FALSE) {
            CloseHandle(file);
            bytes.clear();
            return false;
        }
        bytes.resize(totalRead);
    }
    CloseHandle(file);
    return true;
}

AvScanResult ScanBytes(const std::wstring& path, const std::vector<unsigned char>& bytes) {
    AvScanResult result;
    result.scanned = true;
    result.path = path;
    if (bytes.size() < 8) {
        result.objectType = L"Слишком маленький файл";
        result.message = L"Сигнатура не обнаружена";
        return result;
    }

    AvObjectType objectType = DetectObjectType(path, bytes);
    result.objectType = ObjectTypeName(objectType);

    std::map<unsigned long long, std::vector<AvRecord>> databaseCopy;
    {
        std::lock_guard<std::mutex> lock(g_avMutex);
        databaseCopy = g_avDatabase;
    }

    for (size_t position = 0; position + 8 <= bytes.size(); ++position) {
        const unsigned long long prefix = ReadPrefixLe(bytes, position);
        auto match = databaseCopy.find(prefix);
        if (match == databaseCopy.end()) {
            continue;
        }
        for (const AvRecord& record : match->second) {
            if (record.objectType != objectType) {
                continue;
            }
            if (position < record.offsetBegin || position > record.offsetEnd) {
                continue;
            }
            if (record.objectSignatureLength < 8 || position + record.objectSignatureLength > bytes.size()) {
                continue;
            }
            std::vector<unsigned char> candidate(bytes.begin() + position, bytes.begin() + position + record.objectSignatureLength);
            std::vector<unsigned char> candidateHash = HashToBytes(HashFnv64(candidate));
            if (candidateHash == record.objectSignature) {
                result.malicious = true;
                result.threatName = record.threatName;
                result.offset = static_cast<unsigned long long>(position);
                result.message = L"Объект вредоносный";
                return result;
            }
        }
    }

    result.message = L"Сигнатура не обнаружена";
    return result;
}

AvScanResult ScanFileInternal(const std::wstring& path) {
    std::vector<unsigned char> bytes;
    if (!ReadFileBytes(path, bytes)) {
        AvScanResult result;
        result.path = path;
        result.message = L"Не удалось открыть файл";
        return result;
    }
    return ScanBytes(path, bytes);
}

std::wstring FormatFileScanReport(const AvScanResult& result) {
    std::wstringstream stream;
    stream << L"Файл: " << result.path << L"\r\n";
    stream << L"Тип: " << result.objectType << L"\r\n";
    stream << L"Результат: " << (result.malicious ? L"обнаружена угроза" : L"угроз не найдено") << L"\r\n";
    if (result.malicious) {
        stream << L"Угроза: " << result.threatName << L"\r\n";
        stream << L"Позиция: " << result.offset << L"\r\n";
    }
    stream << L"Сообщение: " << result.message;
    return stream.str();
}

void ScanDirectoryRecursive(const std::wstring& directory, long& scannedCount, long& detectedCount, std::wstringstream& report, int depth) {
    if (depth > 12) {
        return;
    }
    std::wstring mask = directory;
    if (!mask.empty() && mask.back() != L'\\' && mask.back() != L'/') {
        mask += L"\\";
    }
    mask += L"*";

    WIN32_FIND_DATAW data{};
    HANDLE search = FindFirstFileW(mask.c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") {
            continue;
        }
        std::wstring fullPath = directory;
        if (!fullPath.empty() && fullPath.back() != L'\\' && fullPath.back() != L'/') {
            fullPath += L"\\";
        }
        fullPath += name;

        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            ScanDirectoryRecursive(fullPath, scannedCount, detectedCount, report, depth + 1);
            continue;
        }

        ++scannedCount;
        AvScanResult fileResult = ScanFileInternal(fullPath);
        if (fileResult.malicious) {
            ++detectedCount;
            report << L"[DETECTED] " << fileResult.threatName << L" :: " << fullPath << L"\r\n";
        }
    } while (FindNextFileW(search, &data));

    FindClose(search);
}

std::wstring ScanDirectoryInternal(const std::wstring& path, long& scannedCount, long& detectedCount) {
    scannedCount = 0;
    detectedCount = 0;
    std::wstringstream report;
    ScanDirectoryRecursive(path, scannedCount, detectedCount, report, 0);
    if (scannedCount == 0) {
        return L"Файлы для сканирования не найдены";
    }
    if (detectedCount == 0) {
        return L"Просканировано файлов: " + std::to_wstring(scannedCount) + L"\r\nУгроз не найдено";
    }
    std::wstringstream summary;
    summary << L"Просканировано файлов: " << scannedCount << L"\r\n";
    summary << L"Обнаружено угроз: " << detectedCount << L"\r\n";
    summary << report.str();
    return summary.str();
}

bool IsIgnoredFixedDriveDirectory(const std::wstring& path) {
    std::wstring lower = ToLower(path);
    return lower.find(L"\\windows") != std::wstring::npos
        || lower.find(L"\\program files") != std::wstring::npos
        || lower.find(L"\\programdata") != std::wstring::npos
        || lower.find(L"\\appdata") != std::wstring::npos
        || lower.find(L"$recycle.bin") != std::wstring::npos
        || lower.find(L"system volume information") != std::wstring::npos;
}

void ScanDirectoryRecursiveLimited(const std::wstring& directory, long& scannedCount, long& detectedCount, std::wstringstream& report, int depth, long maxFiles) {
    if (depth > 8 || scannedCount >= maxFiles || IsIgnoredFixedDriveDirectory(directory)) {
        return;
    }

    std::wstring mask = directory;
    if (!mask.empty() && mask.back() != L'\\' && mask.back() != L'/') {
        mask += L"\\";
    }
    mask += L"*";

    WIN32_FIND_DATAW data{};
    HANDLE search = FindFirstFileW(mask.c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (scannedCount >= maxFiles) {
            break;
        }
        std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") {
            continue;
        }
        std::wstring fullPath = directory;
        if (!fullPath.empty() && fullPath.back() != L'\\' && fullPath.back() != L'/') {
            fullPath += L"\\";
        }
        fullPath += name;

        if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            continue;
        }
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            ScanDirectoryRecursiveLimited(fullPath, scannedCount, detectedCount, report, depth + 1, maxFiles);
            continue;
        }

        ++scannedCount;
        AvScanResult fileResult = ScanFileInternal(fullPath);
        if (fileResult.malicious) {
            ++detectedCount;
            report << L"[DETECTED] " << fileResult.threatName << L" :: " << fullPath << L"\r\n";
        }
    } while (FindNextFileW(search, &data));

    FindClose(search);
}

std::wstring ScanFixedDrivesInternal(long& scannedCount, long& detectedCount) {
    scannedCount = 0;
    detectedCount = 0;
    std::wstringstream report;
    DWORD mask = GetLogicalDrives();
    const long maxFilesPerDrive = 800;

    for (int index = 0; index < 26; ++index) {
        if ((mask & (1u << index)) == 0) {
            continue;
        }
        wchar_t root[] = { static_cast<wchar_t>(L'A' + index), L':', L'\\', L'\0' };
        if (GetDriveTypeW(root) != DRIVE_FIXED) {
            continue;
        }

        long beforeScanned = scannedCount;
        long beforeDetected = detectedCount;
        report << L"Диск " << root << L" — сканирование запущено\r\n";
        ScanDirectoryRecursiveLimited(root, scannedCount, detectedCount, report, 0, beforeScanned + maxFilesPerDrive);
        report << L"Диск " << root << L": файлов " << (scannedCount - beforeScanned)
               << L", угроз " << (detectedCount - beforeDetected) << L"\r\n";
    }

    if (scannedCount == 0) {
        return L"Несъемные диски не найдены или файлы для сканирования недоступны";
    }

    std::wstringstream summary;
    summary << L"Сканирование всех несъемных дисков завершено\r\n";
    summary << L"Просканировано файлов: " << scannedCount << L"\r\n";
    summary << L"Обнаружено угроз: " << detectedCount << L"\r\n";
    summary << report.str();
    return summary.str();
}

void ClearLicenseLocked() {
    g_account.hasLicense = false;
    g_account.licenseValid = false;
    g_account.antivirusEnabled = false;
    g_account.licenseExpiresAt.clear();
    g_account.ticketTtlSeconds = 0;
    g_account.licenseRefreshAt = 0;
    g_account.activationCode.clear();
}

void ClearAccountLocked(const std::wstring& message) {
    g_account.authenticated = false;
    g_account.username.clear();
    g_account.accessToken.clear();
    g_account.refreshToken.clear();
    g_account.tokenRefreshAt = 0;
    ClearLicenseLocked();
    g_account.message = message;
}

bool ApplyTokenResponse(const std::wstring& body, const std::wstring& username, std::wstring& error) {
    std::wstring access = ExtractJsonString(body, L"accessToken");
    std::wstring refresh = ExtractJsonString(body, L"refreshToken");
    long accessTtl = ExtractJsonLong(body, L"accessExpiresInSeconds", 300);
    long refreshTtl = ExtractJsonLong(body, L"refreshExpiresInSeconds", 3600);
    if (access.empty() || refresh.empty()) {
        error = L"Сервер не вернул JWT-токены";
        return false;
    }
    std::lock_guard<std::mutex> lock(g_accountMutex);
    g_account.authenticated = true;
    g_account.username = username;
    g_account.accessToken = access;
    g_account.refreshToken = refresh;
    g_account.tokenRefreshAt = ScheduleAfterSeconds(accessTtl < refreshTtl ? accessTtl : refreshTtl);
    g_account.message.clear();
    return true;
}

bool ApplyTicketResponse(const std::wstring& body, std::wstring& error) {
    std::wstring endingDate = ExtractJsonString(body, L"endingDate");
    long ttl = ExtractJsonLong(body, L"ticketTtlSeconds", 300);
    bool blocked = ExtractJsonBool(body, L"blocked", false);
    std::wstring signature = ExtractJsonString(body, L"signature");
    if (endingDate.empty() || signature.empty()) {
        error = L"Сервер не вернул лицензионный тикет";
        return false;
    }
    bool expired = IsExpiredUtc(endingDate);
    std::lock_guard<std::mutex> lock(g_accountMutex);
    g_account.hasLicense = !blocked && !expired;
    g_account.licenseValid = !blocked && !expired;
    g_account.antivirusEnabled = g_account.authenticated && g_account.licenseValid;
    g_account.licenseExpiresAt = endingDate;
    g_account.ticketTtlSeconds = ttl;
    g_account.licenseRefreshAt = ScheduleAfterSeconds(ttl);
    g_account.message = g_account.licenseValid ? L"" : L"Лицензия истекла или заблокирована";
    if (g_account.licenseValid) {
        LoadAvDatabase();
    }
    return true;
}

bool RefreshTokens() {
    std::wstring refreshToken;
    std::wstring username;
    {
        std::lock_guard<std::mutex> lock(g_accountMutex);
        if (!g_account.authenticated || g_account.refreshToken.empty()) {
            return false;
        }
        refreshToken = g_account.refreshToken;
        username = g_account.username;
    }

    std::wstring body = L"{\"refreshToken\":\"" + JsonEscape(refreshToken) + L"\"}";
    HttpResponse response = SendJsonRequest(L"POST", L"/api/auth/refresh", body);
    if (response.statusCode >= 200 && response.statusCode < 300) {
        std::wstring error;
        return ApplyTokenResponse(response.body, username, error);
    }

    std::lock_guard<std::mutex> lock(g_accountMutex);
    ClearAccountLocked(L"Сессия истекла, требуется повторный вход");
    return false;
}

bool RequestLicenseCheck() {
    std::wstring accessToken;
    std::wstring activationCode;
    {
        std::lock_guard<std::mutex> lock(g_accountMutex);
        if (!g_account.authenticated || g_account.accessToken.empty()) {
            return false;
        }
        accessToken = g_account.accessToken;
        activationCode = g_account.activationCode;
    }

    std::wstring productId = GetEnvironmentString(L"SAKURA_SHIELD_PRODUCT_ID", L"");
    HttpResponse response;
    if (!productId.empty()) {
        std::wstring body = L"{\"deviceMac\":\"" + std::wstring(kDefaultDeviceMac) + L"\",\"productId\":\"" + JsonEscape(productId) + L"\"}";
        response = SendJsonRequest(L"POST", L"/api/licenses/check", body, accessToken);
    } else if (!activationCode.empty()) {
        std::wstring body = L"{\"activationKey\":\"" + JsonEscape(activationCode) + L"\",\"deviceMac\":\"" + std::wstring(kDefaultDeviceMac) + L"\",\"deviceName\":\"" + JsonEscape(GetDeviceName()) + L"\"}";
        response = SendJsonRequest(L"POST", L"/api/licenses/activate", body, accessToken);
    } else {
        std::lock_guard<std::mutex> lock(g_accountMutex);
        ClearLicenseLocked();
        g_account.message = L"Лицензия не активирована";
        return false;
    }

    if (response.statusCode >= 200 && response.statusCode < 300) {
        std::wstring error;
        return ApplyTicketResponse(response.body, error);
    }

    std::lock_guard<std::mutex> lock(g_accountMutex);
    ClearLicenseLocked();
    g_account.message = ExtractApiError(response.body, response.error.empty() ? L"Лицензия отсутствует" : response.error);
    return false;
}

DWORD WINAPI BackgroundWorker(LPVOID) {
    while (!g_backgroundStopRequested.load()) {
        ULONGLONG now = GetTickCount64Safe();
        bool needTokenRefresh = false;
        bool needLicenseRefresh = false;
        bool needScheduledScan = false;
        bool needMonitorScan = false;
        std::wstring monitorPath;
        {
            std::lock_guard<std::mutex> lock(g_accountMutex);
            needTokenRefresh = g_account.authenticated && g_account.tokenRefreshAt != 0 && now >= g_account.tokenRefreshAt;
            needLicenseRefresh = g_account.authenticated && g_account.hasLicense && g_account.licenseRefreshAt != 0 && now >= g_account.licenseRefreshAt;
        }
        {
            std::lock_guard<std::mutex> lock(g_extraMutex);
            needScheduledScan = g_scheduledScanEnabled && g_nextScheduledScanAt != 0 && now >= g_nextScheduledScanAt;
            needMonitorScan = g_directoryMonitorEnabled && g_nextMonitorScanAt != 0 && now >= g_nextMonitorScanAt;
            monitorPath = g_monitoredDirectory;
        }
        if (needTokenRefresh) {
            RefreshTokens();
        }
        if (needLicenseRefresh) {
            RequestLicenseCheck();
        }
        if (needScheduledScan && IsAntivirusReady()) {
            long scanned = 0;
            long detected = 0;
            std::wstring report = ScanFixedDrivesInternal(scanned, detected);
            std::lock_guard<std::mutex> lock(g_extraMutex);
            g_scheduledScanLastReport = report;
            g_nextScheduledScanAt = GetTickCount64Safe() + static_cast<ULONGLONG>(g_scheduledScanIntervalSeconds) * 1000ULL;
        }
        if (needMonitorScan && IsAntivirusReady() && !monitorPath.empty()) {
            long scanned = 0;
            long detected = 0;
            std::wstring report = ScanDirectoryInternal(monitorPath, scanned, detected);
            std::lock_guard<std::mutex> lock(g_extraMutex);
            g_directoryMonitorLastReport = L"Мониторинг: " + monitorPath + L"\r\n" + report;
            g_nextMonitorScanAt = GetTickCount64Safe() + 3000ULL;
        }
        Sleep(1000);
    }
    return 0;
}

void StartBackgroundWorker() {
    g_backgroundStopRequested = false;
    if (g_backgroundThread == nullptr) {
        g_backgroundThread = CreateThread(nullptr, 0, BackgroundWorker, nullptr, 0, nullptr);
    }
}

void StopBackgroundWorker() {
    g_backgroundStopRequested = true;
    if (g_backgroundThread != nullptr) {
        WaitForSingleObject(g_backgroundThread, 5000);
        CloseHandle(g_backgroundThread);
        g_backgroundThread = nullptr;
    }
}

wchar_t* RpcCopyString(const std::wstring& value) {
    size_t bytes = (value.size() + 1) * sizeof(wchar_t);
    auto* output = static_cast<wchar_t*>(midl_user_allocate(bytes));
    if (output == nullptr) {
        return nullptr;
    }
    wcscpy_s(output, value.size() + 1, value.c_str());
    return output;
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
    if (DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &duplicatedToken) == TRUE) {
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
    RPC_STATUS status = RpcServerUseProtseqEpW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)), RPC_C_PROTSEQ_MAX_REQS_DEFAULT, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)), nullptr);
    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
        return false;
    }
    status = RpcServerRegisterIf2(SakuraShieldRpc_v1_0_s_ifspec, nullptr, nullptr, RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH, RPC_C_LISTEN_MAX_CALLS_DEFAULT, static_cast<unsigned int>(-1), nullptr);
    return status == RPC_S_OK || status == RPC_S_TYPE_ALREADY_REGISTERED;
}

void StopRpcServer() {
    RpcServerUnregisterIf(SakuraShieldRpc_v1_0_s_ifspec, nullptr, FALSE);
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID) {
    if (control == SERVICE_CONTROL_SESSIONCHANGE && eventData != nullptr) {
        const auto* sessionNotification = static_cast<WTSSESSION_NOTIFICATION*>(eventData);
        if (eventType == WTS_SESSION_LOGON || eventType == WTS_CONSOLE_CONNECT || eventType == WTS_REMOTE_CONNECT) {
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

    LoadAvDatabase();
    StartBackgroundWorker();
    SetServiceState(SERVICE_RUNNING);
    LogLine(L"service state running");
    LaunchGuiForExistingSessions();

    LogLine(L"RPC server listening");
    RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);

    LogLine(L"service stopping");
    SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    g_rpcStopRequested = true;
    StopBackgroundWorker();
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
    SC_HANDLE service = CreateServiceW(manager, kServiceName, kServiceDisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, QuotePath(modulePath).c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (service == nullptr && GetLastError() == ERROR_SERVICE_EXISTS) {
        service = OpenServiceW(manager, kServiceName, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS);
        if (service != nullptr) {
            ChangeServiceConfigW(service, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, QuotePath(modulePath).c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, kServiceDisplayName);
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
    RPC_STATUS status = RpcStringBindingComposeW(nullptr, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)), nullptr, reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)), nullptr, &stringBinding);
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

extern "C" long SakuraShieldGetState(handle_t, long* authenticated, wchar_t** username, long* antivirusEnabled, long* hasLicense, long* licenseValid, wchar_t** licenseExpiresAt, wchar_t** message) {
    if (authenticated == nullptr || username == nullptr || antivirusEnabled == nullptr || hasLicense == nullptr || licenseValid == nullptr || licenseExpiresAt == nullptr || message == nullptr) {
        return 87;
    }
    std::lock_guard<std::mutex> lock(g_accountMutex);
    *authenticated = g_account.authenticated ? 1 : 0;
    *antivirusEnabled = g_account.antivirusEnabled ? 1 : 0;
    *hasLicense = g_account.hasLicense ? 1 : 0;
    *licenseValid = g_account.licenseValid ? 1 : 0;
    *username = RpcCopyString(g_account.username);
    *licenseExpiresAt = RpcCopyString(g_account.licenseExpiresAt);
    *message = RpcCopyString(g_account.message);
    return 0;
}

extern "C" long SakuraShieldLogin(handle_t, wchar_t* username, wchar_t* password, wchar_t** message) {
    if (message == nullptr) {
        return 87;
    }
    *message = RpcCopyString(L"");
    std::wstring login = username == nullptr ? L"" : username;
    std::wstring secret = password == nullptr ? L"" : password;
    if (login.empty() || secret.empty()) {
        *message = RpcCopyString(L"Введите логин и пароль");
        return 1;
    }

    std::wstring body = L"{\"username\":\"" + JsonEscape(login) + L"\",\"password\":\"" + JsonEscape(secret) + L"\"}";
    HttpResponse response = SendJsonRequest(L"POST", L"/api/auth/login", body);
    if (response.statusCode >= 200 && response.statusCode < 300) {
        std::wstring error;
        if (ApplyTokenResponse(response.body, login, error)) {
            RequestLicenseCheck();
            return 0;
        }
        *message = RpcCopyString(error);
        return 2;
    }

    std::wstring error = ExtractApiError(response.body, response.error.empty() ? L"Неуспешная аутентификация" : response.error);
    {
        std::lock_guard<std::mutex> lock(g_accountMutex);
        ClearAccountLocked(error);
    }
    *message = RpcCopyString(error);
    return 3;
}

extern "C" long SakuraShieldLogout(handle_t) {
    std::lock_guard<std::mutex> lock(g_accountMutex);
    ClearAccountLocked(L"Выполнен выход из учетной записи");
    return 0;
}

extern "C" long SakuraShieldActivate(handle_t, wchar_t* activationCode, wchar_t** message) {
    if (message == nullptr) {
        return 87;
    }
    *message = RpcCopyString(L"");
    std::wstring code = activationCode == nullptr ? L"" : activationCode;
    if (code.empty()) {
        *message = RpcCopyString(L"Введите код активации");
        return 1;
    }

    std::wstring accessToken;
    {
        std::lock_guard<std::mutex> lock(g_accountMutex);
        if (!g_account.authenticated || g_account.accessToken.empty()) {
            *message = RpcCopyString(L"Сначала выполните вход");
            return 2;
        }
        accessToken = g_account.accessToken;
    }

    std::wstring body = L"{\"activationKey\":\"" + JsonEscape(code) + L"\",\"deviceMac\":\"" + std::wstring(kDefaultDeviceMac) + L"\",\"deviceName\":\"" + JsonEscape(GetDeviceName()) + L"\"}";
    HttpResponse response = SendJsonRequest(L"POST", L"/api/licenses/activate", body, accessToken);
    if (response.statusCode >= 200 && response.statusCode < 300) {
        std::wstring error;
        if (ApplyTicketResponse(response.body, error)) {
            std::lock_guard<std::mutex> lock(g_accountMutex);
            g_account.activationCode = code;
            return 0;
        }
        *message = RpcCopyString(error);
        return 3;
    }

    std::wstring error = ExtractApiError(response.body, response.error.empty() ? L"Неуспешная активация" : response.error);
    {
        std::lock_guard<std::mutex> lock(g_accountMutex);
        ClearLicenseLocked();
        g_account.message = error;
    }
    *message = RpcCopyString(error);
    return 4;
}


extern "C" long SakuraShieldGetAvDatabaseInfo(handle_t, wchar_t** releaseDate, long* recordCount, wchar_t** message) {
    if (releaseDate == nullptr || recordCount == nullptr || message == nullptr) {
        return 87;
    }
    *releaseDate = RpcCopyString(GetAvReleaseDate());
    *recordCount = GetAvRecordCount();
    *message = RpcCopyString(L"Антивирусные базы загружены в оперативную память");
    return 0;
}

extern "C" long SakuraShieldScanFile(handle_t, wchar_t* path, long* malicious, wchar_t** report) {
    if (path == nullptr || malicious == nullptr || report == nullptr) {
        return 87;
    }
    if (!IsAntivirusReady()) {
        *malicious = 0;
        *report = RpcCopyString(L"Нет активной лицензии. Антивирусная функциональность заблокирована.");
        return 5;
    }
    std::wstring filePath = path;
    AvScanResult result = ScanFileInternal(filePath);
    *malicious = result.malicious ? 1 : 0;
    *report = RpcCopyString(FormatFileScanReport(result));
    return result.scanned ? 0 : 2;
}

extern "C" long SakuraShieldScanDirectory(handle_t, wchar_t* path, long* scannedCount, long* detectedCount, wchar_t** report) {
    if (path == nullptr || scannedCount == nullptr || detectedCount == nullptr || report == nullptr) {
        return 87;
    }
    if (!IsAntivirusReady()) {
        *scannedCount = 0;
        *detectedCount = 0;
        *report = RpcCopyString(L"Нет активной лицензии. Антивирусная функциональность заблокирована.");
        return 5;
    }
    long scanned = 0;
    long detected = 0;
    std::wstring text = ScanDirectoryInternal(path, scanned, detected);
    *scannedCount = scanned;
    *detectedCount = detected;
    *report = RpcCopyString(text);
    return 0;
}

extern "C" long SakuraShieldScanFixedDrives(handle_t, long* scannedCount, long* detectedCount, wchar_t** report) {
    if (scannedCount == nullptr || detectedCount == nullptr || report == nullptr) {
        return 87;
    }
    if (!IsAntivirusReady()) {
        *scannedCount = 0;
        *detectedCount = 0;
        *report = RpcCopyString(L"Нет активной лицензии. Антивирусная функциональность заблокирована.");
        return 5;
    }
    long scanned = 0;
    long detected = 0;
    std::wstring text = ScanFixedDrivesInternal(scanned, detected);
    *scannedCount = scanned;
    *detectedCount = detected;
    *report = RpcCopyString(text);
    return 0;
}

extern "C" long SakuraShieldSetScheduledScan(handle_t, long enabled, long intervalSeconds, wchar_t** message) {
    if (message == nullptr) {
        return 87;
    }
    if (!IsAntivirusReady()) {
        *message = RpcCopyString(L"Нет активной лицензии. Расписание сканирования заблокировано.");
        return 5;
    }
    if (intervalSeconds < 60) {
        intervalSeconds = 60;
    }
    {
        std::lock_guard<std::mutex> lock(g_extraMutex);
        g_scheduledScanEnabled = enabled != 0;
        g_scheduledScanIntervalSeconds = intervalSeconds;
        g_nextScheduledScanAt = g_scheduledScanEnabled ? GetTickCount64Safe() + 5000ULL : 0;
        if (!g_scheduledScanEnabled) {
            g_scheduledScanLastReport = L"Сканирование по расписанию отключено";
        }
    }
    *message = RpcCopyString(enabled != 0 ? L"Сканирование по расписанию включено" : L"Сканирование по расписанию отключено");
    return 0;
}

extern "C" long SakuraShieldGetScheduledScanInfo(handle_t, long* enabled, long* intervalSeconds, wchar_t** lastReport, wchar_t** message) {
    if (enabled == nullptr || intervalSeconds == nullptr || lastReport == nullptr || message == nullptr) {
        return 87;
    }
    std::lock_guard<std::mutex> lock(g_extraMutex);
    *enabled = g_scheduledScanEnabled ? 1 : 0;
    *intervalSeconds = g_scheduledScanIntervalSeconds;
    *lastReport = RpcCopyString(g_scheduledScanLastReport);
    *message = RpcCopyString(g_scheduledScanEnabled ? L"Расписание активно" : L"Расписание отключено");
    return 0;
}

extern "C" long SakuraShieldStartDirectoryMonitor(handle_t, wchar_t* path, wchar_t** message) {
    if (path == nullptr || message == nullptr) {
        return 87;
    }
    if (!IsAntivirusReady()) {
        *message = RpcCopyString(L"Нет активной лицензии. Мониторинг директорий заблокирован.");
        return 5;
    }
    {
        std::lock_guard<std::mutex> lock(g_extraMutex);
        g_directoryMonitorEnabled = true;
        g_monitoredDirectory = path;
        g_nextMonitorScanAt = GetTickCount64Safe() + 1000ULL;
        g_directoryMonitorLastReport = L"Мониторинг включен: " + g_monitoredDirectory;
    }
    *message = RpcCopyString(L"Мониторинг директории включен");
    return 0;
}

extern "C" long SakuraShieldStopDirectoryMonitor(handle_t, wchar_t** message) {
    if (message == nullptr) {
        return 87;
    }
    {
        std::lock_guard<std::mutex> lock(g_extraMutex);
        g_directoryMonitorEnabled = false;
        g_nextMonitorScanAt = 0;
        g_directoryMonitorLastReport = L"Мониторинг директории отключен";
    }
    *message = RpcCopyString(L"Мониторинг директории отключен");
    return 0;
}

extern "C" long SakuraShieldGetDirectoryMonitorInfo(handle_t, long* enabled, wchar_t** monitoredPath, wchar_t** lastReport, wchar_t** message) {
    if (enabled == nullptr || monitoredPath == nullptr || lastReport == nullptr || message == nullptr) {
        return 87;
    }
    std::lock_guard<std::mutex> lock(g_extraMutex);
    *enabled = g_directoryMonitorEnabled ? 1 : 0;
    *monitoredPath = RpcCopyString(g_monitoredDirectory);
    *lastReport = RpcCopyString(g_directoryMonitorLastReport);
    *message = RpcCopyString(g_directoryMonitorEnabled ? L"Мониторинг активен" : L"Мониторинг отключен");
    return 0;
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

    if (StartServiceCtrlDispatcherW(serviceTable) == FALSE) {
        return 1;
    }

    return 0;
}
