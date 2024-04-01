#include <windows.h>
#include <winioctl.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <Windows.h>
#include "pugixml.hpp"

#define IOCTL_UPDATE_RULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UPDATE_RULES_COUNT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFICATOR_ON CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFICATOR_OFF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define KEY_REG 1
#define APPLICATION 2

using namespace std;

string xmlFilePath = "C:\\my_reg_driver_db.xml";
wstring deviceName = L"\\\\.\\MyRegDriver";
std::wstring registryKey = L"Software\\myregdriver";

struct AccessRule {
    char path[150];
    int integrityLevel;
} accessRulesArray[150];

struct IoctlInt {
    int count;
} rulesCount;

bool SendIoctlRequest(const std::wstring& deviceName) {
    int entries = 0;
    pugi::xml_document doc;

    if (!doc.load_file(xmlFilePath.c_str())) {
        cout << "Xml file not found" << endl;
        return 0;
    }

    pugi::xml_node root = doc.child("regdriver_mondatory_levels");

    for (pugi::xml_node entry = root.child("entry"); entry; entry = entry.next_sibling("entry")) {
        string path = string(entry.child_value("path"));
        strncpy_s(accessRulesArray[entries].path, path.c_str(), path.size() + 1);
        accessRulesArray[entries++].integrityLevel = stoi(string(entry.child_value("level")));
    }

    rulesCount.count = entries;

    HANDLE deviceHandle = CreateFile(
        deviceName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open device: " << deviceName << std::endl;
        return false;
    }

    DWORD bytesReturned;

    if (!DeviceIoControl(deviceHandle,
        IOCTL_UPDATE_RULES_COUNT,
        &rulesCount,
        sizeof(struct IoctlInt),
        NULL,
        0,
        &bytesReturned,
        NULL
    )) {
        std::wcerr << L"IOCTL request failed with error code: " << GetLastError() << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }

    for (int i = 0; i < rulesCount.count; i++) {
        if (!DeviceIoControl(deviceHandle,
            IOCTL_UPDATE_RULES,
            &accessRulesArray[i],
            sizeof(struct AccessRule),
            NULL,
            0,
            &bytesReturned,
            NULL
        )) {
            std::wcerr << L"IOCTL request failed with error code: " << GetLastError() << std::endl;
            CloseHandle(deviceHandle);
            return false;
        }
    }

    cout << "New rules sended successfully" << endl;
    CloseHandle(deviceHandle);
    return true;
}

void readXMLFileAndSaveToRegistry(const std::string& xmlFilePath, const std::wstring& registryKey) {
    std::ifstream file(xmlFilePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open XML file." << std::endl;
        return;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> fileContent(static_cast<size_t>(fileSize));
    if (file.read(fileContent.data(), fileSize)) {
        HKEY hKey;
        LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, registryKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to create or open the registry key." << std::endl;
            file.close();
            return;
        }

        result = RegSetValueExW(hKey, L"XMLValue", 0, REG_BINARY, reinterpret_cast<const BYTE*>(fileContent.data()), fileContent.size());
        if (result != ERROR_SUCCESS) {
            std::cerr << "Failed to write to the registry key." << std::endl;
        }

        RegCloseKey(hKey);
    }

    file.close();
}

int addNewEntry(const string& path, const int mondatory_level, const int type) {
    pugi::xml_document doc;

    if (doc.load_file(xmlFilePath.c_str())) {
        pugi::xml_node root = doc.child("regdriver_mondatory_levels");
        pugi::xml_node entry = root.append_child("entry");

        if (type == APPLICATION)
            entry.append_attribute("category").set_value("applications");
        else
            entry.append_attribute("category").set_value("reg_keys");

        entry.append_child("path").text() = path.c_str();
        entry.append_child("level").text() = std::to_string(mondatory_level).c_str();

    }
    else {
        pugi::xml_node declarationNode = doc.prepend_child(pugi::node_declaration);
        declarationNode.append_attribute("version") = "1.0";
        declarationNode.append_attribute("encoding") = "utf-8";
        
        pugi::xml_node root = doc.append_child("regdriver_mondatory_levels");
        pugi::xml_node entry = root.append_child("entry");

        if (type == APPLICATION)
            entry.append_attribute("category").set_value("applications");
        else
            entry.append_attribute("category").set_value("reg_keys");

        entry.append_child("path").text() = path.c_str();
        entry.append_child("level").text() = std::to_string(mondatory_level).c_str();
    }

    if (doc.save_file(xmlFilePath.c_str())) {
        std::cout << "Entry added successfully" << std::endl;
    }
    else {
        std::cerr << "Error while adding entry" << std::endl;
    }

    readXMLFileAndSaveToRegistry(xmlFilePath, registryKey);
    return 0;
}

int changeEntry(const string& path, const int new_mondatory_level) {
    pugi::xml_document doc;
    
    if (!doc.load_file(xmlFilePath.c_str())) {
        cout << "Xml file not found" << endl;
        return 0;
    }

    pugi::xml_node root = doc.child("regdriver_mondatory_levels");

    for (pugi::xml_node entry = root.child("entry"); entry; entry = entry.next_sibling("entry")) {
        if (std::string(entry.child_value("path")) == path) {
            entry.child("level").text() = std::to_string(new_mondatory_level).c_str();

            if (doc.save_file(xmlFilePath.c_str())) {
                std::cout << "Entry changed successfully" << std::endl;
            }
            else {
                std::cerr << "Error while changing entry" << std::endl;
            }
            readXMLFileAndSaveToRegistry(xmlFilePath, registryKey);
            return 0;
        }
    }

    std::cerr << "Entry with path '" << path << "' not found." << std::endl;
    return 0;
}

int deleteEntry(const string& path) {
    pugi::xml_document doc;

    if (!doc.load_file(xmlFilePath.c_str())) {
        cout << "Xml file not found" << endl;
        return 0;
    }

    pugi::xml_node root = doc.child("regdriver_mondatory_levels");

    for (pugi::xml_node entry = root.child("entry"); entry; entry = entry.next_sibling("entry")) {
        if (std::string(entry.child_value("path")) == path) {
            root.remove_child(entry);

            if (doc.save_file(xmlFilePath.c_str())) {
                std::cout << "Entry deleted successfully" << std::endl;
            }
            else {
                std::cerr << "Error while deleting entry" << std::endl;
            }

            readXMLFileAndSaveToRegistry(xmlFilePath, registryKey);
            return 0;
        }
    }

    std::cerr << "Entry with path '" << path << "' not found." << std::endl;
    return 0;
}

int notificatorOn() {
    HANDLE deviceHandle = CreateFile(
        deviceName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open device: " << deviceName << std::endl;
        return false;
    }

    DWORD bytesReturned;
    if (!DeviceIoControl(deviceHandle,
        IOCTL_NOTIFICATOR_ON,
        NULL,
        NULL,
        NULL,
        0,
        &bytesReturned,
        NULL
    )) {
        std::wcerr << L"IOCTL request failed with error code: " << GetLastError() << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }

    cout << "Notificator ON successfully" << endl;

    CloseHandle(deviceHandle);
    return 0;
}

int notificatorOff() {
    HANDLE deviceHandle = CreateFile(
        deviceName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open device: " << deviceName << std::endl;
        return false;
    }

    DWORD bytesReturned;
    if (!DeviceIoControl(deviceHandle,
        IOCTL_NOTIFICATOR_OFF,
        NULL,
        NULL,
        NULL,
        0,
        &bytesReturned,
        NULL
    )) {
        std::wcerr << L"IOCTL request failed with error code: " << GetLastError() << std::endl;
        CloseHandle(deviceHandle);
        return false;
    }

    cout << "Notificator OFF successfully" << endl;

    CloseHandle(deviceHandle);
    return 0;
}

void readFromRegistryAndSaveToXML(const std::wstring& registryKey, const std::string& xmlFilePath) {
    HKEY hKey;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, registryKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to open or create the registry key." << std::endl;
        return;
    }

    DWORD dataSize;
    result = RegQueryValueExW(hKey, L"XMLValue", 0, NULL, NULL, &dataSize);
    if (result != ERROR_SUCCESS) {
        std::ofstream outFile(xmlFilePath, std::ios::binary);
        outFile.close();
        std::cerr << "Failed to query the size of the data in the registry key." << std::endl;
        RegCloseKey(hKey);
        return;
    }

    std::vector<char> registryContent(dataSize);
    result = RegQueryValueExW(hKey, L"XMLValue", 0, NULL, reinterpret_cast<BYTE*>(registryContent.data()), &dataSize);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to read from the registry key." << std::endl;
        RegCloseKey(hKey);
        return;
    }

    RegCloseKey(hKey);

    std::ofstream outFile(xmlFilePath, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Failed to open or create XML file." << std::endl;
        return;
    }

    outFile.write(registryContent.data(), registryContent.size());
    outFile.close();
}

int main() {
    readFromRegistryAndSaveToXML(registryKey, xmlFilePath);

    cout << "MyRegDriver controll app" << endl << "Commands:" << endl <<
        "  a [reg/app] [path] [mand_lvl]  - add new entry of mondatory level for reg key or application" << endl <<
        "  c [path] [new_mand_lvl]        - change mandatory level for choosen reg key or applicatoin" << endl <<
        "  d [path]                       - delete entry for choosen reg key or applicatoin" << endl <<
        "  n [on/off]                     - on/of notificator for PsSetCreateThreadNotifyRoutine" << endl <<
        "  v                              - view full config file" << endl <<
        "  q                              - quit from app (PLEASE DONT CLOSE VIA ^X" << endl <<
        "  u                              - update rules to driver" << endl;

    cout << "Input your cmd below:" << endl << "> ";

    string cmd, arg1, arg2, arg3;

    while (1) {
        cin >> cmd;

        if (cmd == "a") {
            cin >> arg1;
            cin >> arg2;
            cin >> arg3;

            if (arg1 == "reg") {
                addNewEntry(arg2, stoi(arg3), KEY_REG);

                if (!SendIoctlRequest(deviceName)) {
                    cout << "Error while sending Ioctl request: " << GetLastError() << endl;
                }
            }
            else if (arg1 == "app") {
                addNewEntry(arg2, stoi(arg3), APPLICATION);

                if (!SendIoctlRequest(deviceName)) {
                    cout << "Error while sending Ioctl request: " << GetLastError() << endl;
                }
            }
            else {
                cout << "Wrong argument" << endl;
            }

        } else if (cmd == "c") {
            cin >> arg1;
            cin >> arg2;

            changeEntry(arg1, stoi(arg2));

            if (!SendIoctlRequest(deviceName)) {
                cout << "Error while sending Ioctl request: " << GetLastError() << endl;
            }

        } else if (cmd == "d") {
            cin >> arg1;
            
            deleteEntry(arg1);

            if (!SendIoctlRequest(deviceName)) {
                cout << "Error while sending Ioctl request: " << GetLastError() << endl;
            }

        } else if (cmd == "n") {
            cin >> arg1;

            if (arg1 == "on") {
                notificatorOn();
            }
            else if (arg1 == "off") {
                notificatorOff();
            }
            else {
                cout << "Wrong argument" << endl;
            }
        }
        else if (cmd == "v") {
            ifstream config(xmlFilePath);
            cout << config.rdbuf() << endl;
        }
        else if (cmd == "q") {
            std::remove(xmlFilePath.c_str());
            break;
        }
        else if (cmd == "u") {
            if (!SendIoctlRequest(deviceName)) {
                cout << "Error while sending Ioctl request: " << GetLastError() << endl;
            }
        }
        else {
            cout << "Unrecognized command" << endl;
        }

        cout << "> ";
    }
}