/*
 * MonoLoader.cpp - Corrected version
 *
 * Credits:
 *   - github.com/hdunl
 *   - https://github.com/warbler/SharpMonoInjector smi source helped me figure some stuff out, thanks warbler!
 */

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <fstream>

typedef void* MonoDomain;
typedef void* MonoAssembly;
typedef void* MonoImage;
typedef void* MonoClass;
typedef void* MonoMethod;
typedef void* MonoObject;
typedef int MonoImageOpenStatus;

typedef MonoDomain(*MonoGetRootDomain)();
typedef MonoDomain(*MonoThreadAttach)(MonoDomain domain);
typedef MonoImage(*MonoImageOpenFromData)(const char* data, UINT32 data_len, BOOL need_copy, MonoImageOpenStatus* status);
typedef MonoAssembly(*MonoAssemblyLoadFromFull)(MonoImage image, const char* fname, MonoImageOpenStatus* status, BOOL refonly);
typedef MonoImage(*MonoAssemblyGetImage)(MonoAssembly assembly);
typedef MonoClass(*MonoClassFromName)(MonoImage image, const char* name_space, const char* name);
typedef MonoMethod(*MonoClassGetMethodFromName)(MonoClass klass, const char* name, int param_count);
typedef MonoObject* (*MonoRuntimeInvoke)(MonoMethod method, void* obj, void** params, MonoObject** exc);
typedef void (*MonoAssemblyClose)(MonoAssembly assembly);
typedef const char* (*MonoImageStrerror)(MonoImageOpenStatus status);

struct MonoFunctions {
    MonoGetRootDomain mono_get_root_domain;
    MonoThreadAttach mono_thread_attach;
    MonoImageOpenFromData mono_image_open_from_data;
    MonoAssemblyLoadFromFull mono_assembly_load_from_full;
    MonoAssemblyGetImage mono_assembly_get_image;
    MonoClassFromName mono_class_from_name;
    MonoClassGetMethodFromName mono_class_get_method_from_name;
    MonoRuntimeInvoke mono_runtime_invoke;
    MonoAssemblyClose mono_assembly_close;
    MonoImageStrerror mono_image_strerror;
};

void WriteLog(const std::string& message) {
    std::string appdata = std::getenv("APPDATA");
    std::string logPath = appdata + "\\MonoLoader.log";
    std::ofstream logFile;
    logFile.open(logPath, std::ios_base::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }
}

HMODULE FindMonoModule() {
    HMODULE hMono = NULL;
    const char* monoNames[] = {
        "mono.dll",
        "mono-2.0-bdwgc.dll",
        "mono-2.0.dll"
    };
    for (const auto& name : monoNames) {
        hMono = GetModuleHandleA(name);
        if (hMono != NULL) {
            WriteLog(std::string("Found Mono module: ") + name);
            return hMono;
        }
    }
    WriteLog("Failed to find Mono module");
    return NULL;
}

bool LoadMonoFunctions(HMODULE hMono, MonoFunctions* functions) {
    if (!hMono || !functions) {
        WriteLog("Invalid parameters for LoadMonoFunctions");
        return false;
    }
    functions->mono_get_root_domain = (MonoGetRootDomain)GetProcAddress(hMono, "mono_get_root_domain");
    functions->mono_thread_attach = (MonoThreadAttach)GetProcAddress(hMono, "mono_thread_attach");
    functions->mono_image_open_from_data = (MonoImageOpenFromData)GetProcAddress(hMono, "mono_image_open_from_data");
    functions->mono_assembly_load_from_full = (MonoAssemblyLoadFromFull)GetProcAddress(hMono, "mono_assembly_load_from_full");
    functions->mono_assembly_get_image = (MonoAssemblyGetImage)GetProcAddress(hMono, "mono_assembly_get_image");
    functions->mono_class_from_name = (MonoClassFromName)GetProcAddress(hMono, "mono_class_from_name");
    functions->mono_class_get_method_from_name = (MonoClassGetMethodFromName)GetProcAddress(hMono, "mono_class_get_method_from_name");
    functions->mono_runtime_invoke = (MonoRuntimeInvoke)GetProcAddress(hMono, "mono_runtime_invoke");
    functions->mono_assembly_close = (MonoAssemblyClose)GetProcAddress(hMono, "mono_assembly_close");
    functions->mono_image_strerror = (MonoImageStrerror)GetProcAddress(hMono, "mono_image_strerror");
    if (!functions->mono_get_root_domain ||
        !functions->mono_thread_attach ||
        !functions->mono_image_open_from_data ||
        !functions->mono_assembly_load_from_full ||
        !functions->mono_assembly_get_image ||
        !functions->mono_class_from_name ||
        !functions->mono_class_get_method_from_name ||
        !functions->mono_runtime_invoke ||
        !functions->mono_assembly_close ||
        !functions->mono_image_strerror) {
        WriteLog("Failed to get all required Mono functions");
        return false;
    }
    WriteLog("Successfully loaded all Mono functions");
    return true;
}

std::vector<char> ReadFileContents(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        WriteLog("Failed to open file: " + path);
        return std::vector<char>();
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        WriteLog("Failed to read file contents");
        return std::vector<char>();
    }
    WriteLog("Successfully read file: " + path + " (" + std::to_string(size) + " bytes)");
    return buffer;
}

bool InjectAssembly(const std::string& dllPath, const std::string& nameSpace, const std::string& className, const std::string& methodName) {
    WriteLog("Starting assembly injection");
    WriteLog("DLL Path: " + dllPath);
    WriteLog("Namespace: " + nameSpace);
    WriteLog("Class: " + className);
    WriteLog("Method: " + methodName);
    HMODULE hMono = FindMonoModule();
    if (!hMono) {
        return false;
    }
    MonoFunctions functions = {};
    if (!LoadMonoFunctions(hMono, &functions)) {
        return false;
    }
    std::vector<char> assemblyData = ReadFileContents(dllPath);
    if (assemblyData.empty()) {
        return false;
    }
    try {
        WriteLog("Getting root domain");
        MonoDomain rootDomain = functions.mono_get_root_domain();
        if (!rootDomain) {
            WriteLog("Failed to get root domain");
            return false;
        }
        WriteLog("Attaching to thread");
        functions.mono_thread_attach(rootDomain);
        WriteLog("Opening image from data");
        MonoImageOpenStatus status;
        MonoImage image = functions.mono_image_open_from_data(
            assemblyData.data(),
            static_cast<UINT32>(assemblyData.size()),
            TRUE,
            &status
        );
        if (!image || status != 0) {
            WriteLog(std::string("Failed to open image: ") + functions.mono_image_strerror(status));
            return false;
        }
        WriteLog("Loading assembly from image");
        MonoAssembly assembly = functions.mono_assembly_load_from_full(
            image,
            "",
            &status,
            FALSE
        );
        if (!assembly || status != 0) {
            WriteLog(std::string("Failed to load assembly: ") + functions.mono_image_strerror(status));
            return false;
        }
        WriteLog("Getting image from assembly");
        MonoImage assemblyImage = functions.mono_assembly_get_image(assembly);
        if (!assemblyImage) {
            WriteLog("Failed to get assembly image");
            return false;
        }
        WriteLog("Getting class from name");
        MonoClass klass = functions.mono_class_from_name(
            assemblyImage,
            nameSpace.c_str(),
            className.c_str()
        );
        if (!klass) {
            WriteLog("Failed to get class");
            return false;
        }
        WriteLog("Getting method from name");
        MonoMethod method = functions.mono_class_get_method_from_name(
            klass,
            methodName.c_str(),
            0
        );
        if (!method) {
            WriteLog("Failed to get method");
            return false;
        }
        WriteLog("Invoking method");
        MonoObject* exception = NULL;
        functions.mono_runtime_invoke(
            method,
            NULL,
            NULL,
            &exception
        );
        if (exception) {
            WriteLog("Method threw an exception");
            return false;
        }
        WriteLog("Method invoked successfully");
        return true;
    }
    catch (const std::exception& e) {
        WriteLog(std::string("Exception during injection: ") + e.what());
        return false;
    }
    catch (...) {
        WriteLog("Unknown exception during injection");
        return false;
    }
}

extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(int code, WPARAM wParam, LPARAM lParam) {
    static bool initialized = false;
    if (code >= 0 && !initialized) {
        initialized = true;
        std::string appdata = std::getenv("APPDATA");
        std::string dllPath = appdata + "\\DarkRepoLauncher\\r.e.p.o.cheat.dll";
        std::string nameSpace = "r.e.p.o_cheat";
        std::string className = "Loader";
        std::string methodName = "Init";
        InjectAssembly(dllPath, nameSpace, className, methodName);
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        CreateThread(NULL, 0, [](LPVOID lpParam) -> DWORD {
            Sleep(500);
            std::string appdata = std::getenv("APPDATA");
            std::string dllPath = appdata + "\\DarkRepoLauncher\\r.e.p.o.cheat.dll";
            std::string nameSpace = "r.e.p.o_cheat";
            std::string className = "Loader";
            std::string methodName = "Init";
            InjectAssembly(dllPath, nameSpace, className, methodName);
            return 0;
            }, NULL, 0, NULL);
        break;
    }
    }
    return TRUE;
}
