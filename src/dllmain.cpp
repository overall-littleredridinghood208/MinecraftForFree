#include <libhat/scanner.hpp>
#include <libhat/signature.hpp>
#include "vcproxy/vcruntime.hpp"
#include "utils/detour.hpp"

// bool TrialManager::isTrial()
std::unique_ptr<detour> gIsTrialDetour = nullptr;
hat::fixed_signature gIsTrialSig = hat::compile_signature<"40 ? 48 83 EC ? 48 8B ? ? ? ? ? 48 33 ? 48 89 ? ? ? 48 8B ? 48 8B ? ? 48 8B ? 48 8B ? ? ? ? ? FF 15">();

static bool isTrial(void* _this)
{
    return false;
}

BOOL WINAPI DllMain(HMODULE /* module */, DWORD reason,  LPVOID /* reserved */)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
        {
            proxy::init();
            MH_Initialize();

            hat::scan_result isTrialAddr = hat::find_pattern(gIsTrialSig, ".text");
            gIsTrialDetour = std::make_unique<detour>(isTrialAddr.get(), &isTrial);
            gIsTrialDetour->enable();

            break;
        }
        case DLL_PROCESS_DETACH:
        {
            gIsTrialDetour->disable();
            gIsTrialDetour.reset();

            MH_Uninitialize();
            proxy::shutdown();

            break;
        }

        default: break;
    }

    return TRUE;
}