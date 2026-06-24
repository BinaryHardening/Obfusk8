#include "../Instrumentation/materialization/state/Obfusk8Core.hpp"
#include "../Instrumentation/materialization/transform/antiemu8.hpp"
#include <iostream>

using namespace std;

_main
({
    if (!k8_antiemu::is_safe_environment()) {
        cout << OBFUSCATE_STRING("[ANTI-EMU] Environment looks unsafe, exiting.\n").c_str();
        return 1;
    }
    cout << OBFUSCATE_STRING("[ANTI-EMU] Environment looks safe, continuing.\n").c_str();
 })
