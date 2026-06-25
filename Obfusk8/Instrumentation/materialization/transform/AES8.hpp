#pragma once

#include "K8_UTILS/k8_utils.hpp"

using namespace std;

NOOPT

constexpr uint32_t _obf_date_hash() {
    const char* s = __DATE__;
    uint32_t h = 0x811C9DC5;
    while (*s) { h = (h ^ (uint8_t)*s) * 0x01000193; ++s; }
    s = __TIME__;
    while (*s) { h = (h ^ (uint8_t)*s) * 0x01000193; ++s; }
    return h;
}

        #pragma region AES_CONSTEXPR
            namespace aes_constexpr {
                constexpr uint8_t sbox[256] = {
                        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
                };

                constexpr uint8_t rsbox[256] = {
                    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
                };

                constexpr uint8_t rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
            }
        #pragma endregion AES_CONSTEXPR

        #pragma region Helpers
            #define _L_SUB(a, b) ( \
                ((unsigned int)(a) ^ (unsigned int)(b)) - \
                (2 * ((~(unsigned int)(a)) & (unsigned int)(b))) \
            )

            #define _L_XOR(a, b) ( \
                ((unsigned int)(a) | (unsigned int)(b)) - \
                ((unsigned int)(a) & (unsigned int)(b)) \
            )

            #define _L_OR(a, b) ( \
                ((unsigned int)(a) + (unsigned int)(b)) - \
                ((unsigned int)(a) & (unsigned int)(b)) \
            )

            K8_FORCEINLINE uint32_t _bstrap_hash(const char* str) {
                uint32_t h = _BSTRAP_IV;
                if (!str) return 0;
                while (*str) {
                    char c = *str++;
                    if (c >= 'a' && c <= 'z')
                        c = (char)_L_SUB((int)c, 0x20);
                    uint8_t low_byte = (uint8_t)_L_XOR((h & 0xFF), (uint32_t)c);
                    uint8_t sub = aes_constexpr::sbox[low_byte];
                    h = _L_OR((h >> 8), (h << 24));
                    h = _L_XOR(h, (uint32_t)sub);
                }
                return h;
            }

            K8_FORCEINLINE uint32_t _char_hasher(char c) {
                uint32_t h = _BSTRAP_IV;
                if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
                   c = (char)_L_SUB((int)c, 0x20);
                uint8_t low_byte = (uint8_t)_L_XOR((h & 0xFF), (uint32_t)c);
                uint8_t sub = aes_constexpr::sbox[low_byte];
                h = _L_OR((h >> 8), (h << 24));
                h = _L_XOR(h, (uint32_t)sub);
                return h;
            }
        #pragma endregion Helpers

        #pragma region Sections
            #define PACKER_SECTION_0 ".reloc"
            #define PACKER_SECTION_1 ".reloc"
            #define PACKER_SECTION_2 ".bss"
            #define PACKER_SECTION_3 ".bss"
            #define PACKER_SECTION_4 ".reloc"
            #define PACKER_SECTION_5 ".reloc"
            #define PACKER_SECTION_6 ".tls"
            #define PACKER_SECTION_7 ".tls"
            #define PACKER_SECTION_8 ".CRT"
            #define PACKER_SECTION_9 ".CRT"
            #define PACKER_SECTION_10 ".idata"
            #define PACKER_SECTION_11 ".idata"
            #define PACKER_SECTION_12 ".edata"
            #define PACKER_SECTION_13 ".edata"
            #define PACKER_SECTION_14 ".00cfg"
            #define PACKER_SECTION_15 ".00cfg"
            #define PACKER_SECTION_16 ".sxdata"
            #define PACKER_SECTION_17 ".sxdata"
            #define PACKER_SECTION_18 ".gfids"
            #define PACKER_SECTION_19 ".gfids"
            #define PACKER_SECTION_20 ".giats"
            #define PACKER_SECTION_21 ".giats"
            #define PACKER_SECTION_22 ".eh_frame"
            #define PACKER_SECTION_23 ".eh_frame"
            #define PACKER_SECTION_24 ".giats"
            #define PACKER_SECTION_25 ".giats"
            #define PACKER_SECTION_26 ".giats"
            #define PACKER_SECTION_27 ".giats"
            #define PACKER_SECTION_28 ".reloc"
            #define PACKER_SECTION_29 ".reloc"
            #define PACKER_SECTION_30 ".bss"
            #define PACKER_SECTION_31 ".bss"
            #define PACKER_SECTION_32 ".reloc"
            #define PACKER_SECTION_33 ".reloc"
            #define PACKER_SECTION_34 ".tls"
            #define PACKER_SECTION_35 ".tls"
            #define PACKER_SECTION_36 ".CRT"
            #define PACKER_SECTION_37 ".CRT"
            #define PACKER_SECTION_38 ".idata"
            #define PACKER_SECTION_39 ".idata"

            #define PICK_SECTION(idx) PACKER_SECTION_##idx

            #if defined(_MSC_VER) || defined(__clang__)
                #pragma section(".reloc", read, write)
                #pragma section(".bss", read, write)
                #pragma section(".tls", read, write)
                #pragma section(".CRT", read, write)
                #pragma section(".idata", read, write)
                #pragma section(".edata", read, write)
                #pragma section(".00cfg", read, write)
                #pragma section(".sxdata", read, write)
                #pragma section(".gfids", read, write)
                #pragma section(".eh_frame", read, write)
                #pragma section(".giats", read, write)
            #endif

            #if defined(_MSC_VER) || defined(__clang__)
                #define DECLARE_SECTION(secname) __pragma(section(secname, read, write))
                #define SECTION_ATTR_SEC(secname) __declspec(allocate(secname))
            #else
                #define DECLARE_SECTION(secname)
                #define SECTION_ATTR_SEC(secname) 
            #endif

            #define SIG_BASE_UPX     0x21585055
            #define SIG_BASE_VMP     0x504d565b
            #define SIG_BASE_ENIGMA  0x47494e45
            #define SIG_BASE_THEMIDA 0x4944454d
            #define SIG_BASE_FSG     0x21475346
            #define SIG_BASE_ASPACK  0x4b434150
            #define SIG_BASE_NSPACK  0x4b43414e
            #define SIG_BASE_MPRESS  0x53534552

            #define GEN_SIG(base, line) (uint32_t)((base) ^ ((line) * 0x78654) ^ 0x874275372)
        #pragma endregion Sections

        #define CONCAT2(a,b) a##b
        #define CONCAT(a,b) CONCAT2(a,b)

        #define _INTERNAL_OBF(str) \
                ([]() { \
                    struct _OD { \
                        using _CharT = remove_cv_t<remove_reference_t<decltype(str[0])>>; \
                        static constexpr size_t _N() { return sizeof(str); } \
                        static_assert((_N() + 15) / 16 <= 40, "[Obfusk8] String exceeds 640-byte limit."); \
                        static constexpr uint32_t _SEED() { return (uint32_t)(__LINE__ ^ 0x7F3A5C1E) + (uint32_t)_N(); } \
                        static constexpr auto _xored() { \
                            constexpr size_t N = _N(); \
                            array<uint8_t, N> r{}; \
                            uint32_t s = _SEED(); \
                            for (size_t i = 0; i < N; ++i) { \
                                s = s * 0x41C64E6D + 0x3039; \
                                size_t w_idx = i / sizeof(_CharT); \
                                size_t b_off = i % sizeof(_CharT); \
                                r[i] = (uint8_t)((str[w_idx] >> (b_off * 8)) & 0xFF) ^ (uint8_t)(s >> 16); \
                            } \
                            return r; \
                        } \
                    }; \
                    \
                    constexpr size_t _N = _OD::_N(); \
                    uint8_t _buf[640] = {}; \
                    { \
                        uint32_t s = _OD::_SEED(); \
                        auto _xd = _OD::_xored(); \
                        for (size_t i = 0; i < _N; ++i) { \
                            s = s * 0x41C64E6D + 0x3039; \
                            _buf[i] = _xd[i] ^ (uint8_t)(s >> 16); \
                        } \
                    } \
                    \
                    size_t _len = _N; \
                    for (size_t i = 1; i < _len; ++i) \
                        if (_buf[i] == 0) { _len = i; break; } \
                    \
                    if constexpr (sizeof(typename _OD::_CharT) > 1) { \
                        wstring ws; \
                        ws.resize(_len / sizeof(wchar_t)); \
                        for (size_t i = 0; i < ws.size(); ++i) \
                            ws[i] = (wchar_t)((uint16_t)_buf[i*2] | ((uint16_t)_buf[i*2+1] << 8)); \
                        volatile uint32_t _v = 0; \
                        for (size_t i = 0; i < 20 && i < _N; ++i) _v ^= _buf[i]; \
                        (void)_v; \
                        return ws; \
                    } else { \
                        string _result((char*)_buf, _len); \
                        volatile uint32_t _v = 0; \
                        for (size_t i = 0; i < 20 && i < _N; ++i) _v ^= _buf[i]; \
                        (void)_v; \
                        return _result; \
                    } \
                })()

        #define OBFUSCATE_STRING(str) _INTERNAL_OBF(str)
        #define OBFUSCATE_WSTRING(str) _INTERNAL_OBF(str)
OPT