#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "aes.h"

// Macro to export functions for a shared library
#if defined(_WIN32) || defined(_WIN64)
    #define EXPORT __declspec(dllexport)
    #include <windows.h>
    #include <dpapi.h>
    #pragma comment(lib, "Crypt32.lib")
    #define SECURE_ZERO(ptr, size) SecureZeroMemory(ptr, size)
#else
    #define EXPORT
    // Custom fallback for secure zeroing on non-Windows
    static void secure_zero_mem(void *v, size_t n) {
        volatile unsigned char *p = (volatile unsigned char *)v;
        while (n--) *p++ = 0;
    }
    #define SECURE_ZERO(ptr, size) secure_zero_mem(ptr, size)
#endif

// AES-256 requires a 32-byte key and 16-byte IV
EXPORT void encrypt_vault(const uint8_t* key, const uint8_t* iv, uint8_t* data, size_t length) {
    struct AES_ctx ctx;
    
    // In a real advanced scenario, the key is already CryptProtectMemory'd
    // We would CryptUnprotectMemory here, initialize AES, and then CryptProtectMemory it again.
    
    AES_init_ctx_iv(&ctx, key, iv);
    
    // AES-CBC encryption works in-place
    AES_CBC_encrypt_buffer(&ctx, data, length);
    
    // Secure Memory Wiping
    SECURE_ZERO(&ctx, sizeof(struct AES_ctx));
}

EXPORT void decrypt_vault(const uint8_t* key, const uint8_t* iv, uint8_t* data, size_t length) {
    struct AES_ctx ctx;
    
    AES_init_ctx_iv(&ctx, key, iv);
    
    // AES-CBC decryption works in-place
    AES_CBC_decrypt_buffer(&ctx, data, length);
    
    // Secure Memory Wiping
    SECURE_ZERO(&ctx, sizeof(struct AES_ctx));
}
