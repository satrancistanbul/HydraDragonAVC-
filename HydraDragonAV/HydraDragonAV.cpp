#include "framework.h"
#include "HydraDragonAV.h"
#include <string>
#include <cmath>
#include <commdlg.h>  // Common Dialogs
#include <fstream>     // File stream
#include <array>     /// For std::array
#include <cassert>   /// For assert
#include <cstdint>   /// For uint8_t, uint32_t and uint64_t data types
#include <iomanip>   /// For std::setfill and std::setw
#include <iostream>  /// For IO operations
#include <sstream>   /// For std::stringstream
#include <utility>   /// For std::move
#include <vector>    /// For std::vector

using namespace std;

#define IDC_CALCULATE_MD5 1001
#define IDC_CALCULATE_SHA256 1002

// Global variable for the file path
std::wstring g_filePath;

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

typedef union uwb {
    unsigned w;
    unsigned char b[4];
} MD5union;

typedef unsigned DigestArray[4];

static unsigned func0(unsigned abcd[]) {
    return (abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]);
}

static unsigned func1(unsigned abcd[]) {
    return (abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]);
}

static unsigned func2(unsigned abcd[]) {
    return  abcd[1] ^ abcd[2] ^ abcd[3];
}

static unsigned func3(unsigned abcd[]) {
    return abcd[2] ^ (abcd[1] | ~abcd[3]);
}

typedef unsigned(*DgstFctn)(unsigned a[]);

static unsigned* calctable(unsigned* k) {
    double s, pwr;
    int i;

    pwr = pow(2.0, 32);
    for (i = 0; i < 64; i++) {
        s = fabs(sin(1.0 + i));
        k[i] = static_cast<unsigned>(s * pwr);
    }
    return k;
}

static unsigned rol(unsigned r, short N) {
    unsigned mask1 = (1 << N) - 1;
    return ((r >> (32 - N)) & mask1) | ((r << N) & ~mask1);
}

static unsigned* MD5Hash(std::string msg) {
    int mlen = static_cast<int>(msg.length());
    static DigestArray h0 = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    static DgstFctn ff[] = { &func0, &func1, &func2, &func3 };
    static short M[] = { 1, 5, 3, 7 };
    static short O[] = { 0, 1, 5, 0 };
    static short rot0[] = { 7, 12, 17, 22 };
    static short rot1[] = { 5, 9, 14, 20 };
    static short rot2[] = { 4, 11, 16, 23 };
    static short rot3[] = { 6, 10, 15, 21 };
    static short* rots[] = { rot0, rot1, rot2, rot3 };
    static unsigned kspace[64];
    static unsigned* k;

    static DigestArray h;
    DigestArray abcd;
    DgstFctn fctn;
    short m, o, g;
    unsigned f = 0;
    short* rotn;
    union {
        unsigned w[16];
        char b[64];
    } mm;
    int os = 0;
    int grp, grps, q, p;
    unsigned char* msg2 = nullptr;

    if (k == nullptr) k = calctable(kspace);

    for (q = 0; q < 4; q++) h[q] = h0[q];

    grps = 1 + (mlen + 8) / 64;
    msg2 = (unsigned char*)malloc(64 * grps);
    if (msg2 == nullptr) {
        // Handle memory allocation failure
        // You can throw an exception or return an error code
        return nullptr;
    }
    memcpy(msg2, msg.c_str(), mlen);
    msg2[mlen] = static_cast<unsigned char>(0x80);
    q = mlen + 1;
    while (q < 64 * grps) { msg2[q] = 0; q++; }
    {
        MD5union u;
        u.w = 8 * mlen;
        q -= 8;
        memcpy(msg2 + q, &u.w, 4);
    }

    for (grp = 0; grp < grps; grp++) {
        if (msg2 != nullptr) {
            memcpy(mm.b, msg2 + os, 64);
            for (q = 0; q < 4; q++) abcd[q] = h[q];
            for (p = 0; p < 4; p++) {
                fctn = ff[p];
                rotn = rots[p];
                m = M[p]; o = O[p];
                for (q = 0; q < 16; q++) {
                    g = (m * q + o) % 16;
                    if (msg2 != nullptr) {
                        f = abcd[1] + rol(abcd[0] + fctn(abcd) + k[q + 16 * p] + mm.w[g], rotn[q % 4]);
                    }
                    else {
                        // Handle the case when msg2 is null
                        f = 0; // Or any other appropriate value
                    }

                    abcd[0] = abcd[3];
                    abcd[3] = abcd[2];
                    abcd[2] = abcd[1];
                    abcd[1] = f;
                }
            }
            for (p = 0; p < 4; p++)
                h[p] += abcd[p];
            os += 64;
        }
    }

    free(msg2); // Don't forget to free the allocated memory
    return h;
}

static std::string GetMD5String(std::string msg) {
    std::string str;
    int j, k;
    unsigned* d = MD5Hash(msg);
    MD5union u;
    for (j = 0; j < 4; j++) {
        u.w = d[j];
        char s[9];
        // Use sprintf_s instead of sprintf
        sprintf_s(s, "%02x%02x%02x%02x", u.b[0], u.b[1], u.b[2], u.b[3]);
        str += s;
    }

    return str;
}


std::string GetMD5StringFromFile(const std::wstring& filePath) {
    // Open the file and read its contents
    std::ifstream file(filePath, std::ios::binary);
    if (file) {
        // Handle file opening failure
        return "";
    }

    // Read the file contents into a string
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // Call your existing MD5 hash calculation function with the file content
    return GetMD5String(content);
}


/**
 * @namespace hashing
 * @brief Hashing algorithms
 */
namespace hashing {
    /**
     * @namespace SHA-256
     * @brief Functions for the [SHA-256](https://en.wikipedia.org/wiki/SHA-2)
     * algorithm implementation
     */
    namespace sha256 {
        /**
         * @class Hash
         * @brief Contains hash array and functions to update it and convert it to a
         * hexadecimal string
         */
        class Hash {
            // Initialize array of hash values with first 32 bits of the fractional
            // parts of the square roots of the first 8 primes 2..19
            std::array<uint32_t, 8> hash = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372,
                                            0xA54FF53A, 0x510E527F, 0x9B05688C,
                                            0x1F83D9AB, 0x5BE0CD19 };

        public:
            void update(const std::array<uint32_t, 64>& blocks);
            std::string to_string() const;
        };

        /**
         * @brief Rotates the bits of a 32-bit unsigned integer
         * @param n Integer to rotate
         * @param rotate Number of bits to rotate
         * @return uint32_t The rotated integer
         */
        uint32_t right_rotate(uint32_t n, size_t rotate) {
            return (n >> rotate) | (n << (32 - rotate));
        }

        /**
         * @brief Updates the hash array
         * @param blocks Message schedule array
         * @return void
         */
        void Hash::update(const std::array<uint32_t, 64>& blocks) {
            // Initialize array of round constants with first 32 bits of the fractional
            // parts of the cube roots of the first 64 primes 2..311
            const std::array<uint32_t, 64> round_constants = {
                0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
                0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
                0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
                0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
                0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
                0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
                0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
                0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
                0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
                0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
                0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2 };

            // Initialize working variables
            auto a = hash[0];
            auto b = hash[1];
            auto c = hash[2];
            auto d = hash[3];
            auto e = hash[4];
            auto f = hash[5];
            auto g = hash[6];
            auto h = hash[7];

            // Compression function main loop
            for (size_t block_num = 0; block_num < 64; ++block_num) {
                const auto s1 =
                    right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
                const auto ch = (e & f) ^ (~e & g);
                const auto temp1 =
                    h + s1 + ch + round_constants[block_num] + blocks[block_num];
                const auto s0 =
                    right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
                const auto maj = (a & b) ^ (a & c) ^ (b & c);
                const auto temp2 = s0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            // Update hash values
            hash[0] += a;
            hash[1] += b;
            hash[2] += c;
            hash[3] += d;
            hash[4] += e;
            hash[5] += f;
            hash[6] += g;
            hash[7] += h;
        }

        /**
         * @brief Convert the hash to a hexadecimal string
         * @return std::string Final hash value
         */
        std::string Hash::to_string() const {
            std::stringstream ss;
            for (size_t i = 0; i < 8; ++i) {
                ss << std::hex << std::setfill('0') << std::setw(8) << hash[i];
            }
            return ss.str();
        }

        /**
         * @brief Computes size of the padded input
         * @param input Input string
         * @return size_t Size of the padded input
         */
        std::size_t compute_padded_size(const std::size_t input_size) {
            if (input_size % 64 < 56) {
                return input_size + 64 - (input_size % 64);
            }
            return input_size + 128 - (input_size % 64);
        }

        /**
         * @brief Returns the byte at position byte_num in in_value
         * @param in_value Input value
         * @param byte_num Position of byte to be returned
         * @return uint8_t Byte at position byte_num
         */
        template <typename T>
        uint8_t extract_byte(const T in_value, const std::size_t byte_num) {
            if (sizeof(in_value) <= byte_num) {
                throw std::out_of_range("Byte at index byte_num does not exist");
            }
            return (in_value >> (byte_num * 8)) & 0xFF;
        }

        /**
         * @brief Returns the character at pos after the input is padded
         * @param input Input string
         * @param pos Position of character to be returned
         * @return char Character at the index pos in the padded string
         */
        char get_char(const std::string& input, std::size_t pos) {
            const auto input_size = input.length();
            if (pos < input_size) {
                return input[pos];
            }
            if (pos == input_size) {
                return '\x80';
            }
            const auto padded_input_size = compute_padded_size(input_size);
            if (pos < padded_input_size - 8) {
                return '\x00';
            }
            if (padded_input_size <= pos) {
                throw std::out_of_range("pos is out of range");
            }
            return static_cast<char>(
                extract_byte<size_t>(input_size * 8, padded_input_size - pos - 1));
        }

        /**
         * @brief Creates the message schedule array
         * @param input Input string
         * @param byte_num Position of the first byte of the chunk
         * @return std::array<uint32_t, 64> Message schedule array
         */
        std::array<uint32_t, 64> create_message_schedule_array(const std::string& input,
            const size_t byte_num) {
            std::array<uint32_t, 64> blocks{};

            // Copy chunk into first 16 words of the message schedule array
            for (size_t block_num = 0; block_num < 16; ++block_num) {
                blocks[block_num] =
                    (static_cast<uint8_t>(get_char(input, byte_num + block_num * 4))
                        << 24) |
                    (static_cast<uint8_t>(get_char(input, byte_num + block_num * 4 + 1))
                        << 16) |
                    (static_cast<uint8_t>(get_char(input, byte_num + block_num * 4 + 2))
                        << 8) |
                    static_cast<uint8_t>(get_char(input, byte_num + block_num * 4 + 3));
            }

            // Extend the first 16 words into remaining 48 words of the message schedule
            // array
            for (size_t block_num = 16; block_num < 64; ++block_num) {
                const auto s0 = right_rotate(blocks[block_num - 15], 7) ^
                    right_rotate(blocks[block_num - 15], 18) ^
                    (blocks[block_num - 15] >> 3);
                const auto s1 = right_rotate(blocks[block_num - 2], 17) ^
                    right_rotate(blocks[block_num - 2], 19) ^
                    (blocks[block_num - 2] >> 10);
                blocks[block_num] =
                    blocks[block_num - 16] + s0 + blocks[block_num - 7] + s1;
            }

            return blocks;
        }

        /**
         * @brief Computes the final hash value
         * @param input Input string
         * @return std::string The final hash value
         */
        std::string sha256(const std::string& input) {
            Hash h;
            // Process message in successive 512-bit (64-byte) chunks
            for (size_t byte_num = 0; byte_num < compute_padded_size(input.length());
                byte_num += 64) {
                h.update(create_message_schedule_array(input, byte_num));
            }
            return h.to_string();
        }
    }  // namespace sha256
}  // namespace hashing

void CalculateSHA256() {
    OPENFILENAME ofn;
    WCHAR szFileName[MAX_PATH] = L"";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFileName;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFileName) / sizeof(*szFileName);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        g_filePath = szFileName;

        // Convert the wide string to narrow string
        std::string narrowFilePath(g_filePath.begin(), g_filePath.end());

        // Open the file in binary mode
        std::ifstream file(narrowFilePath, std::ios::binary);

        if (file.is_open()) {
            // Calculate SHA256 hash
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string fileContent = buffer.str();

            std::string sha256Hash = hashing::sha256::sha256(fileContent);

            file.close();

            if (!sha256Hash.empty()) {
                // Convert the SHA256 hash to a wide string
                std::wstring wideSHA256Hash(sha256Hash.begin(), sha256Hash.end());

                // Display the SHA256 hash in a message box
                MessageBoxW(nullptr, wideSHA256Hash.c_str(), L"SHA256 Hash", MB_OK | MB_ICONINFORMATION);
            }
            else {
                // Display an error message if SHA256 calculation fails
                MessageBoxW(nullptr, L"Failed to calculate SHA256 hash.", L"Error", MB_OK | MB_ICONERROR);
            }
        }
        else {
            // Display an error message if the file cannot be opened
            MessageBoxW(nullptr, L"Failed to open the file.", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

void CalculateMD5FromFile() {
    OPENFILENAME ofn;
    WCHAR szFileName[MAX_PATH] = L"";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFileName;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFileName) / sizeof(*szFileName);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        g_filePath = szFileName;

        // Call your MD5 hash calculation function with the file path
        std::string md5Hash = GetMD5StringFromFile(g_filePath);
        if (!md5Hash.empty()) {
            // Display the MD5 hash in a message box
            MessageBoxA(nullptr, md5Hash.c_str(), "MD5 Hash", MB_OK | MB_ICONINFORMATION);
        }
        else {
            // Display an error message if MD5 calculation fails
            MessageBox(nullptr, L"Failed to calculate MD5 hash.", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        // Create the "Calculate MD5" button
        HWND hButtonMD5 = CreateWindow(
            L"BUTTON",
            L"Calculate MD5",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            10, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_MD5,
            hInst,
            nullptr);

        if (hButtonMD5 == nullptr) {
            // Handle button creation failure
            return -1;
        }

        // Create the "Calculate SHA256" button
        HWND hButtonSHA256 = CreateWindow(
            L"BUTTON",
            L"Calculate SHA256",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            140, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_SHA256,
            hInst,
            nullptr);

        if (hButtonSHA256 == nullptr) {
            // Handle button creation failure
            return -1;
        }

        break;
    }
    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        switch (wmId) {
        case IDC_CALCULATE_MD5:
            CalculateMD5FromFile();
            break;
        case IDC_CALCULATE_SHA256:
            CalculateSHA256();
            break;
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
    }
    break;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        // TODO: Add any drawing code that uses hdc here...
        EndPaint(hWnd, &ps);
    }
    break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

ATOM MyRegisterClass(HINSTANCE hInstance) {
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_HYDRADRAGONAV));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_HYDRADRAGONAV);
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    hInst = hInstance; // Store instance handle in our global variable

    HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

    if (!hWnd) {
        return FALSE;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    return TRUE;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_HYDRADRAGONAV, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    if (!InitInstance(hInstance, nCmdShow)) {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_HYDRADRAGONAV));

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int)msg.wParam;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
