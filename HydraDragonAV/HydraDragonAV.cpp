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
#include <algorithm>  /// For std::copy
#include <vector>     /// For std::vector
#include "sha256.cpp"
#include "md5.cpp"
#include "sha1.cpp"
#include "ssdeep\fuzzy.h"
#pragma comment(lib, "ssdeep\\fuzzy.lib")
#define IDC_CALCULATE_MD5 1001
#define IDC_CALCULATE_SHA1 1002
#define IDC_CALCULATE_SHA256 1003
#define IDC_CALCULATE_SSDEEP 1004  // Define ID for the ssdeep button

void CalculateSSDeep() {
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
            // Read the entire file into a buffer
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string fileContentBuffer = buffer.str();

            // Allocate a buffer for the result
            char resultBuffer[FUZZY_MAX_RESULT];

            // Compute the SSDeep hash
            int status = fuzzy_hash_buf(reinterpret_cast<const unsigned char*>(fileContentBuffer.c_str()), fileContentBuffer.size(), resultBuffer);

            file.close();

            if (status == 0) {
                // Convert the SSDeep hash to a wide string
                std::wstring wideSSDeepHash(resultBuffer, resultBuffer + FUZZY_MAX_RESULT);

                // Display the SSDeep hash in a message box
                MessageBoxW(nullptr, wideSSDeepHash.c_str(), L"SSDeep Hash", MB_OK | MB_ICONINFORMATION);
            }
            else {
                // Display an error message if SSDeep calculation fails
                MessageBoxW(nullptr, L"Failed to calculate SSDeep hash.", L"Error", MB_OK | MB_ICONERROR);
            }
        }
        else {
            // Display an error message if the file cannot be opened
            MessageBoxW(nullptr, L"Failed to open the file.", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

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

void CalculateMD5() {
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

void CalculateSHA1() {
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
            // Calculate SHA1 hash
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string fileContent = buffer.str();

            // Calculate SHA-1 hash
            void* sha1Signature = hashing::sha1::hash_bs(fileContent.c_str(), fileContent.size());
            std::string sha1Hex = hashing::sha1::sig2hex(sha1Signature);

            file.close();

            if (!sha1Hex.empty()) {
                // Convert the SHA1 hash to a wide string
                std::wstring wideSHA1Hash(sha1Hex.begin(), sha1Hex.end());

                // Display the SHA1 hash in a message box
                MessageBoxW(nullptr, wideSHA1Hash.c_str(), L"SHA1 Hash", MB_OK | MB_ICONINFORMATION);
            }
            else {
                // Display an error message if SHA1 calculation fails
                MessageBoxW(nullptr, L"Failed to calculate SHA1 hash.", L"Error", MB_OK | MB_ICONERROR);
            }

            // Clean up allocated memory
            delete[] sha1Signature;
        }
        else {
            // Display an error message if the file cannot be opened
            MessageBoxW(nullptr, L"Failed to open the file.", L"Error", MB_OK | MB_ICONERROR);
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

        // Create the "Calculate SHA1" button
        HWND hButtonSHA1 = CreateWindow(
            L"BUTTON",
            L"Calculate SHA1",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            140, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_SHA1,
            hInst,
            nullptr);

        if (hButtonSHA1 == nullptr) {
            // Handle button creation failure
            return -1;
        }

        // Create the "Calculate SHA256" button
        HWND hButtonSHA256 = CreateWindow(
            L"BUTTON",
            L"Calculate SHA256",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            270, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_SHA256,
            hInst,
            nullptr);

        if (hButtonSHA256 == nullptr) {
            // Handle button creation failure
            return -1;
        }

        // Create the "Calculate SSDeep" button
        HWND hButtonSSDeep = CreateWindow(
            L"BUTTON",
            L"Calculate SSDeep",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            400, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_SSDEEP,
            hInst,
            nullptr);

        if (hButtonSSDeep == nullptr) {
            // Handle button creation failure
            return -1;
        }

        break;
    }
    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        switch (wmId) {
        case IDC_CALCULATE_MD5:
            CalculateMD5();
            break;
        case IDC_CALCULATE_SHA256:
            CalculateSHA256();
            break;
        case IDC_CALCULATE_SSDEEP:
            CalculateSSDeep();
            break;
        case IDC_CALCULATE_SHA1:  // Added case for SHA-1 calculation
            CalculateSHA1();
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
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        // TODO: Add any drawing code that uses hdc here...
        EndPaint(hWnd, &ps);
        break;
    }
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
