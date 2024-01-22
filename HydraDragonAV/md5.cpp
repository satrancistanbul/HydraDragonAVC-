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