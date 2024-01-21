#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "md5\md5.h"
#include "lzma\Lzmalib.h"

#ifdef UNICODE
#define tcout wprintf
#endif

#define BUF_LEN (10 * (sizeof(FILE_NOTIFY_INFORMATION) + MAX_PATH))
#define MD5_HASH_SIZE 32
#define LZMA_PROPS_SIZE 5

_TCHAR quarantinePath[MAX_PATH];

// Function to free memory allocated for MD5 hashes
void FreeMD5Hashes(char** md5Hashes, size_t numHashes) {
    for (size_t i = 0; i < numHashes; ++i) {
        free(md5Hashes[i]);
    }
    free(md5Hashes);
}

// Function to terminate a process using taskkill
void TerminateProcessByFullPath(const _TCHAR* filePath) {
    _TCHAR command[MAX_PATH + 50];
    _stprintf_s(command, MAX_PATH + 50, _T("taskkill /F /FI \"MODULES eq %s\""), filePath);
    system(reinterpret_cast<const char*>(command));
}

// Function to create the C:\Quarantine folder
void CreateQuarantineFolder() {
    if (!CreateDirectory(quarantinePath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        tcout(_T("Failed to create the quarantine folder.\n"));
        exit(1);
    }
}

// Function to move a file to the C:\Quarantine folder
void MoveToQuarantine(const _TCHAR* filePath) {
    _TCHAR newPath[MAX_PATH];
    _stprintf_s(newPath, MAX_PATH, _T("%s\\%s"), quarantinePath, _tcsrchr(filePath, _T('\\')) + 1);

    if (!MoveFile(filePath, newPath)) {
        tcout(_T("Failed to move the file to quarantine.\n"));
        exit(1);
    }
}

// Function to read MD5 hashes from an XZ-compressed file into memory
int ReadMD5HashesFromXZ(const _TCHAR* xzFilePath, char*** md5Hashes, size_t* numHashes) {
    FILE* file;
    if (_wfopen_s(&file, xzFilePath, _T("rb")) != 0) {
        tcout(_T("Failed to open file: %s\n"), xzFilePath);
        return 0;
    }
    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* compressedData = (unsigned char*)malloc(fileSize);
    if (!compressedData) {
        fclose(file);
        tcout(_T("Memory allocation failed.\n"));
        return 0; // Memory allocation failed
    }

    if (fread(compressedData, 1, fileSize, file) != fileSize) {
        free(compressedData);
        fclose(file);
        tcout(_T("Failed to read file: %s\n"), xzFilePath);
        return 0; // Failed to read the file
    }

    fclose(file);

    // Initialize variables for decompression
    size_t offset = LZMA_PROPS_SIZE;
    size_t uncompressedSize = 0;

    // Declare uncompressedData outside the loop
    unsigned char* uncompressedData = nullptr;

    // Decompress the data
    for (;;) {
        size_t outSize = (1 << 16);
        if (!outSize) outSize = 1;

        // Allocate memory for decompressed data
        uncompressedData = (unsigned char*)malloc(uncompressedSize + outSize);
        if (!uncompressedData) {
            free(compressedData);
            tcout(_T("Memory allocation failed.\n"));
            return 0; // Memory allocation failed
        }

        // Use LzmaUncompress to decompress data
        size_t destLen = outSize;
        size_t srcLen = fileSize - offset;
        SRes result = LzmaUncompress(uncompressedData + uncompressedSize, &destLen, compressedData + offset, &srcLen, NULL, 0);

        if (result != SZ_OK) {
            free(uncompressedData);
            free(compressedData);
            tcout(_T("Decompression failed. Error code: %d\n"), result);
            return 0; // Decompression failed
        }

        uncompressedSize += destLen;
        offset += srcLen;

        if (srcLen == 0) break;
    }

    free(compressedData);

    // Parse the uncompressed data to extract MD5 hashes
    char* start = (char*)uncompressedData;
    size_t count = 0;

    while (start < (char*)uncompressedData + uncompressedSize) {
        char* end = strchr(start, '\n');
        if (!end) end = (char*)uncompressedData + uncompressedSize;

        *end = '\0';
        (*md5Hashes)[count] = _strdup(start);
        if (!(*md5Hashes)[count]) {
            for (size_t i = 0; i < count; ++i) {
                free((*md5Hashes)[i]);
            }
            free(*md5Hashes);
            free(uncompressedData);
            tcout(_T("Memory allocation failed.\n"));
            return 0; // Memory allocation failed
        }

        start = end + 1;
        ++count;
    }

    free(uncompressedData);

    *numHashes = count;
    return 1; // Success
}

int main() {
    // Set the path for the quarantine folder
    _stprintf_s(quarantinePath, MAX_PATH, _T("C:\\Quarantine"));

    // Create the C:\Quarantine folder
    CreateQuarantineFolder();

    TCHAR buffer[BUF_LEN];
    DWORD bytes_returned;
    HANDLE dir;

    _TCHAR monitored_path[MAX_PATH] = _T("C:\\");

    dir = CreateFile(
        monitored_path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (dir == INVALID_HANDLE_VALUE) {
        tcout(_T("Failed to open directory.\n"));
        return 1;
    }

    char** maliciousHashes;
    size_t numMaliciousHashes;

    // Read malicious MD5 hashes from virusshare.xz
    if (!ReadMD5HashesFromXZ(_T("signatures\\hash\\virusshare.xz"), &maliciousHashes, &numMaliciousHashes)) {
        tcout(_T("Failed to read malicious MD5 hashes.\n"));
        FreeMD5Hashes(maliciousHashes, numMaliciousHashes);
        CloseHandle(dir);
        return 1;
    }

    bool exitLoop = false;

    while (!exitLoop) {
        if (!ReadDirectoryChangesW(
            dir,
            buffer,
            BUF_LEN,
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_ATTRIBUTES |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_SECURITY |
            FILE_NOTIFY_CHANGE_LAST_ACCESS,
            &bytes_returned,
            NULL,
            NULL
        )) {
            tcout(_T("Failed to read directory changes.\n"));
        }
        else {
            FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buffer;
            _TCHAR full_path[MAX_PATH];
            size_t path_len = _tcslen(monitored_path);
            size_t file_name_len = fni->FileNameLength / sizeof(WCHAR);

            if ((path_len + file_name_len) < MAX_PATH) {
                _tcsncpy_s(full_path, MAX_PATH, monitored_path, path_len);
                _tcsncpy_s(full_path + path_len, MAX_PATH - path_len, fni->FileName, file_name_len);
                full_path[path_len + file_name_len] = _T('\0');

                // Calculate MD5 hash of the file
                char md5Hash[MD5_HASH_SIZE];
                FILE* fileStream;
                if (_wfopen_s(&fileStream, full_path, _T("rb")) == 0) {
                    if (md5_stream() == 0) {
                        // Check if the MD5 hash is in the list of known malicious hashes
                        int isMalicious = 0;
                        for (size_t i = 0; i < numMaliciousHashes; ++i) {
                            if (strcmp(md5Hash, maliciousHashes[i]) == 0) {
                                isMalicious = 1;
                                break;
                            }
                        }

                        // Take appropriate action for malware detection
                        if (isMalicious) {
                            tcout(_T("File is malicious: %s\n"), full_path);
                            // Terminate the process using taskkill
                            TerminateProcessByFullPath(full_path);

                            // Move the infected file to quarantine
                            MoveToQuarantine(full_path);
                        }
                        else {
                            tcout(_T("File is clean: %s\n"), full_path);
                        }
                    }
                    fclose(fileStream);
                }
                else {
                    tcout(_T("Error opening file: %s\n"), full_path);
                }
            }
            else {
                tcout(_T("File path is too long.\n"));
            }
        }
    }

    // Free memory allocated for malicious MD5 hashes
    FreeMD5Hashes(maliciousHashes, numMaliciousHashes);

    CloseHandle(dir);
    return 0;
}
