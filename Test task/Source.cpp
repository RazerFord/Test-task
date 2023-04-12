#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#include <windows.h>
#define FILENAME "C:\\temp\\file.txt"
#endif
#ifdef __linux__

#include <dlfcn.h>

#define FILENAME "/tmp/file.txt"
#endif


void CWE114_Process_Control__w32_char_file_01_bad() {
    char *data;

    char buff[100] = "";

    FILE *hFile;
    unsigned long lpNumberOfBytesRead;

    hFile = fopen(FILENAME, "a+t");

    if (hFile == NULL) {
        printf("Cannot open file\n");
        return;
    }
    do {
        lpNumberOfBytesRead = fread(buff, sizeof(char), sizeof(buff), hFile);
    } while (lpNumberOfBytesRead == sizeof(buff));

    fclose(hFile);

    data = buff;

    {
        void *hModule = NULL;
        /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
         * replace his own file with the intended library */
        if (strcmp(data, ""))
            hModule = dlopen(data, RTLD_LAZY | RTLD_GLOBAL);
        if (hModule != NULL) {
            dlclose(hModule);
            printf("Library loaded and freed successfully\n");
        } else {
            printf("Unable to load library\n");
        }
    }
}


/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B() {
    char *data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: Specify the full pathname for the library */
    strcpy(data, "/usr/lib/libhandle.so.1");
    {
        void *hModule = NULL;
        /* POTENTIAL FLAW: If the path to the library is not specified, an attacker may be able to
         * replace his own file with the intended library */
        hModule = dlopen(data, RTLD_LAZY | RTLD_GLOBAL);
        if (hModule != NULL) {
            dlclose(hModule);
            printf("Library loaded and freed successfully \n");
        } else {
            printf("Unable to load library\n");
        }
    }
}

void CWE114_Process_Control__w32_char_file_01_good() {
    goodG2B();
}


/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */



int main(int argc, char *argv[]) {
    /* seed randomness */
    srand((unsigned) time(NULL));
    printf("Calling good()... \n");
    CWE114_Process_Control__w32_char_file_01_good();
    printf("Finished good() \n");

    printf("Calling bad()...\n");
    CWE114_Process_Control__w32_char_file_01_bad();
    printf("Finished bad() \n");
    return 0;
}
