/*
 * mythaia-proxy-guard.exe: puts the system proxy back when Mythaia Pro dies
 * without doing it itself.
 *
 * The app points the per-user proxy at its own local listener. Ended from
 * Task Manager, killed by a crash or by a debugger, it never gets to undo
 * that, and every program on the PC then goes through a proxy that is not
 * there until the app is started again. This process is started by the app
 * once, waits on the app's process handle (no polling, no CPU), and when
 * the app is gone while the snapshot of the old settings is still on disk,
 * it runs the app's own restore (`Mythaia Pro.exe --restore-proxy`), which
 * knows what to put back. A clean exit deletes the snapshot first, so then
 * nothing is run.
 *
 * Why a separate native program: a second JVM would cost tens of megabytes
 * for the whole session and show up as a second "Mythaia Pro"; a scheduled
 * task or a service needs administrator rights. This needs none.
 *
 * Task Manager's "End task" ends the app together with the processes it
 * started, so the first copy only re-launches itself and exits at once:
 * the copy that waits has no living parent and is not part of the app's
 * process tree. The app's process handle is opened by the first copy and
 * inherited by the second, so a reused process id can never be mistaken
 * for the app.
 *
 * Usage (as the app starts it):
 *   mythaia-proxy-guard.exe --pid <app pid> --snapshot <file> --run <command...>
 * The second copy gets --handle <inherited handle> in place of --pid.
 *
 * Wide-character APIs only: the install folder may well have letters that
 * the ANSI code page cannot spell.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <shellapi.h>
#include <stdlib.h>
#include <wchar.h>

/* How long the restore may take before the guard stops waiting for it. */
#define RESTORE_WAIT_MS 120000

typedef struct {
    wchar_t *text;
    size_t length;
    size_t capacity;
} Buffer;

static int buffer_append(Buffer *b, const wchar_t *text, size_t count) {
    if (b->length + count + 1 > b->capacity) {
        size_t capacity = (b->capacity == 0) ? 512 : b->capacity;
        while (b->length + count + 1 > capacity) capacity *= 2;
        wchar_t *grown = (wchar_t *)realloc(b->text, capacity * sizeof(wchar_t));
        if (grown == NULL) return 0;
        b->text = grown;
        b->capacity = capacity;
    }
    memcpy(b->text + b->length, text, count * sizeof(wchar_t));
    b->length += count;
    b->text[b->length] = L'\0';
    return 1;
}

/*
 * Appends one argument the way CommandLineToArgvW and the C runtime read it
 * back: quoted when needed, backslashes doubled only where they precede a
 * quote.
 */
static int append_argument(Buffer *b, const wchar_t *arg) {
    if (b->length > 0 && !buffer_append(b, L" ", 1)) return 0;
    if (arg[0] != L'\0' && wcspbrk(arg, L" \t\n\v\"") == NULL) {
        return buffer_append(b, arg, wcslen(arg));
    }
    if (!buffer_append(b, L"\"", 1)) return 0;
    for (const wchar_t *p = arg;; p++) {
        size_t slashes = 0;
        while (*p == L'\\') {
            p++;
            slashes++;
        }
        if (*p == L'\0') {
            for (size_t i = 0; i < slashes * 2; i++) {
                if (!buffer_append(b, L"\\", 1)) return 0;
            }
            break;
        }
        if (*p == L'"') {
            for (size_t i = 0; i < slashes * 2 + 1; i++) {
                if (!buffer_append(b, L"\\", 1)) return 0;
            }
        } else {
            for (size_t i = 0; i < slashes; i++) {
                if (!buffer_append(b, L"\\", 1)) return 0;
            }
        }
        if (!buffer_append(b, p, 1)) return 0;
    }
    return buffer_append(b, L"\"", 1);
}

/* Where the command to run begins: the argument after --run, or argc. */
static int run_index(int argc, wchar_t **argv) {
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--run") == 0) return i + 1;
    }
    return argc;
}

/* The value after option `name`, looked for only before --run: the command may have options of its own. */
static const wchar_t *option_value(int argc, wchar_t **argv, const wchar_t *name) {
    int run = run_index(argc, argv);
    /* The options end at --run itself (run - 1), or at argc when there is none. */
    int end = (run < argc || (run == argc && argc > 1 && wcscmp(argv[argc - 1], L"--run") == 0)) ? run - 1 : argc;
    for (int i = 1; i + 1 < end; i++) {
        if (wcscmp(argv[i], name) == 0) return argv[i + 1];
    }
    return NULL;
}

/*
 * Starts `command` without a window. Breaking away from the caller's job
 * keeps it alive where the app was started inside one that is torn down
 * with the app (some launchers do that); a job that forbids it gets the
 * plain start instead.
 */
static HANDLE start_process(wchar_t *command, HANDLE inherit) {
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION info;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    SIZE_T size = 0;
    DWORD flags = CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB | CREATE_UNICODE_ENVIRONMENT;
    BOOL inherits = FALSE;

    ZeroMemory(&startup, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);

    if (inherit != NULL) {
        /* Only the app's handle goes to the child, nothing else this process holds. */
        InitializeProcThreadAttributeList(NULL, 1, 0, &size);
        attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
        if (attributes == NULL || !InitializeProcThreadAttributeList(attributes, 1, 0, &size)) return NULL;
        if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                       &inherit, sizeof(HANDLE), NULL, NULL)) {
            DeleteProcThreadAttributeList(attributes);
            HeapFree(GetProcessHeap(), 0, attributes);
            return NULL;
        }
        startup.lpAttributeList = attributes;
        flags |= EXTENDED_STARTUPINFO_PRESENT;
        inherits = TRUE;
    }

    BOOL started = CreateProcessW(NULL, command, NULL, NULL, inherits, flags, NULL, NULL,
                                  &startup.StartupInfo, &info);
    if (!started && GetLastError() == ERROR_ACCESS_DENIED) {
        flags &= ~CREATE_BREAKAWAY_FROM_JOB;
        started = CreateProcessW(NULL, command, NULL, NULL, inherits, flags, NULL, NULL,
                                 &startup.StartupInfo, &info);
    }
    if (attributes != NULL) {
        DeleteProcThreadAttributeList(attributes);
        HeapFree(GetProcessHeap(), 0, attributes);
    }
    if (!started) return NULL;
    CloseHandle(info.hThread);
    return info.hProcess;
}

/* First copy: open the app, hand it to a detached second copy, leave. */
static int launch_waiter(int argc, wchar_t **argv, const wchar_t *pid_text) {
    DWORD pid = (DWORD)wcstoul(pid_text, NULL, 10);
    if (pid == 0) return 2;

    HANDLE app = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
    if (app == NULL) return 3;

    wchar_t self[32768];
    DWORD length = GetModuleFileNameW(NULL, self, (DWORD)(sizeof(self) / sizeof(self[0])));
    if (length == 0 || length >= sizeof(self) / sizeof(self[0])) return 4;

    wchar_t handle_text[32];
    swprintf(handle_text, sizeof(handle_text) / sizeof(handle_text[0]), L"%llu",
             (unsigned long long)(ULONG_PTR)app);

    Buffer command = {0};
    int ok = append_argument(&command, self) &&
             append_argument(&command, L"--handle") &&
             append_argument(&command, handle_text);
    /* Everything but --pid and its value goes along unchanged. */
    int run = run_index(argc, argv);
    for (int i = 1; ok && i < argc; i++) {
        if (i < run && wcscmp(argv[i], L"--pid") == 0) {
            i++;
            continue;
        }
        ok = append_argument(&command, argv[i]);
    }
    if (!ok) return 5;

    HANDLE waiter = start_process(command.text, app);
    free(command.text);
    if (waiter == NULL) return 6;
    CloseHandle(waiter);
    return 0;
}

/* Second copy: wait for the app; if it left the proxy set, run the restore. */
static int wait_and_restore(int argc, wchar_t **argv, const wchar_t *handle_text) {
    HANDLE app = (HANDLE)(ULONG_PTR)_wcstoui64(handle_text, NULL, 10);
    const wchar_t *snapshot = option_value(argc, argv, L"--snapshot");
    int run = run_index(argc, argv);
    if (app == NULL || snapshot == NULL || run >= argc) return 2;

    if (WaitForSingleObject(app, INFINITE) != WAIT_OBJECT_0) return 3;
    CloseHandle(app);

    /* A clean exit restored the proxy and deleted the snapshot: nothing to do. */
    if (GetFileAttributesW(snapshot) == INVALID_FILE_ATTRIBUTES) return 0;

    Buffer command = {0};
    for (int i = run; i < argc; i++) {
        if (!append_argument(&command, argv[i])) return 4;
    }
    HANDLE restore = start_process(command.text, NULL);
    free(command.text);
    if (restore == NULL) return 5;
    WaitForSingleObject(restore, RESTORE_WAIT_MS);
    CloseHandle(restore);
    return 0;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR line, int show) {
    (void)instance;
    (void)previous;
    (void)line;
    (void)show;

    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) return 1;

    int result;
    const wchar_t *handle_text = option_value(argc, argv, L"--handle");
    const wchar_t *pid_text = option_value(argc, argv, L"--pid");
    if (handle_text != NULL) {
        result = wait_and_restore(argc, argv, handle_text);
    } else if (pid_text != NULL) {
        result = launch_waiter(argc, argv, pid_text);
    } else {
        result = 1;
    }
    LocalFree(argv);
    return result;
}
