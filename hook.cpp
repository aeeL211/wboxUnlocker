#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <signal.h>
#include <ucontext.h>
#include <android/log.h>
#include "save_data.h"

#define LOG_TAG "WBoxHack"
#define ARM64_MOV_W0_1 0x52800020
#define ARM64_NOP 0xD503201F

FILE* gLog = nullptr;
char gAppDir[256] = {0};
size_t gPageSize = 0;

// log output ke logcat dan file
static void printLog(const char* fmt, ...) {
  va_list args, fargs;
  va_start(args, fmt);
  va_copy(fargs, args);

  //__android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, args);
  if (gLog) {
    vfprintf(gLog, fmt, fargs);
    fprintf(gLog, "\n");
    fflush(gLog);
  }

  va_end(fargs);
  va_end(args);
}

// cegah silent crash
void onCrash(int sig, siginfo_t* info, void* ctx) {
  ucontext_t* uc = (ucontext_t*)ctx;
  uintptr_t pc = uc->uc_mcontext.pc;

  printLog("\n[!] Fatal Crash Detected");
  printLog(" |  Signal: %d", sig);
  printLog(" |  PC: %p", (void*)pc);
  printLog(" |  Fault Addr: %p", info->si_addr);

  if (gLog) {
    fclose(gLog);
    gLog = nullptr;
  }

  signal(sig, SIG_DFL);
  raise(sig);
}

void initCrash() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = onCrash;

  sigaction(SIGSEGV, &sa, nullptr);
  sigaction(SIGBUS, &sa, nullptr);
  sigaction(SIGILL, &sa, nullptr);
  sigaction(SIGABRT, &sa, nullptr);
  sigaction(SIGFPE, &sa, nullptr);
}

// setup file
void initLog() {
  char pkg[128] = "com.mkarpenko.worldbox";
  FILE* cmd = fopen("/proc/self/cmdline", "r");
  if (cmd) {
    fgets(pkg, sizeof(pkg), cmd);
    fclose(cmd);
  }

  snprintf(gAppDir, sizeof(gAppDir), "/sdcard/Android/data/%s/files", pkg);
  mkdir(gAppDir, 0777);

  char modsDir[300];
  snprintf(modsDir, sizeof(modsDir), "%s/mods", gAppDir);
  mkdir(modsDir, 0777);

  char logPath[350];
  snprintf(logPath, sizeof(logPath), "%s/log.txt", modsDir);

  gLog = fopen(logPath, "w");
}

// inject save data kalo belum
void writeSave() {
  if (!gAppDir[0]) return;

  char save[350];
  snprintf(save, sizeof(save), "%s/worldboxProgress", gAppDir);

  // Jangan overwrite save yang sudah ada.
  if (access(save, F_OK) == 0) {
    printLog("[*] Save file already exists. Skipping.");
    return;
  }

  FILE* f = fopen(save, "w");
  if (f) {
    fputs(SAVE_DATA, f);
    fflush(f);
    fclose(f);

    printLog("[+] Save file injected successfully.");
  } else {
    printLog("[-] Failed to write save file.");
  }
}

struct PatchDef {
  const char* pat;
  const char* mask;
  int type;
};

// credit: carunocat
const PatchDef PATCHES[] = {
  {"\x48\x00\x00\x35\x58\xF5\x7D\x97\x00\x00\x00\x00\x0A\x00\x00\x14\x68\x23\x00\x90", "xxxxxxxx????xxxxxxxx", 2},
  {"\x60\x13\x80\x52\xE1\x03\x1F\xAA\x00\x00\x00\x00\xA0\x02\x40\xF9\x08\xE0\x40\xB9", "xxxxxxxx????xxxxxxxx", 2},
  {"\x48\x00\x00\x35\xE0\xE4\x7D\x97\x00\x00\x00\x00\x0A\x00\x00\x14\x48\x23\x00\x90", "xxxxxxxx????xxxxxxxx", 2},
  {"\x80\x13\x80\x52\xE1\x03\x1F\xAA\x00\x00\x00\x00\xA0\x02\x40\xF9\x08\xE0\x40\xB9", "xxxxxxxx????xxxxxxxx", 2},
  {"\x5E\x32\xEB\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\xA0\x00\x00\x36\xF4\x4F\x41\xA9", "xxxxxxxx????xxxxxxxx", 1},
  {"\x1C\x0D\xEB\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x60\x01\x00\x36\xA8\xFD\x00\xB0", "xxxxxxxx????xxxxxxxx", 1},
  {"\x89\x43\xE8\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x80\x02\x00\x36\x58\x10\x01\xF0", "xxxxxxxx????xxxxxxxx", 1},
  {"\x72\x2C\xE7\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x20\x05\x00\x36\x33\x0E\x01\xB0", "xxxxxxxx????xxxxxxxx", 1},
  {"\xB3\xB3\xE0\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x40\x02\x00\x36\x68\x3E\x40\xF9", "xxxxxxxx????xxxxxxxx", 1},
  {"\x5C\xAD\xE0\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\xC0\x09\x00\x36\x80\x22\x40\xF9", "xxxxxxxx????xxxxxxxx", 1},
  {"\x34\x88\xDF\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x00\x07\x00\x37\xF3\xFE\x00\x90", "xxxxxxxx????xxxxxxxx", 1},
  {"\x99\x86\xDF\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\xE0\x01\x00\x36\x18\x01\x00\x34", "xxxxxxxx????xxxxxxxx", 1},
  {"\x91\x86\xDF\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x40\x01\x00\x36\x95\x00\x00\x36", "xxxxxxxx????xxxxxxxx", 1},
  {"\xDE\xF4\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x80\x05\x00\x36\x68\x22\x40\xF9", "xxxxxxxx????xxxxxxxx", 1},
  {"\x3A\xF3\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x40\x09\x00\x37\x75\xE3\x00\xF0", "xxxxxxxx????xxxxxxxx", 1},
  {"\x01\xE1\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x20\x01\x00\x36\x60\x3A\x40\xF9", "xxxxxxxx????xxxxxxxx", 1},
  {"\x96\xDF\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x00\x06\x00\x37\x58\xE3\x00\xD0", "xxxxxxxx????xxxxxxxx", 1},
  {"\x6B\xD5\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\xC0\x0B\x00\x37\x34\xE3\x00\xF0", "xxxxxxxx????xxxxxxxx", 1},
  {"\x2B\xD5\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\xC0\x03\x00\x37\x37\xE3\x00\xF0", "xxxxxxxx????xxxxxxxx", 1},
  {"\xD0\xD4\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x20\x02\x00\x36\x60\x32\x40\xF9", "xxxxxxxx????xxxxxxxx", 1},
  {"\xD6\xD1\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\xE0\x04\x00\x37\x60\x02\x40\xF9", "xxxxxxxx????xxxxxxxx", 1},
  {"\x15\xD1\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\xA0\x00\x00\x36\xF4\x4F\x42\xA9", "xxxxxxxx????xxxxxxxx", 1},
  {"\xB0\xD0\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\xA8\x02\x40\xF9\x08\x5D\x40\xF9", "xxxxxxxx????xxxxxxxx", 1},
  {"\xD7\xAB\xDD\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x80\x03\x00\x36\x35\xFB\x00\xB0", "xxxxxxxx????xxxxxxxx", 1},
  {"\x8D\x4E\xCB\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x20\x02\x00\x36\x14\x05\x00\xB4", "xxxxxxxx????xxxxxxxx", 1},
  {"\xCC\x45\xCB\x97\xE0\x03\x1F\xAA\x00\x00\x00\x00\x20\x02\x00\x36\x14\x05\x00\xB4", "xxxxxxxx????xxxxxxxx", 1},
};

// apply memory patch
bool applyPatch(uintptr_t addr, uint32_t val) {
  uintptr_t pageStart = addr & ~(gPageSize - 1);

  if (mprotect((void*)pageStart, gPageSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    return false;
  }

  *(volatile uint32_t*)addr = val;
  __builtin___clear_cache((char*)addr, (char*)(addr + sizeof(uint32_t)));

  // Kembalikan protection seperti semula.
  mprotect((void*)pageStart, gPageSize, PROT_READ | PROT_EXEC);

  return true;
}

// cari libil2cpp.so di memory
bool getBase(uintptr_t* outBase, size_t* outSize) {
  FILE* fp = fopen("/proc/self/maps", "rt");
  if (!fp) return false;

  char line[512];
  uintptr_t bestBase = 0;
  size_t bestSize = 0;

  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "libil2cpp.so") && strstr(line, "r-xp")) {
      uintptr_t start, end;
      if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
        size_t sz = end - start;
        if (sz > bestSize) {
          bestSize = sz;
          bestBase = start;
        }
      }
    }
  }

  fclose(fp);

  if (bestBase != 0 && bestSize > 0x100000) {
    *outBase = bestBase;
    *outSize = bestSize;
    return true;
  }

  return false;
}

// pattern scan memory block
uintptr_t scan(uintptr_t base, size_t size, const char* pat, const char* mask) {
  size_t len = strlen(mask);
  if (size < len) return 0;

  const uint8_t* mem = (const uint8_t*)base;
  const uint8_t* pattern = (const uint8_t*)pat;

  for (size_t i = 0; i <= size - len; i += 4) {
    if (mem[i] == pattern[0]) {
      bool match = true;

      for (size_t j = 1; j < len; j++) {
        if (mask[j] != '?' && pattern[j] != mem[i + j]) {
          match = false;
          break;
        }
      }

      if (match) return base + i;
    }
  }

  return 0;
}

void* modThread(void*) {
  gPageSize = sysconf(_SC_PAGESIZE);
  initCrash();
  initLog();

  printLog("WorldBox Mod Initialized");
  writeSave();

  printLog("[*] Waiting for libil2cpp.so...");

  uintptr_t base = 0;
  size_t size = 0;

  while (!getBase(&base, &size)) {
    usleep(200000);
  }

  printLog("[+] Engine Loaded");
  printLog(" |  Base: %p", (void*)base);
  printLog(" |  Size: %.2f MB", size / 1048576.0);

  // Beri IL2CPP waktu menyelesaikan startup.
  usleep(1000000);

  printLog("[*] Starting Memory Scan...");

  size_t total = sizeof(PATCHES) / sizeof(PatchDef);
  size_t applied = 0;

  for (size_t i = 0; i < total; ++i) {
    uintptr_t addr = scan(base, size, PATCHES[i].pat, PATCHES[i].mask);

    if (addr) {
      uintptr_t targetAddr = addr + 8;
      uint32_t val = (PATCHES[i].type == 1) ? ARM64_MOV_W0_1 : ARM64_NOP;

      if (applyPatch(targetAddr, val)) {
        printLog("[+] Patch %02zu Applied | Offset: 0x%lX", i + 1, targetAddr - base);
        applied++;
      } else {
        printLog("[-] Patch %02zu Failed  | Offset: 0x%lX", i + 1, targetAddr - base);
      }
    } else {
      printLog("[-] Patch %02zu Missing | Pattern Not Found", i + 1);
    }
  }

  printLog("Scan Complete: %zu/%zu Patches Applied", applied, total);

  if (gLog) {
    fclose(gLog);
    gLog = nullptr;
  }

  return nullptr;
}

__attribute__((constructor))
void init() {
  pthread_t pt;
  pthread_create(&pt, nullptr, modThread, nullptr);
  pthread_detach(pt);
}
