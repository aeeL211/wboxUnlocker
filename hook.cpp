// wboxUnlocker - WorldBox 0.51.4 (Unity 2022.3.62f3, arm64-v8a)
//
// Runtime IL2CPP hooking, no save-file injection and no AOB patch list.
//
// Strategy:
//   1. Locate the shared premium/entitlement helper by its prologue signature
//      and force it to return true. This replaces the old 22 "mov w0,#1"
//      patches and does not depend on any IL2CPP API export.
//   2. Resolve the obfuscated IL2CPP API exports from libil2cpp.so by name.
//   3. Decode each exported wrapper to the internal implementation it calls.
//   4. Attach this thread to IL2CPP, enumerate InAppManager / GameProgress /
//      GameProgressData at runtime, log every field and method, and install
//      generic true-return hooks on bool methods whose names look like
//      premium/progress checks. Method names are encrypted in the metadata
//      file, so runtime enumeration is the only reliable source of names.

#include <android/log.h>
#include <ctype.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <ucontext.h>
#include <unistd.h>

#include "shadowhook.h"

#if !defined(__aarch64__)
#error "wboxUnlocker supports arm64-v8a only"
#endif

#define LOG_TAG "WBoxHack"

#define ARM64_BRANCH_MASK 0xFC000000u
#define ARM64_B 0x14000000u
#define ARM64_BL 0x94000000u
#define ARM64_RET 0xD65F03C0u

#define MAX_EXEC_RANGES 8
#define MAX_HOOKED_ADDRS 1024

// MethodInfo / FieldInfo offsets for Unity 2022.3 IL2CPP (arm64).
#define MI_METHOD_POINTER 0x00
#define MI_VIRTUAL_METHOD_POINTER 0x08
#define MI_NAME 0x18
#define MI_RETURN_TYPE 0x28
#define MI_FLAGS 0x4C
#define MI_PARAM_COUNT 0x52

#define FI_NAME 0x00
#define FI_TYPE 0x08
#define FI_OFFSET 0x18

#define IL2CPP_TYPE_BOOLEAN 2
#define METHOD_ATTRIBUTE_STATIC 0x0010

static FILE* gLog = nullptr;
static char gAppDir[256] = {0};

// ---------------------------------------------------------------------------
// Logging / crash handling
// ---------------------------------------------------------------------------

static void printLog(const char* fmt, ...) {
  va_list argsLogcat, argsFile, argsAndroid;
  va_start(argsLogcat, fmt);
  va_copy(argsFile, argsLogcat);
  va_copy(argsAndroid, argsLogcat);

  __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, argsAndroid);

  if (gLog) {
    vfprintf(gLog, fmt, argsFile);
    fputc('\n', gLog);
    fflush(gLog);
  }

  va_end(argsAndroid);
  va_end(argsFile);
  va_end(argsLogcat);
}

static void onCrash(int sig, siginfo_t* info, void* ctx) {
  ucontext_t* uc = (ucontext_t*)ctx;
  uintptr_t pc = uc ? (uintptr_t)uc->uc_mcontext.pc : 0;

  printLog("[!] Fatal signal %d at pc=%p fault=%p", sig, (void*)pc,
           info ? info->si_addr : nullptr);

  if (gLog) {
    fclose(gLog);
    gLog = nullptr;
  }

  signal(sig, SIG_DFL);
  raise(sig);
}

static void initCrash() {
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

static void initLog() {
  char pkg[128] = "com.mkarpenko.worldbox";
  FILE* cmd = fopen("/proc/self/cmdline", "rb");
  if (cmd) {
    size_t n = fread(pkg, 1, sizeof(pkg) - 1, cmd);
    if (n > 0) pkg[n] = '\0';
    fclose(cmd);

    char* colon = strchr(pkg, ':');
    if (colon) *colon = '\0';
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

// ---------------------------------------------------------------------------
// Module / helper discovery
// ---------------------------------------------------------------------------

struct ExecRange {
  uintptr_t start;
  size_t size;
};

struct ModuleInfo {
  uintptr_t base;
  const Elf64_Phdr* phdrs;
  int phnum;
  int rangeCount;
  bool found;
  ExecRange ranges[MAX_EXEC_RANGES];
};

static int moduleCallback(struct dl_phdr_info* info, size_t size, void* data) {
  (void)size;
  if (!info->dlpi_name || !strstr(info->dlpi_name, "libil2cpp.so")) return 0;

  ModuleInfo* mod = (ModuleInfo*)data;
  mod->base = (uintptr_t)info->dlpi_addr;
  mod->phdrs = info->dlpi_phdr;
  mod->phnum = info->dlpi_phnum;
  mod->rangeCount = 0;

  for (int i = 0; i < info->dlpi_phnum && mod->rangeCount < MAX_EXEC_RANGES; ++i) {
    const Elf64_Phdr* ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_LOAD) continue;
    if ((ph->p_flags & (PF_R | PF_X)) != (PF_R | PF_X)) continue;

    mod->ranges[mod->rangeCount].start = mod->base + (uintptr_t)ph->p_vaddr;
    mod->ranges[mod->rangeCount].size = (size_t)ph->p_memsz;
    mod->rangeCount++;
  }

  mod->found = true;
  return 1;
}

static bool getModuleInfo(ModuleInfo* out) {
  memset(out, 0, sizeof(*out));
  dl_iterate_phdr(moduleCallback, out);
  return out->found && out->rangeCount > 0;
}

// Resolve an exported symbol from the in-memory ELF dynamic symbol table.
//
// dlsym() would only see libil2cpp.so if the linker namespace of this library
// is the same as the namespace that loaded the game. Parsing the module's own
// .dynsym avoids that dependency entirely. libil2cpp.so has DT_HASH, so its
// nchain field gives the exact symbol count.
static uintptr_t findExport(const ModuleInfo& mod, const char* name) {
  const Elf64_Dyn* dynamic = nullptr;
  for (int i = 0; i < mod.phnum; ++i) {
    if (mod.phdrs[i].p_type == PT_DYNAMIC) {
      dynamic = (const Elf64_Dyn*)(mod.base + (uintptr_t)mod.phdrs[i].p_vaddr);
      break;
    }
  }
  if (!dynamic) return 0;

  const Elf64_Sym* symtab = nullptr;
  const char* strtab = nullptr;
  size_t symbolCount = 0;

  for (const Elf64_Dyn* d = dynamic; d->d_tag != DT_NULL; ++d) {
    switch (d->d_tag) {
      case DT_SYMTAB:
        symtab = (const Elf64_Sym*)(mod.base + (uintptr_t)d->d_un.d_ptr);
        break;
      case DT_STRTAB:
        strtab = (const char*)(mod.base + (uintptr_t)d->d_un.d_ptr);
        break;
      case DT_HASH:
        symbolCount = ((const uint32_t*)(mod.base + (uintptr_t)d->d_un.d_ptr))[1];
        break;
      default:
        break;
    }
  }

  if (!symtab || !strtab || symbolCount == 0) return 0;

  for (size_t i = 0; i < symbolCount; ++i) {
    const Elf64_Sym* sym = &symtab[i];
    if (sym->st_shndx == SHN_UNDEF || sym->st_value == 0) continue;
    if (strcmp(strtab + sym->st_name, name) != 0) continue;
    return mod.base + (uintptr_t)sym->st_value;
  }

  return 0;
}

// Prologue of the shared entitlement helper at libil2cpp+0x1d9f318.
// This 16-byte sequence is unique in the executable segments of this build.
static const uint8_t kHelperSignature[16] = {
    0xFE, 0x0F, 0x1E, 0xF8, 0xF4, 0x4F, 0x01, 0xA9,
    0xF3, 0x1A, 0x01, 0xD0, 0x68, 0x1E, 0x69, 0x39,
};

static uintptr_t findHelper(const ModuleInfo& mod) {
  for (int i = 0; i < mod.rangeCount; ++i) {
    uintptr_t start = mod.ranges[i].start;
    size_t size = mod.ranges[i].size;
    if (size < sizeof(kHelperSignature)) continue;

    uintptr_t end = start + size - sizeof(kHelperSignature);
    for (uintptr_t p = start; p <= end; p += 4) {
      if (*(const uint32_t*)p != 0xF81E0FFEu) continue;
      if (memcmp((const void*)p, kHelperSignature, sizeof(kHelperSignature)) == 0) return p;
    }
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Obfuscated IL2CPP export resolution
// ---------------------------------------------------------------------------

static uintptr_t branchTarget(uintptr_t pc, uint32_t insn) {
  int32_t imm = (int32_t)(insn & 0x03FFFFFFu);
  if (imm & 0x02000000) imm |= (int32_t)0xFC000000u;
  return pc + ((intptr_t)imm << 2);
}

// Exported API wrappers either start with an unconditional "b impl" or call
// the real implementation with the last b/bl before the first "ret".
static uintptr_t decodeImpl(void* wrapper) {
  const uint32_t* code = (const uint32_t*)wrapper;
  uint32_t first = code[0];
  if ((first & ARM64_BRANCH_MASK) == ARM64_B) return branchTarget((uintptr_t)wrapper, first);

  uintptr_t lastBranch = 0;
  for (int i = 0; i < 256; ++i) {
    uint32_t insn = code[i];
    if (insn == ARM64_RET) return lastBranch;

    uint32_t op = insn & ARM64_BRANCH_MASK;
    if (op == ARM64_B || op == ARM64_BL)
      lastBranch = branchTarget((uintptr_t)wrapper + (uintptr_t)(i * 4), insn);
  }

  return 0;
}

typedef void* (*FnDomainGet)();
typedef uintptr_t (*FnGetAssemblies)();
typedef void* (*FnAssemblyGetImage)(void* assembly);
typedef void* (*FnClassFromName)(void* image, const char* ns, const char* name);
typedef void* (*FnClassGetMethods)(void* klass, void** iter);
typedef void* (*FnClassGetFields)(void* klass, void** iter);
typedef const char* (*FnClassGetName)(void* klass);
typedef const char* (*FnClassGetNamespace)(void* klass);
typedef void* (*FnThreadAttach)(void* domain);

struct Api {
  FnDomainGet domainGet;
  FnGetAssemblies getAssemblies;
  FnAssemblyGetImage assemblyGetImage;
  FnClassFromName classFromName;
  FnClassGetMethods classGetMethods;
  FnClassGetFields classGetFields;
  FnClassGetName classGetName;
  FnClassGetNamespace classGetNamespace;
  FnThreadAttach threadAttach;
};

#define RESOLVE_FN(api, mod, field, exportName)                                         \
  do {                                                                                  \
    uintptr_t wrapper = findExport((mod), (exportName));                                \
    if (!wrapper) {                                                                     \
      printLog("[-] Export %s not found in libil2cpp.so", (exportName));                \
      return false;                                                                     \
    }                                                                                   \
    uintptr_t impl = decodeImpl((void*)wrapper);                                        \
    if (!impl) {                                                                        \
      printLog("[-] Failed to decode %s wrapper at %p", (exportName),                   \
               (void*)wrapper);                                                         \
      return false;                                                                     \
    }                                                                                   \
    (api)->field = reinterpret_cast<decltype(api->field)>(impl);                        \
    printLog("[+] %-32s wrapper=%p impl=%p", (exportName), (void*)wrapper, (void*)impl);\
  } while (0)

static bool resolveApi(Api* api, const ModuleInfo& mod) {
  memset(api, 0, sizeof(*api));

  RESOLVE_FN(api, mod, domainGet, "iUqUtAUwkbd");
  RESOLVE_FN(api, mod, getAssemblies, "ldkfDlkuaXr");
  RESOLVE_FN(api, mod, assemblyGetImage, "fOMMoGNvCOU");
  RESOLVE_FN(api, mod, classFromName, "IvObYcSoisk");
  RESOLVE_FN(api, mod, classGetMethods, "HKlFxqYmbNu");
  RESOLVE_FN(api, mod, classGetFields, "btiIyPIMoID");
  RESOLVE_FN(api, mod, classGetName, "QiGvzgo_gmf");
  RESOLVE_FN(api, mod, classGetNamespace, "Ebkjpdi_PKY");
  RESOLVE_FN(api, mod, threadAttach, "koTSjtQiflq");

  return true;
}

// ---------------------------------------------------------------------------
// IL2CPP metadata enumeration
// ---------------------------------------------------------------------------

struct AssemblyVector {
  uintptr_t begin;
  uintptr_t end;
};

static bool readAssemblies(const Api& api, AssemblyVector* out) {
  uintptr_t vec = api.getAssemblies();
  if (!vec) return false;

  uintptr_t begin = *(uintptr_t*)(vec + 0);
  uintptr_t end = *(uintptr_t*)(vec + 8);
  if (!begin || end <= begin) return false;

  size_t bytes = (size_t)(end - begin);
  if ((bytes & 7u) != 0 || bytes > 8192u * sizeof(void*)) return false;

  out->begin = begin;
  out->end = end;
  return true;
}

static bool waitForAssemblies(const Api& api, size_t* outCount) {
  int stable = 0;

  for (;;) {
    AssemblyVector vec;
    if (readAssemblies(api, &vec)) {
      stable++;
      if (stable >= 10) {
        *outCount = (size_t)(vec.end - vec.begin) / sizeof(void*);
        return true;
      }
    } else {
      stable = 0;
    }
    usleep(200000);
  }
}

static void* findClass(const Api& api, const char* className, char* imageNameOut,
                       size_t imageNameOutSize) {
  AssemblyVector vec;
  if (!readAssemblies(api, &vec)) return nullptr;

  size_t count = (size_t)(vec.end - vec.begin) / sizeof(void*);
  for (size_t i = 0; i < count; ++i) {
    void* assembly = *(void**)(vec.begin + i * sizeof(void*));
    if (!assembly) continue;

    void* image = api.assemblyGetImage(assembly);
    if (!image) continue;

    const char* imageName = *(const char**)((const char*)image + 0);
    void* klass = api.classFromName(image, "", className);
    if (!klass) continue;

    if (imageNameOut && imageNameOutSize)
      snprintf(imageNameOut, imageNameOutSize, "%s", imageName ? imageName : "?");
    return klass;
  }

  return nullptr;
}

static bool ciContains(const char* haystack, const char* needle) {
  if (!haystack || !needle) return false;

  size_t needleLen = strlen(needle);
  if (needleLen == 0) return true;

  for (const char* p = haystack; *p; ++p) {
    size_t i = 0;
    while (i < needleLen && p[i] &&
           tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
      ++i;
    if (i == needleLen) return true;
  }

  return false;
}

static bool isPremiumMethod(const char* name) {
  return ciContains(name, "premium") || ciContains(name, "purchas") ||
         ciContains(name, "subscri") || ciContains(name, "entitle") ||
         ciContains(name, "adfree") || ciContains(name, "no_ads") ||
         ciContains(name, "noads") || ciContains(name, "buy") ||
         ciContains(name, "owned") || ciContains(name, "unlock");
}

static bool isProgressMethod(const char* name) {
  return ciContains(name, "unlock") || ciContains(name, "achiev") ||
         ciContains(name, "complet") || ciContains(name, "trait") ||
         ciContains(name, "owned") || ciContains(name, "discovered") ||
         ciContains(name, "collected") || ciContains(name, "reached") ||
         ciContains(name, "avail") || ciContains(name, "grant") ||
         ciContains(name, "earn");
}

// ---------------------------------------------------------------------------
// ShadowHook hooks
// ---------------------------------------------------------------------------

static uintptr_t gHookedAddrs[MAX_HOOKED_ADDRS];
static size_t gHookedCount = 0;
static bool gShadowHookReady = false;

static bool alreadyHooked(uintptr_t addr) {
  for (size_t i = 0; i < gHookedCount; ++i)
    if (gHookedAddrs[i] == addr) return true;
  return false;
}

static void rememberHooked(uintptr_t addr) {
  if (gHookedCount < MAX_HOOKED_ADDRS) gHookedAddrs[gHookedCount++] = addr;
}

// Any method returning bool can be routed here; unused arguments are ignored.
static bool returnTrue(void*) {
  return true;
}

// Last-resort fallback for the entitlement helper if ShadowHook itself cannot
// initialize or cannot place an island. This is one function entry, not the
// old 22-site patch list.
static bool patchHelperInline(uintptr_t addr) {
  if (!addr) return false;

  size_t pageSize = (size_t)sysconf(_SC_PAGESIZE);
  uintptr_t page = addr & ~(uintptr_t)(pageSize - 1);

  if (mprotect((void*)page, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    return false;

  // mov w0, #1 ; ret
  const uint32_t code[2] = {0x52800020u, 0xD65F03C0u};
  memcpy((void*)addr, code, sizeof(code));
  __builtin___clear_cache((char*)addr, (char*)(addr + sizeof(code)));

  mprotect((void*)page, pageSize, PROT_READ | PROT_EXEC);
  return true;
}

static bool hookTrue(const char* className, const char* methodName, uintptr_t addr) {
  if (!addr || !gShadowHookReady) return false;

  if (alreadyHooked(addr)) {
    printLog("[=] %s.%s at %p already hooked, skipping", className, methodName,
             (void*)addr);
    return false;
  }

  void* orig = nullptr;
  void* task = shadowhook_hook_func_addr((void*)addr, (void*)returnTrue, &orig);
  if (!task) {
    int err = shadowhook_get_errno();
    printLog("[-] Hook %s.%s at %p failed: %d (%s)", className, methodName, (void*)addr,
             err, shadowhook_to_errmsg(err));
    return false;
  }

  rememberHooked(addr);
  printLog("[+] Hooked %s.%s at %p -> true (orig=%p)", className, methodName,
           (void*)addr, orig);
  return true;
}

// ---------------------------------------------------------------------------
// Class dump / candidate hooks
// ---------------------------------------------------------------------------

static void dumpAndHookClass(const Api& api, void* klass, const char* wantedName,
                             const char* imageName, bool premiumClass) {
  const char* ns = api.classGetNamespace ? api.classGetNamespace(klass) : nullptr;
  const char* realName = api.classGetName ? api.classGetName(klass) : wantedName;

  printLog("[*] %s%s%s (%s)", (ns && *ns) ? ns : "", (ns && *ns) ? "." : "",
           realName ? realName : wantedName, imageName);

  void* iter = nullptr;
  void* field;
  int fieldCount = 0;
  while ((field = api.classGetFields(klass, &iter)) != nullptr) {
    fieldCount++;
    const char* fieldName = *(const char**)((const char*)field + FI_NAME);
    const void* fieldType = *(void**)((const char*)field + FI_TYPE);
    int32_t fieldOffset = *(int32_t*)((const char*)field + FI_OFFSET);
    unsigned typeEnum =
        fieldType ? *(const unsigned char*)((const char*)fieldType + 0xA) : 0xFF;

    printLog("  [F] %-40s type=%u offset/index=0x%x", fieldName ? fieldName : "(null)",
             typeEnum, (unsigned)fieldOffset);
  }

  iter = nullptr;
  void* method;
  int methodCount = 0;
  int hookedCount = 0;
  while ((method = api.classGetMethods(klass, &iter)) != nullptr) {
    methodCount++;

    void* methodPointer = *(void**)((const char*)method + MI_METHOD_POINTER);
    void* virtualMethodPointer = *(void**)((const char*)method + MI_VIRTUAL_METHOD_POINTER);
    const char* methodName = *(const char**)((const char*)method + MI_NAME);
    const void* returnType = *(void**)((const char*)method + MI_RETURN_TYPE);
    uint16_t flags = *(uint16_t*)((const char*)method + MI_FLAGS);
    uint8_t paramCount = *(uint8_t*)((const char*)method + MI_PARAM_COUNT);
    unsigned returnEnum =
        returnType ? *(const unsigned char*)((const char*)returnType + 0xA) : 0xFF;

    printLog("  [M] %p v=%p %-40s ret=%u params=%u flags=0x%x%s", methodPointer,
             virtualMethodPointer, methodName ? methodName : "(null)", returnEnum,
             paramCount, flags, (flags & METHOD_ATTRIBUTE_STATIC) ? " static" : "");

    if (!methodName) continue;
    if (returnEnum != IL2CPP_TYPE_BOOLEAN) continue;

    bool candidate = premiumClass ? isPremiumMethod(methodName) : isProgressMethod(methodName);
    if (!candidate) continue;

    if (methodPointer && hookTrue(wantedName, methodName, (uintptr_t)methodPointer))
      hookedCount++;
    if (virtualMethodPointer && virtualMethodPointer != methodPointer &&
        hookTrue(wantedName, methodName, (uintptr_t)virtualMethodPointer))
      hookedCount++;
  }

  printLog("[*] %s summary: %d fields, %d methods, %d newly hooked", wantedName,
           fieldCount, methodCount, hookedCount);
}

static void* getDomain(const Api& api) {
  for (int i = 0; i < 20; ++i) {
    void* domain = api.domainGet();
    if (domain) return domain;
    usleep(100000);
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

static void* modThread(void*) {
  initCrash();
  initLog();

  printLog("WorldBox runtime unlocker starting");
  printLog("ShadowHook: %s", shadowhook_get_version());

  printLog("[*] Waiting for libil2cpp.so...");
  ModuleInfo mod;
  for (int i = 0;; ++i) {
    if (getModuleInfo(&mod)) break;

    if (i > 0 && (i % 50) == 0) printLog("[*] Still waiting for libil2cpp.so...");
    usleep(200000);
  }
  printLog("[+] libil2cpp base=%p execRanges=%d", (void*)mod.base, mod.rangeCount);

  uintptr_t helper = findHelper(mod);
  if (helper) {
    printLog("[+] Entitlement helper found at %p (offset 0x%lx)", (void*)helper,
             (unsigned long)(helper - mod.base));
  } else {
    printLog("[-] Entitlement helper signature not found; relying on named methods");
  }

  int shInit = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
  gShadowHookReady = (shInit == 0);
  if (!gShadowHookReady) {
    printLog("[-] shadowhook_init failed: %d (%s)", shInit,
             shadowhook_to_errmsg(shInit));
  } else {
    printLog("[+] shadowhook_init ok");
  }

  bool helperHooked = false;
  if (helper && gShadowHookReady) {
    void* orig = nullptr;
    void* task = shadowhook_hook_func_addr((void*)helper, (void*)returnTrue, &orig);
    if (task) {
      rememberHooked(helper);
      helperHooked = true;
      printLog("[+] Entitlement helper hooked -> true (orig=%p)", orig);
    } else {
      int err = shadowhook_get_errno();
      printLog("[-] Entitlement helper hook failed: %d (%s)", err,
               shadowhook_to_errmsg(err));
    }
  }

  if (helper && !helperHooked) {
    if (patchHelperInline(helper)) {
      rememberHooked(helper);
      helperHooked = true;
      printLog("[+] Entitlement helper patched inline -> true");
    } else {
      printLog("[-] Entitlement helper inline patch failed");
    }
  }

  // The helper hook is the primary unlock and does not need any IL2CPP API.
  // Resolve the metadata API afterwards so a renamed export cannot prevent it.
  Api api;
  if (!resolveApi(&api, mod)) {
    printLog("[-] Failed to resolve the IL2CPP API; metadata hooks skipped");
    return nullptr;
  }

  size_t assemblyCount = 0;
  if (!waitForAssemblies(api, &assemblyCount)) return nullptr;
  printLog("[+] IL2CPP assemblies ready: %zu", assemblyCount);

  // Give the runtime a moment to finish publishing class metadata.
  usleep(500000);

  void* domain = getDomain(api);
  if (!domain) {
    printLog("[-] il2cpp_domain_get returned null");
    return nullptr;
  }
  printLog("[+] IL2CPP domain: %p", domain);

  void* attached = nullptr;
  for (int i = 0; i < 50 && !attached; ++i) {
    attached = api.threadAttach(domain);
    if (!attached) usleep(200000);
  }
  if (!attached) {
    printLog("[-] il2cpp_thread_attach failed");
    return nullptr;
  }
  printLog("[+] Thread attached: %p", attached);

  char imageName[256] = {0};

  struct ClassTarget {
    const char* name;
    bool premium;
  };

  const ClassTarget targets[] = {
      {"InAppManager", true},
      {"GameProgress", false},
      {"GameProgressData", false},
  };

  for (const ClassTarget& target : targets) {
    imageName[0] = '\0';
    void* klass = nullptr;
    for (int attempt = 0; attempt < 10 && !klass; ++attempt) {
      klass = findClass(api, target.name, imageName, sizeof(imageName));
      if (!klass) usleep(250000);
    }
    if (!klass) {
      printLog("[-] Class %s not found", target.name);
      continue;
    }

    printLog("[+] Found class %s in %s", target.name,
             imageName[0] ? imageName : "(unknown image)");
    dumpAndHookClass(api, klass, target.name, imageName, target.premium);
  }

  printLog("[*] Hook setup complete");

  // Stay attached for the lifetime of the process. IL2CPP has registered this
  // thread with its runtime; letting it exit without il2cpp_thread_detach()
  // can leave a dangling thread object behind for the GC.
  for (;;) sleep(3600);
}

#ifndef WBOX_NO_CONSTRUCTOR
__attribute__((constructor)) static void init() {
  pthread_t thread;
  if (pthread_create(&thread, nullptr, modThread, nullptr) == 0) pthread_detach(thread);
}
#endif
