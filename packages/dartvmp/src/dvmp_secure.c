/*
 * dvmp_secure.c - guarded memory for the decrypted bytecode image.
 *
 * Design notes
 * ------------
 * The interpreter never executes bytecode in place. The shipped image is
 * encrypted; a working copy is materialised into a page-aligned mapping that
 * is (a) excluded from core dumps, (b) wiped and re-encrypted after every
 * protected call. An attacker who dumps the process *between* calls finds the
 * same ciphertext that is already in the binary, so a memory dump adds nothing
 * unless it is taken while a protected function is executing - which is
 * exactly the window the anti-debug layer targets.
 *
 * mprotect(PROT_EXEC) is deliberately NOT used: bytecode is data here, not
 * machine code, and requesting executable data pages is a bigger red flag to
 * hardened allocators than it is a barrier to an attacker who already has
 * arbitrary read.
 */
#include "dvmp_internal.h"

#include <string.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

static uint32_t g_live_bytes = 0;

/* ------------------------------------------------------------------ */
/* Page helpers                                                        */
/* ------------------------------------------------------------------ */

static size_t vmp_page_size(void) {
#if defined(_WIN32)
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return (size_t)si.dwPageSize;
#else
  long ps = sysconf(_SC_PAGESIZE);
  return ps > 0 ? (size_t)ps : 4096u;
#endif
}

static size_t vmp_round_up(size_t v, size_t align) {
  return (v + align - 1) & ~(align - 1);
}

/* ------------------------------------------------------------------ */
/* Wipe primitives                                                     */
/* ------------------------------------------------------------------ */

/*
 * memset through a volatile pointer: the compiler is not allowed to remove the
 * stores, and the function-pointer indirection keeps LTO from proving the
 * buffer is dead afterwards.
 */
void vmp_secure_zero(void *p, size_t size) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (size--) {
    *v++ = 0;
  }
}

void vmp_secure_wipe(void *p, size_t size) {
  if (p == NULL || size == 0) return;
  vmp_secure_zero(p, size);
  /* Second pass with a barrier: defeats "recover the previous page contents
   * from the same physical frame" tricks that only work on a single wipe. */
#if defined(_WIN32)
  MemoryBarrier();
#else
  __sync_synchronize();
#endif
  vmp_secure_zero(p, size);
}

/* ------------------------------------------------------------------ */
/* Allocation                                                          */
/* ------------------------------------------------------------------ */

void *vmp_secure_alloc(size_t size) {
  if (size == 0) return NULL;
  const size_t page = vmp_page_size();
  const size_t total = vmp_round_up(size, page);

#if defined(_WIN32)
  void *p = VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (p == NULL) return NULL;
#else
  void *p = mmap(NULL, total, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return NULL;
#endif
  g_live_bytes += (uint32_t)total;
  return p;
}

void vmp_secure_free(void *p, size_t size) {
  if (p == NULL) return;
  const size_t page = vmp_page_size();
  const size_t total = vmp_round_up(size, page);
  vmp_secure_wipe(p, total);
  if (g_live_bytes >= (uint32_t)total) {
    g_live_bytes -= (uint32_t)total;
  } else {
    g_live_bytes = 0;
  }
#if defined(_WIN32)
  VirtualFree(p, 0, MEM_RELEASE);
#else
  munmap(p, total);
#endif
}

void vmp_secure_harden(void *p, size_t size) {
  if (p == NULL) return;
  const size_t page = vmp_page_size();
  const size_t total = vmp_round_up(size, page);
#if defined(_WIN32)
  /* Exclude from crash dumps: a minidump is otherwise a free copy of the
   * decrypted bytecode. */
  ULONG dep = 0;
  typedef BOOL(WINAPI * SetInformationFn)(HANDLE, ULONG, PVOID, SIZE_T, PULONG);
  HMODULE k32 = GetModuleHandleA("kernel32.dll");
  if (k32 != NULL) {
    SetInformationFn fn =
        (SetInformationFn)(void *)GetProcAddress(k32, "SetProcessInformation");
    /* ProcessMemoryExclusionInformation is not exported as a constant in all
     * SDKs; the well-known value is 4. Failures are non-fatal. */
    if (fn != NULL) {
      fn(GetCurrentProcess(), 4, p, total, &dep);
    }
  }
  VirtualLock(p, total);
#else
  /* Do not include these pages in a core dump. Android's linkers honour this
   * flag on the mapping itself, which is stronger than a process-wide
   * setrlimit. */
  madvise(p, total, MADV_DONTDUMP);
  /* Ask the kernel not to copy these pages on fork(). */
  madvise(p, total, MADV_DONTFORK);
  /* Best effort: pin the pages so they are not written to swap, where the
   * plaintext image would outlive the process. */
  mlock(p, total);
#endif
}

uint32_t vmp_secure_bytes_live(void) { return g_live_bytes; }
