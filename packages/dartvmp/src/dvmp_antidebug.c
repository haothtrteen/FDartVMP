/*
 * dvmp_antidebug.c - instrumentation detection and process hardening.
 *
 * WHAT THIS IS
 * ------------
 * A speed bump. Every check here can be defeated by an attacker who is willing
 * to patch the shared object, and the Frida/server signatures go stale with
 * every release. It exists because the interpreter necessarily has a window in
 * which the bytecode is plaintext in memory, and the cheap attacks against
 * that window (attach gdb, `frida -U -f`, dump the heap) should fail.
 *
 * WHAT THIS IS NOT
 * ----------------
 * A substitute for the other layers. In particular there is no kernel-level
 * detection (a debugger under a hypervisor, or on a rooted device with a
 * patched ptrace, is invisible to us). The environment escape hatch below is a
 * deliberate concession to legitimate profilers, and it is compiled out of any
 * build without the diagnostic probes - so it exists in the test library and in
 * debug builds, and not in a shipped one.
 *
 * Enable with -DDVMP_ANTIDEBUG=ON (see CMakeLists.txt). It is off by default so
 * that a developer running `flutter run --profile` is not shot in the foot.
 */
#include "dvmp_internal.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(__ANDROID__) || defined(__linux__)
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

static char g_reason[128];
/* Set only by vmp_antidebug_force(), i.e. only in a diagnostics build. */
static int g_forced;

const char *vmp_instrumentation_reason(void) {
  return g_reason[0] != '\0' ? g_reason : "none";
}

/*
 * The reason a positive verdict is consumed rather than acted on directly.
 *
 * `vmp_is_instrumented()` answers a question; what to *do* about it is a policy
 * decision that belongs to the layer that can see the consequences. The one thing the
 * runtime must not do is change what a protected function computes, so the default
 * reaction (see dartvmp_init_locked and dvmp_code_ensure) narrows the plaintext window
 * and nothing else. Refusing to run at all is available, but it is opt-in, because a
 * false positive there is an application that will not start.
 */

static int vmp_report(const char *reason) {
  /* Keep the first (most specific) reason; later checks are usually cascade
   * artifacts of the same instrumentation. */
  if (g_reason[0] == '\0') {
    size_t n = strlen(reason);
    if (n >= sizeof(g_reason)) n = sizeof(g_reason) - 1;
    memcpy(g_reason, reason, n);
    g_reason[n] = '\0';
  }
  return 1;
}

/*
 * Escape hatch used by the test suite and by `flutter run --profile`.
 *
 * COMPILED OUT OF RELEASE BUILDS, and that is not a detail. `DARTVMP_NO_ANTIDEBUG`
 * used to be a runtime-only check, which made the entire anti-debug layer optional
 * from the shell: `DARTVMP_NO_ANTIDEBUG=1 ./app` disabled it, and `strings
 * libdartvmp.so | grep DARTVMP_NO` disclosed the name. An environment gate that a
 * one-line `export` defeats is not a gate, so in a build without the diagnostic
 * probes (which is what the Android plugin ships, and what a release build of any
 * embedding should produce) this returns 0 unconditionally and the name is not
 * referenced at all.
 */
static int vmp_antidebug_disabled(void) {
#if defined(DVMP_DIAGNOSTICS)
  const char *v = getenv("DARTVMP_NO_ANTIDEBUG");
  return v != NULL && v[0] != '\0' && v[0] != '0';
#else
  /* No escape hatch in a release build: see above. */
  return 0;
#endif
}

/* ------------------------------------------------------------------ */

#if defined(__ANDROID__) || defined(__linux__)

/*
 * PTRACE_TRACEME fails with EPERM when somebody is already tracing this
 * process. Successful calls leave us traced by our own parent, so the check is
 * only meaningful as a probe - we never keep the tracing relationship.
 */
static int vmp_check_ptrace(void) {
  /* Reading /proc/self/status avoids the side effect of actually calling
   * ptrace(), which some Android SELinux policies deny outright and which
   * would give a false positive on those devices. */
  FILE *f = fopen("/proc/self/status", "r");
  if (f == NULL) return 0;
  char line[256];
  int traced = 0;
  while (fgets(line, sizeof(line), f) != NULL) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
      long pid = strtol(line + 10, NULL, 10);
      if (pid > 0) traced = 1;
      break;
    }
  }
  fclose(f);
  return traced ? vmp_report("TracerPid is non-zero (ptrace attached)") : 0;
}

/*
 * Scans the process mapping table for the well-known injection artifacts. A
 * real deployment should hash-map the known-good library list and flag
 * *anything* unexpected; the signature list below is the cheap approximation
 * used by the demo.
 */
static int vmp_check_maps(void) {
  static const char *kBad[] = {
      "frida", "gum-js-loop", "gmain", "gadget", "substrate", "cynject",
      "libhook", "xposed", "magisk", "riru", "edxposed", "re.frida",
  };
  FILE *f = fopen("/proc/self/maps", "r");
  if (f == NULL) return 0;
  char line[512];
  int found = 0;
  while (!found && fgets(line, sizeof(line), f) != NULL) {
    for (size_t i = 0; i < sizeof(kBad) / sizeof(kBad[0]); i++) {
      if (strstr(line, kBad[i]) != NULL) {
        char buf[128];
        snprintf(buf, sizeof(buf), "instrumentation library mapped: %s",
                 kBad[i]);
        vmp_report(buf);
        found = 1;
        break;
      }
    }
  }
  fclose(f);
  return found;
}

/* Frida's default listener. Connecting to a port we control is harmless; a
 * successful connect means somebody else is already there. */
static int vmp_check_frida_port(void) {
  static const int kPorts[] = {27042, 27043};
  for (size_t i = 0; i < sizeof(kPorts) / sizeof(kPorts[0]); i++) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) continue;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)kPorts[i]);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    int r = connect(s, (struct sockaddr *)&a, sizeof(a));
    close(s);
    if (r == 0) {
      char buf[96];
      snprintf(buf, sizeof(buf), "frida control port %d is open", kPorts[i]);
      return vmp_report(buf);
    }
  }
  return 0;
}

/* Hardening that is not a detection: make this process undumpable so an
 * attached debugger cannot read our memory without CAP_SYS_PTRACE. */
static void vmp_harden_process(void) {
  /* PR_SET_DUMPABLE = 4 */
  ptrace(0x4 /* PR_SET_DUMPABLE */, 0, 0, 0);
}

int vmp_is_instrumented(void) {
  if (g_forced) return 1;
  if (vmp_antidebug_disabled()) {
    return 0;
  }
  vmp_harden_process();
  if (vmp_check_ptrace()) return 1;
  if (vmp_check_maps()) return 1;
  if (vmp_check_frida_port()) return 1;
  return 0;
}

#elif defined(_WIN32)

int vmp_is_instrumented(void) {
  if (g_forced) return 1;
  if (vmp_antidebug_disabled()) {
    return 0;
  }
  if (IsDebuggerPresent()) {
    return vmp_report("IsDebuggerPresent()");
  }
  BOOL remote = FALSE;
  if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
    return vmp_report("CheckRemoteDebuggerPresent()");
  }
  /* A hardware breakpoint registers check: DR0..DR3 non-zero while no
   * debugger is "present" means somebody set a breakpoint and detached. */
  CONTEXT ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (GetThreadContext(GetCurrentThread(), &ctx)) {
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
      return vmp_report("hardware breakpoint register is set");
    }
  }
  return 0;
}

#else

int vmp_is_instrumented(void) { return g_forced ? 1 : 0; }

#endif

#if defined(DVMP_DIAGNOSTICS)
/*
 * Force the verdict so the reaction to detection can be tested.
 *
 * The shipping reaction is a *narrower plaintext window*, not a refusal (see
 * dartvmp_init_locked), and it is only reachable when something is really attached -
 * which a test suite cannot arrange. Without this hook that path would be unverified
 * code whose only exercise is in the field, which is the worst place to find out it is
 * wrong.
 */
void vmp_antidebug_force(int on, const char *reason) {
  g_forced = on ? 1 : 0;
  if (on) {
    (void)vmp_report(reason != NULL ? reason : "forced by the test suite");
  } else {
    g_reason[0] = '\0';
  }
}
#else
/* Not `static`: the declaration in dvmp_internal.h is unconditional, and silently
 * dropping the definition here would turn a diagnostics-only call into a link error in
 * a release build rather than a compile-time one. A no-op definition keeps the release
 * binary honest - the exported symbol does not exist either way, because this whole
 * block sits behind the same switch the probes do. */
void vmp_antidebug_force(int on, const char *reason) {
  (void)on;
  (void)reason;
}
#endif
