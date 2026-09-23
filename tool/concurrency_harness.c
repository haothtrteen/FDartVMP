/*
 * concurrency_harness.c - drives the public ABI from several OS threads at once.
 *
 * The runtime has one module and one interpreter shared by every thread in the
 * process, so overlapping calls must be serialised. This is the check that the
 * serialisation actually exists:
 *
 *   * every thread calls the same protected function with the same arguments and
 *     compares the result against a reference computed before any thread starts,
 *     so a lost update or a torn read shows up as a mismatch rather than as a
 *     flaky pass;
 *   * any non-zero status is reported with its name, because the failure mode
 *     observed without a lock was NOT a crash - it was a wrong answer and a
 *     "module corrupt", which a test that only checks "did it crash" would miss.
 *
 * Built and run by tool/verify_concurrency.ps1.
 *
 * Usage: concurrency.exe [threads] [rounds]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dartvmp.h"

/*
 * Wire-format tag bytes (dvmp_wire.h), declared here rather than pulling in the
 * runtime's internal header: this harness deliberately uses only the public ABI
 * plus the documented wire encoding, so it exercises what a host sees.
 */
#define DVMP_T_STR 0x03
#define DVMP_T_INT 0x02

#if defined(_WIN32)
#include <windows.h>
#define THREAD_RET DWORD WINAPI
#else
#include <pthread.h>
#define THREAD_RET void *
#endif

typedef struct Worker {
  int id;
  int rounds;
  int mismatches;
  int errors;
  char first_bad[64];
  int32_t first_error;
} Worker;

static char g_reference[64];

/*
 * Arguments for `makeLicenseKey(String seed, int counter)`, encoded in call
 * order: the VM's marshaller reads them left to right.
 */
static uint32_t encode_args(uint8_t *out, const char *seed, int64_t counter) {
  uint32_t at = 0;
  const size_t n = strlen(seed);
  out[at++] = DVMP_T_STR;
  out[at++] = (uint8_t)(n & 0xFF);
  out[at++] = (uint8_t)((n >> 8) & 0xFF);
  out[at++] = (uint8_t)((n >> 16) & 0xFF);
  out[at++] = (uint8_t)((n >> 24) & 0xFF);
  memcpy(out + at, seed, n);
  at += (uint32_t)n;

  out[at++] = DVMP_T_INT;
  for (int b = 0; b < 8; b++) {
    out[at++] = (uint8_t)(((uint64_t)counter >> (8 * b)) & 0xFF);
  }
  return at;
}

/* Pulls the payload of a DVMP_T_STR result into `dst`. */
static int decode_string(const uint8_t *buf, uint32_t len, char *dst,
                         size_t cap) {
  if (len < 5 || buf[0] != DVMP_T_STR) return -1;
  const uint32_t n = (uint32_t)buf[1] | ((uint32_t)buf[2] << 8) |
                     ((uint32_t)buf[3] << 16) | ((uint32_t)buf[4] << 24);
  if ((uint64_t)5 + n > len || (size_t)n + 1 > cap) return -1;
  memcpy(dst, buf + 5, n);
  dst[n] = '\0';
  return 0;
}

static int32_t call_make_license_key(uint8_t *out, uint32_t *out_len) {
  uint8_t args[64];
  const uint32_t args_len = encode_args(args, "seed", 7);
  *out_len = 256;
  return dartvmp_call_named("makeLicenseKey", args, args_len, out, out_len);
}

static THREAD_RET worker(void *arg) {
  Worker *w = (Worker *)arg;
  uint8_t out[256];

  for (int i = 0; i < w->rounds; i++) {
    uint32_t out_len = 0;
    const int32_t rc = call_make_license_key(out, &out_len);
    if (rc != DARTVMP_OK) {
      w->errors++;
      if (w->first_error == 0) w->first_error = rc;
      continue;
    }
    char got[64];
    if (decode_string(out, out_len, got, sizeof(got)) != 0) {
      w->errors++;
      if (w->first_error == 0) w->first_error = DARTVMP_ERR_BAD_ARGUMENT;
      continue;
    }
    if (strcmp(got, g_reference) != 0) {
      w->mismatches++;
      if (w->first_bad[0] == '\0') {
        snprintf(w->first_bad, sizeof(w->first_bad), "%s", got);
      }
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  const int threads = (argc > 1) ? atoi(argv[1]) : 8;
  const int rounds = (argc > 2) ? atoi(argv[2]) : 400;
  if (threads < 1 || threads > 64 || rounds < 1) {
    fprintf(stderr, "usage: %s [threads 1..64] [rounds]\n", argv[0]);
    return 2;
  }

  const int32_t irc = dartvmp_init(NULL, 0, NULL);
  if (irc != DARTVMP_OK) {
    fprintf(stderr, "init failed: %s (%s)\n", dartvmp_status_name(irc),
            dartvmp_last_error());
    return 2;
  }

  /* Reference, single-threaded, before any thread starts. */
  {
    uint8_t out[256];
    uint32_t out_len = 0;
    const int32_t rc = call_make_license_key(out, &out_len);
    if (rc != DARTVMP_OK ||
        decode_string(out, out_len, g_reference, sizeof(g_reference)) != 0) {
      fprintf(stderr, "reference call failed: %s (%s)\n",
              dartvmp_status_name(rc), dartvmp_last_error());
      return 2;
    }
  }
  printf("reference          : %s\n", g_reference);
  printf("threads x rounds   : %d x %d\n", threads, rounds);

  Worker *workers = (Worker *)calloc((size_t)threads, sizeof(Worker));
  if (workers == NULL) return 2;

#if defined(_WIN32)
  HANDLE *handles = (HANDLE *)calloc((size_t)threads, sizeof(HANDLE));
  for (int i = 0; i < threads; i++) {
    workers[i].id = i;
    workers[i].rounds = rounds;
    handles[i] = CreateThread(NULL, 0, worker, &workers[i], 0, NULL);
    if (handles[i] == NULL) {
      fprintf(stderr, "CreateThread failed\n");
      return 2;
    }
  }
  WaitForMultipleObjects((DWORD)threads, handles, TRUE, INFINITE);
  for (int i = 0; i < threads; i++) CloseHandle(handles[i]);
  free(handles);
#else
  pthread_t *tids = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));
  for (int i = 0; i < threads; i++) {
    workers[i].id = i;
    workers[i].rounds = rounds;
    if (pthread_create(&tids[i], NULL, worker, &workers[i]) != 0) {
      fprintf(stderr, "pthread_create failed\n");
      return 2;
    }
  }
  for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
  free(tids);
#endif

  int mismatches = 0;
  int errors = 0;
  for (int i = 0; i < threads; i++) {
    mismatches += workers[i].mismatches;
    errors += workers[i].errors;
    if (workers[i].mismatches > 0) {
      printf("  thread %d: %d mismatch(es), first bad result %s\n", i,
             workers[i].mismatches, workers[i].first_bad);
    }
    if (workers[i].errors > 0) {
      printf("  thread %d: %d error(s), first %s\n", i, workers[i].errors,
             dartvmp_status_name(workers[i].first_error));
    }
  }
  printf("mismatches         : %d\n", mismatches);
  printf("errors             : %d\n", errors);

  free(workers);
  if (mismatches != 0 || errors != 0) {
    fprintf(stderr,
            "FAILED: concurrent calls did not agree with the serial result\n");
    return 1;
  }
  return 0;
}
