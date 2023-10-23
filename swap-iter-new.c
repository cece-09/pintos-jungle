/* Checks if any type of memory is properly swapped out and swapped in
 * For this test, Pintos memory size is 128MB */

#include <stdio.h>
#include <string.h>
#include <syscall.h>

#include "tests/lib.h"
#include "tests/main.h"
#include "tests/vm/large.inc"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define ONE_MB (1 << 20)  // 1MB
#define CHUNK_SIZE (20 * ONE_MB)
#define PAGE_COUNT (CHUNK_SIZE / PAGE_SIZE)

static char big_chunks[CHUNK_SIZE];

void test_main(void) {
  size_t i, handle, j;
  char *actual = (char *)0x10000000;
  void *map;

  for (i = 0; i < PAGE_COUNT; i++) {
    big_chunks[i * PAGE_SIZE] = (char)i;
  }

  CHECK((handle = open("large.txt")) > 1, "open \"large.txt\"");
  CHECK((map = mmap(actual, sizeof(large), 0, handle, 0)) != MAP_FAILED,
        "mmap \"large.txt\"");

  // 반복적으로 페이지 접근
  for (j = 0; j < 10; j++) {
    // 처음 반을 자주 접근
    for (i = 0; i < PAGE_COUNT / 2; i++) {
      if (big_chunks[i * PAGE_SIZE] != (char)i) fail("data is inconsistent");
    }

    // 파일의 내용 검사
    if (memcmp(actual, large, strlen(large)))
      fail("read of mmap'd file reported bad data");

    // 두 번째 반은 거의 접근하지 않음. 이 부분이 clock 알고리즘에 유리함
    if (j % 5 == 0) {
      for (i = PAGE_COUNT / 2; i < PAGE_COUNT; i++) {
        if (big_chunks[i * PAGE_SIZE] != (char)i) fail("data is inconsistent");
      }
    }
  }

  munmap(map);
  close(handle);
}
