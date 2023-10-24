#include "filesys/filesys.h"

#include <debug.h>
#include <stdio.h>
#include <string.h>

#include "devices/disk.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/thread.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

/* Filesys lock. */
static struct lock filesys_lock;

static void do_format(void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  filesys_disk = disk_get(0, 1);
  if (filesys_disk == NULL)
    PANIC("hd0:1 (hdb) not present, file system initialization failed");

  inode_init();

#ifdef EFILESYS
  fat_init();

  if (format) do_format();

  fat_open();
#else
  /* Original FS */
  free_map_init();

  if (format) do_format();

  free_map_open();
  lock_init(&filesys_lock);
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void filesys_done(void) {
  /* Original FS */
#ifdef EFILESYS
  fat_close();
#else
  free_map_close();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size) {
  lock_acquire(&filesys_lock);

  disk_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root();
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) &&
                  dir_add(dir, name, inode_sector));
  if (!success && inode_sector != 0) free_map_release(inode_sector, 1);
  dir_close(dir);

  lock_release(&filesys_lock);
  return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *filesys_open(const char *name) {
  lock_acquire(&filesys_lock);

  struct dir *dir = dir_open_root();
  struct inode *inode = NULL;

  if (dir != NULL) dir_lookup(dir, name, &inode);
  dir_close(dir);

  struct file *file;
  file = file_open(inode);

  lock_release(&filesys_lock);
  return file;
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool filesys_remove(const char *name) {
  lock_acquire(&filesys_lock);

  struct dir *dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  lock_release(&filesys_lock);
  return success;
}

/* ==== Wrapper functions with lock. ==== */
void filesys_close(struct file *file) {
  lock_acquire(&filesys_lock);
  file_close(file);
  lock_release(&filesys_lock);
}

off_t filesys_read(struct file *file, void *buf, off_t size) {
  int bytes;
  lock_acquire(&filesys_lock);
  bytes = file_read(file, buf, size);
  lock_release(&filesys_lock);
  return bytes;
}

off_t filesys_write(struct file *file, const void *buf, off_t size) {
  int bytes;
  lock_acquire(&filesys_lock);
  bytes = file_write(file, buf, size);
  lock_release(&filesys_lock);
  return bytes;
}

off_t filesys_length(struct file *file) {
  off_t length;
  lock_acquire(&filesys_lock);
  length = file_length(file);
  lock_release(&filesys_lock);
  return length;
}

void filesys_seek(struct file *file, off_t pos) {
  lock_acquire(&filesys_lock);
  file_seek(file, pos);
  lock_release(&filesys_lock);
}

off_t filesys_tell(struct file *file) {
  off_t pos;
  lock_acquire(&filesys_lock);
  pos = file_tell(file);
  lock_release(&filesys_lock);
  return pos;
}

struct file *filesys_duplicate(struct file *file) {
  struct file *nfile;
  lock_acquire(&filesys_lock);
  nfile = file_duplicate(file);
  lock_release(&filesys_lock);
  return nfile;
}

void filesys_deny_write(struct file *file) {
  lock_acquire(&filesys_lock);
  file_deny_write(file);
  lock_release(&filesys_lock);
}

void filesys_incr_dup(struct file *file) {
  lock_acquire(&filesys_lock);
  file->dup_cnt++;
  lock_release(&filesys_lock);
}

void filesys_decr_dup(struct file *file) {
  lock_acquire(&filesys_lock);
  file->dup_cnt--;
  lock_release(&filesys_lock);
}

int filesys_get_dup(struct file *file) {
  int dup_cnt;
  lock_acquire(&filesys_lock);
  dup_cnt = file->dup_cnt;
  lock_release(&filesys_lock);
  return dup_cnt;
}

void clear_filesys_lock() {
  struct thread *curr = thread_current();
  if (filesys_lock.holder == curr) {
    lock_release(&filesys_lock);
  }
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");

#ifdef EFILESYS
  /* Create FAT and save it to the disk. */
  fat_create();
  fat_close();
#else
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16)) PANIC("root directory creation failed");
  free_map_close();
#endif

  printf("done.\n");
}
