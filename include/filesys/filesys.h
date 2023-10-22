#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Disk used for file system. */
extern struct disk *filesys_disk;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);

/* === Wrapper functions with lock. === */
void filesys_close(struct file *file);
off_t filesys_read(struct file *file, void *buf, off_t size);
off_t filesys_write(struct file *file, const void *buf, off_t size);
off_t filesys_length(struct file *file);
void filesys_seek(struct file *file, off_t pos);
off_t filesys_tell(struct file *file);

#endif /* filesys/filesys.h */
