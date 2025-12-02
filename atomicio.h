/* ABOUTME: Header for atomicio - atomic read/write operations
 * ABOUTME: Ensures complete data transfer on socket operations */

#ifndef _ATOMICIO_H_
#define _ATOMICIO_H_

#include <sys/types.h>

ssize_t atomicio(ssize_t (*)(int, void *, size_t), int, void *, size_t);

#endif /* _ATOMICIO_H_ */
