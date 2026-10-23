#ifndef __APP_THREADX_H__
#define __APP_THREADX_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "tx_api.h"

UINT App_ThreadX_Init(VOID *memory_ptr);
void MX_ThreadX_Init(void);

#ifdef __cplusplus
}
#endif
#endif /* __APP_THREADX_H__ */
