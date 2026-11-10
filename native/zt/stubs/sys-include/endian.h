/* newlib has <machine/endian.h> but no <endian.h>; node/Constants.hpp wants
 * __BYTE_ORDER, __LITTLE_ENDIAN and __BIG_ENDIAN from it. */
#ifndef ZT_SWITCH_ENDIAN_H
#define ZT_SWITCH_ENDIAN_H
#include <machine/endian.h>
#ifndef __BYTE_ORDER
#define __BYTE_ORDER _BYTE_ORDER
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#define __BIG_ENDIAN _BIG_ENDIAN
#endif
#endif
