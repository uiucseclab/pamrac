#ifndef __SYSENDIAN_STANDIN_H_
#define __SYSENDIAN_STANDIN_H_

static inline uint32_t le32dec(const void *pp)
 {
         unsigned char const *p = (unsigned char const *)pp;
 
         return ((p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0]);
 }
 
static inline void le32enc(void *pp, uint32_t x)
{
 uint8_t *p = (uint8_t *)pp;
 p[0] = x & 0xff;
 p[1] = (x >> 8) & 0xff;
 p[2] = (x >> 16) & 0xff;
 p[3] = (x >> 24) & 0xff;
}

static inline void be32enc(void *pp, uint32_t x)
{
 uint8_t *p = (uint8_t *)pp;
 p[3] = x & 0xff;
 p[2] = (x >> 8) & 0xff;
 p[1] = (x >> 16) & 0xff;
 p[0] = (x >> 24) & 0xff;
}

static inline uint32_t
be32dec(const void *pp)
{
	unsigned char const *p = (unsigned char const *)pp;

	return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static inline void
be64enc(void *pp, uint64_t u)
{
	unsigned char *p = (unsigned char *)pp;

	be32enc(p, u >> 32);
	be32enc(p + 4, u & 0xffffffff);
}

#endif //__SYSENDIAN_STANDIN_H_
