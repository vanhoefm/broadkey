#ifndef OPENCL_UTIL_CL__
#define OPENCL_UTIL_CL__

#define COPY_PAD(dst, src) \
	(dst)[0] = (src)[0];		\
	(dst)[1] = (src)[1];		\
	(dst)[2] = (src)[2];		\
	(dst)[3] = (src)[3];		\
	(dst)[4] = (src)[4];

#define COPY_GTK(dst, src) \
	(dst)[0] = (src)[0];		\
	(dst)[1] = (src)[1];		\
	(dst)[2] = (src)[2];		\
	(dst)[3] = (src)[3];		\
	(dst)[4] = (src)[4];		\
	(dst)[5] = (src)[5];		\
	(dst)[6] = (src)[6];		\
	(dst)[7] = (src)[7];

#define COPY_BLOCK(dst, src) \
	(dst)[0] = (src)[0];		\
	(dst)[1] = (src)[1];		\
	(dst)[2] = (src)[2];		\
	(dst)[3] = (src)[3];		\
	(dst)[4] = (src)[4];		\
	(dst)[5] = (src)[5];		\
	(dst)[6] = (src)[6];		\
	(dst)[7] = (src)[7];		\
	(dst)[8] = (src)[8];		\
	(dst)[9] = (src)[9];		\
	(dst)[10] = (src)[10];		\
	(dst)[11] = (src)[11];		\
	(dst)[12] = (src)[12];		\
	(dst)[13] = (src)[13];		\
	(dst)[14] = (src)[14];		\
	(dst)[15] = (src)[15];

#define SET_BLOCK(dst, value) \
	(dst)[0] = value;		\
	(dst)[1] = value;		\
	(dst)[2] = value;		\
	(dst)[3] = value;		\
	(dst)[4] = value;		\
	(dst)[5] = value;		\
	(dst)[6] = value;		\
	(dst)[7] = value;		\
	(dst)[8] = value;		\
	(dst)[9] = value;		\
	(dst)[10] = value;		\
	(dst)[11] = value;		\
	(dst)[12] = value;		\
	(dst)[13] = value;		\
	(dst)[14] = value;		\
	(dst)[15] = value;

inline void memcpy_offset6(uint __private *dst, uint __private *src)
{
	dst[1] = (dst[1] & 0xFFFF0000) | (src[0] & 0xFFFF0000) >> 16;
	#pragma unroll
	for (int i = 0; i < 7; ++i) {
		dst[2 + i] = ((src[i] & 0x0000FFFF) << 16) | ((src[i + 1] & 0xFFFF0000) >> 16);
	}
	dst[9] = (src[7] & 0x0000FFFF) << 16;
}

inline void memcpy_offset10(uint __private *dst, uint __private *src)
{
	dst[2] = (dst[2] & 0xFFFF0000) | (src[0] & 0xFFFF0000) >> 16;
	#pragma unroll
	for (int i = 0; i < 7; ++i) {
		dst[3 + i] = ((src[i] & 0x0000FFFF) << 16) | ((src[i + 1] & 0xFFFF0000) >> 16);
	}
	dst[10] = (src[7] & 0x0000FFFF) << 16;
}

#endif // OPENCL_UTIL_CL__
