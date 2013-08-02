#ifndef __TEST_H__
#define __TEST_H__

#ifdef __cplusplus
extern "C"
{
#endif

__declspec(dllexport) int test_dll_add(int a, int b);
__declspec(dllexport) void test_dll_messagebox();

#ifdef __cplusplus
}
#endif


#endif