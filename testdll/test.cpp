#include "test.h"
#include <Windows.h>
#include <stdio.h>

int gValue = 100;

int my_add(int a, int b)
{
	return a + b;
}

int test_dll_add( int a, int b )
{
	return a + b + gValue;
}

void test_dll_messagebox()
{
	MessageBox(NULL, ("succeed"), NULL, MB_OK);
}
