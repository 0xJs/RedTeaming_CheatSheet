// author: reenz0h(twitter : @SEKTOR7net)
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "user32.lib")

int main(void){

	printf("Starting.\n");

	MessageBox(NULL, "First message", "Messagebox", MB_OK);
	MessageBox(NULL, "Second message", "Messagebox", MB_OK);
	MessageBox(NULL, "Third message", "Messagebox", MB_OK);

	printf("Roger and out!\n");

    return 0;
}
