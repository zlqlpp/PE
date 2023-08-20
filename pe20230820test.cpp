#include "windows.h"
#include "stdio.h"
#include "stdlib.h"
#include <iostream>
#pragma warning(disable : 4996)

 using namespace std;
 //https://blog.csdn.net/z17805008775/article/details/105539478
void main() {


	FILE* pfile = fopen("C:\\ProgramFiles_dev\\鼠标单击变双击测试器V2.0.exe", "rb");

	   DWORD dw = GetLastError();
		fseek(pfile,0,SEEK_END);
		long fsize = ftell(pfile);
		rewind(pfile);

		void * pmfile=malloc(fsize);

		fread(pmfile,1,fsize,pfile);

		//printf("%s", pmfile);

		PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)pmfile;


		printf("dos header:%x\n", dosheader->e_magic);
		 
		//printf("%x\n", dosheader->e_lfanew);

		PIMAGE_NT_HEADERS pntheader = (PIMAGE_NT_HEADERS)((DWORD)pmfile + (DWORD)dosheader->e_lfanew);

		printf("PE header: %x\n", pntheader->Signature);

		PIMAGE_FILE_HEADER pfileheader = (PIMAGE_FILE_HEADER)((DWORD)pntheader + (DWORD)4);
		printf("pe header ,section num: %x\n", pfileheader->NumberOfSections);

		PIMAGE_OPTIONAL_HEADER poptheader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pntheader + (DWORD)sizeof(pntheader->Signature)+ (DWORD)sizeof(IMAGE_FILE_HEADER));

		printf("p opt header,imagebase: %x\n", poptheader->ImageBase);
		printf("p opt header, DataDirectory addr: %x\n", poptheader->DataDirectory);

		printf("--------------IMAGE_DATA_DIRECTORY----------数据目录表-\n" );
		for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES;i++) {
			IMAGE_DATA_DIRECTORY dd = poptheader->DataDirectory[i];
			printf("%x-----%x\n", dd.VirtualAddress, dd.Size);
	 
		}

		//---------------------------导出表0
		IMAGE_DATA_DIRECTORY ddexp = poptheader->DataDirectory[0];
		PIMAGE_EXPORT_DIRECTORY pexp = (PIMAGE_EXPORT_DIRECTORY)ddexp.VirtualAddress;



		//---------------------------导入表1
		IMAGE_DATA_DIRECTORY ddimp = poptheader->DataDirectory[1];
		PIMAGE_IMPORT_DESCRIPTOR pimp = (PIMAGE_IMPORT_DESCRIPTOR)ddimp.VirtualAddress;
		while (pimp->Name!=0x0000) {
			printf("%x----- \n", pimp->Name);
		}

		
		PIMAGE_SECTION_HEADER psecheader = (PIMAGE_SECTION_HEADER)((DWORD)pntheader + (DWORD)sizeof(IMAGE_NT_HEADERS));
		printf("--------------section--------节表---\n");
		for (int i = 0; i < pfileheader->NumberOfSections;i++) {
			psecheader = (PIMAGE_SECTION_HEADER)((DWORD)psecheader + i * (DWORD)sizeof(IMAGE_SECTION_HEADER));

			printf("%x-----%x\n", psecheader->PointerToRawData, psecheader->VirtualAddress);
		}



		exit(0);
	 
}