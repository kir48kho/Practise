/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
* ��������� ����������:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* ������ ������ � ������� ��� ������ ���������� PKCS#11 �� ����� C       *
*------------------------------------------------------------------------*
* ������������� ������ �������� �������� � ������ �������:               *
*  - ������������ ���������� � ������� � ������ ��������� �����;         *
*  - �������������� ������;												 *
*  - �������� ���������� PIN-����;										 *
*  - �������� ���� �������� CD+RW;										 *
*  - ���������� ��������� ������� RW �� RO;								 *
*  - �������� ��������� ������� RO �� RW;	 							 *
*------------------------------------------------------------------------*
* ��������� �������� ������� ������������ ����� � � ������ ��������      *
* ������ � ����������� PKCS#11.                                          *
*************************************************************************/
#define CKU_LOCAL_1 3
#include <Common.h>

int main(void)
{
	HMODULE module;                                              // ����� ����������� ���������� PKCS#11

	CK_FUNCTION_LIST_PTR functionList;                           // ��������� �� ������ ������� PKCS#11, ���������� � ��������� CK_FUNCTION_LIST
	CK_C_GetFunctionList getFunctionList;                        // ��������� �� ������� C_GetFunctionList
	CK_FUNCTION_LIST_EXTENDED_PTR functionListEx;				 // ��������� �� ������ ������� PKCS#11, ���������� � ��������� CK_FUNCTION_LIST_EXTENDED
	CK_C_EX_GetFunctionListExtended getFunctionListEx;			 // ��������� �� ������� C_GetFunctionListExtended


	CK_SLOT_ID_PTR slots;                                        // ������ ��������������� ������
	CK_ULONG slotCount;                                          // ���������� ��������������� ������ � �������

	CK_RV rv;                                                    // ��� ��������. ����� ���� ���������� ������ ������, ������������ � PKCS#11

	CK_ULONG i;                                                  // ��������������� ����������-������� � ������

	int errorCode = 1;                                           // ���� ������

	CK_ULONG	VolumeRWSize = 0;							     // ������ ������� ��� ������ � ������
	CK_ULONG	VolumeROSize = 0;							     // ������ ������� ������ ��� ������
	CK_ULONG	VolumeCDSize = 0;							     // ������ ������� CD-ROM

	CK_ULONG    ulDriveSize = 0;								 // ����� ����� ����-������

	CK_RUTOKEN_INIT_PARAM ckRtInitParams;                                  // ���������, �������� ��������� �������������� ������

	/* ���������� ����� ��������� CK_RUTOKEN_INIT_PARAM */
	ckRtInitParams.ulSizeofThisStructure = sizeof(CK_RUTOKEN_INIT_PARAM);   // ������ ������ ���������
	ckRtInitParams.UseRepairMode = 0;                                       // ������� ���� PIN-���� �������������� (0 - ��, ����� �������������� ��������, !0 - ���, ����� �������������� �������)
	ckRtInitParams.pNewAdminPin = SO_PIN;                                   // ������ ����� PIN-��� �������������� (������� (?), �������� 32 �����)
	ckRtInitParams.ulNewAdminPinLen = SO_PIN_LEN;                       // ��������� ����� ������ PIN-���� ��������������
	ckRtInitParams.pNewUserPin = USER_PIN;                                  // ������ ����� PIN-��� ������������ (������� (?), �������� 32 �����)
	ckRtInitParams.ulNewUserPinLen = USER_PIN_LEN;                     // ��������� ����� ������ PIN-���� ������������
	ckRtInitParams.ChangeUserPINPolicy = TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN | TOKEN_FLAGS_USER_CHANGE_USER_PIN; // ������ �������� ����� PIN-���� ������������: ��������������� � �������������
	ckRtInitParams.ulMinAdminPinLen = 6;                                    // ������ ����������� ����� PIN-���� �������������� (������� 6, �������� 32 �����)
	ckRtInitParams.ulMinUserPinLen = 6;                                     // ������ ����������� ����� PIN-���� ������������ (������� 6, �������� 32 �����)
	ckRtInitParams.ulMaxAdminRetryCount = 10;                               // ������ ������������ ���������� ������� ������� � PIN-���� �������������� (������� 3, �������� 10 ������)
	ckRtInitParams.ulMaxUserRetryCount = 10;                                // ������ ������������ ���������� ������� ������� � PIN-���� ������������ (������� 1, �������� 10 ������)
	ckRtInitParams.pTokenLabel = "Rutoken label";                           // ������ ����� ������������
	ckRtInitParams.ulLabelLen = 13;                                         // ��������� ����� ����� ������������

	/*************************************************************************
	* ��������� �������� ��� ������ ������ � ����������� PKCS#11             *
	*************************************************************************/
	printf("Initialization...\n");

	/*************************************************************************
	* ��������� ����������                                                   *
	*************************************************************************/
	module = LoadLibrary(PKCS11ECP_LIBRARY_NAME);
	CHECK(" LoadLibrary", module != NULL, exit);

	/*************************************************************************
	* �������� ����� ������� ������� ��������� � ����������� �� �������      *
	*************************************************************************/
	getFunctionList = (CK_C_GetFunctionList)GetProcAddress(module, "C_GetFunctionList");
	CHECK(" GetProcAddress", getFunctionList != NULL, unload_pkcs11);

	/*************************************************************************
	* �������� ����� ������� ������� ��������� � ����������� �� ������� ex   *
	*************************************************************************/
	getFunctionListEx = (CK_C_EX_GetFunctionListExtended)GetProcAddress(module, "C_EX_GetFunctionListExtended");
	CHECK(" GetProcAddress (C_EX_GetFunctionListExtended)", getFunctionListEx != NULL, unload_pkcs11);

	/*************************************************************************
	* �������� ��������� � ����������� �� �������                            *
	*************************************************************************/
	rv = getFunctionList(&functionList);
	CHECK_AND_LOG(" Get function list", rv == CKR_OK, rvToStr(rv), unload_pkcs11);

	/*************************************************************************
	* �������� ��������� � ����������� �� ������� ����������                 *
	*************************************************************************/
	rv = getFunctionListEx(&functionListEx);
	CHECK_AND_LOG(" Get function list extended", rv == CKR_OK, rvToStr(rv), unload_pkcs11);

	/*************************************************************************
	* ���������������� ����������                                            *
	*************************************************************************/
	rv = functionList->C_Initialize(NULL_PTR);
	CHECK_AND_LOG(" C_Initialize", rv == CKR_OK, rvToStr(rv), unload_pkcs11);

	/*************************************************************************
	* �������� ���������� ������ c ������������� ��������                    *
	*************************************************************************/
	rv = functionList->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
	CHECK_AND_LOG(" C_GetSlotList (number of slots)", rv == CKR_OK, rvToStr(rv), finalize_pkcs11);

	CHECK_AND_LOG(" Checking available tokens", slotCount > 0, " No tokens available", finalize_pkcs11);

	/*************************************************************************
	* �������� ������ ������ c ������������� ��������                        *
	*************************************************************************/
	slots = (CK_SLOT_ID_PTR)malloc(slotCount * sizeof(CK_SLOT_ID));
	CHECK(" Memory allocation for slots", slots != NULL_PTR, finalize_pkcs11);

	rv = functionList->C_GetSlotList(CK_TRUE, slots, &slotCount);
	CHECK_AND_LOG(" C_GetSlotList", rv == CKR_OK, rvToStr(rv), free_slots);
	printf(" Slots available: %d\n", (int)slotCount);

	/*����� ������� ��������������, ����� ��������� ������ � �������� �������� */

	/*************************************************************************
	* ���������������� �����                                                 *
	*************************************************************************/
	rv = functionListEx->C_EX_InitToken(slots[0], SO_PIN, SO_PIN_LEN, &ckRtInitParams);
	if (rv == CKR_OK)                                                       // �������� ����������
		printf("Token initialization -> OK \n");
	else
		printf("Token initialization -> failed \n");

	/*************************************************************************
	* �������� ���������� PIN-����                                           *
	*************************************************************************/
	rv = functionListEx->C_EX_SetLocalPIN(slots[0], USER_PIN, USER_PIN_LEN, LOCAL_PIN, LOCAL_PIN_LEN, CKU_LOCAL_1);		// ��� ������ � ��������� ��������� PIN-�����???
	if (rv != CKR_OK)
		printf("C_EX_SetLocalPIN() -> failed \n");
	else
		printf("C_EX_SetLocalPIN() -> OK \n");

	/*************************************************************************
	* �������� ����� ������ � ��											 *
	*************************************************************************/
	printf("Get Flash memory size");
	rv = functionListEx->C_EX_GetDriveSize(slots[0],      // ������������� ����� � ������������ �������
		&ulDriveSize);  // ������������ ������ ����-������ � ��
	if (rv != CKR_OK)
		printf(" -> Failed\n");
	else
	{
		printf(" -> OK\n");
		printf("Memory size: %d Mb\n", (int)ulDriveSize);
	}

	/*************************************************************************
	* �������� 2� �������� (CD + RW) � ������� ������� �� ��������� PIN-���� *
	*************************************************************************/
	CK_VOLUME_FORMAT_INFO_EXTENDED InitParams[] =
	{
		{ 500, ACCESS_MODE_CD, CKU_USER, 0 },
		{ ulDriveSize - 500, ACCESS_MODE_RW, CKU_LOCAL_1, 0 }
	};


	printf("\nFormatting flash memory");
	rv = functionListEx->C_EX_FormatDrive(slots[0],               // ������������� ����� � ������������ �������
		CKU_SO,                 // �������������� ����������� ������ � ������� ��������������
		SO_PIN,                 // ������� PIN-��� ��������������
		SO_PIN_LEN,             // ����� PIN-���� ��������������
		InitParams,             // ������ � ����������� � ��������
		arraysize(InitParams)); // ������ �������
	if (rv != CKR_OK)
		printf(" -> Failed\n");
	else
		printf(" -> OK\n");

	/*************************************************************************
	* ���������� ��������� RW ������� �� RO                                  *
	*************************************************************************/
	printf("\nChanging volume attributes");
	rv = functionListEx->C_EX_ChangeVolumeAttributes(slots[0],     // ������������� ����� � ������������ �������
		CKU_LOCAL_1,            // �������� �������
		LOCAL_PIN,			    // PIN-��� ��������� �������
		LOCAL_PIN_LEN,		    // ����� PIN-���� ��������� �������
		1,			    // ������������� �������
		ACCESS_MODE_RO,		    // ����� ����� ������� � �������
		CK_TRUE);		        // CK_TRUE - ���������� ��������� ���������, CK_FALSE - ��������� ��������� ���������
	if (rv != CKR_OK)
		printf(" -> Failed\n");
	else
		printf(" -> OK\n");

	/*************************************************************************
	* ��������� ��������� RO ������� �� RW                                   *
	*************************************************************************/
	printf("\nChanging volume attributes");
	rv = functionListEx->C_EX_ChangeVolumeAttributes(slots[0],     // ������������� ����� � ������������ �������
		CKU_LOCAL_1,		    // �������� �������
		LOCAL_PIN,			    // PIN-��� ��������� �������
		LOCAL_PIN_LEN,		    // ����� PIN-���� ��������� �������
		1,			    // ������������� �������                                ������ ����� ������ ������ + ��� �������������
		ACCESS_MODE_RW,		    // ����� ����� ������� � �������
		CK_FALSE);			    // CK_TRUE - ���������� ��������� ���������, CK_FALSE - ��������� ��������� ���������
	if (rv != CKR_OK)
		printf(" -> Failed\n");
	else
		printf(" -> OK\n");

	/*************************************************************************
	* �������� ������, ���������� ��� �����							         *
	*************************************************************************/
free_slots:
	free(slots);

	/*************************************************************************
	* ������������������ ����������                                          *
	*************************************************************************/
finalize_pkcs11:
	rv = functionList->C_Finalize(NULL_PTR);
	CHECK_RELEASE_AND_LOG(" C_Finalize", rv == CKR_OK, rvToStr(rv), errorCode);

	/*************************************************************************
	* ��������� ���������� �� ������                                         *
	*************************************************************************/
unload_pkcs11:
	CHECK_RELEASE(" FreeLibrary", FreeLibrary(module), errorCode);

exit:
	if (errorCode) {
		printf("\n\nSome error occurred. Sample failed.\n");
	}
	else {
		printf("\n\nSample has been completed successfully.\n");
	}

	return errorCode;
}