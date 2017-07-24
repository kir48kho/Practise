/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
* Подробная информация:  http://www.rutoken.ru                           *
*------------------------------------------------------------------------*
* Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
*------------------------------------------------------------------------*
* Использование команд создания объектов в памяти Рутокен:               *
*  - установление соединения с Рутокен в первом доступном слоте;         *
*  - форматирование токена;												 *
*  - создание локального PIN-кода;										 *
*  - создание двух разделов CD+RW;										 *
*  - постоянное изменение раздела RW на RO;								 *
*  - временно изменение раздела RO на RW;	 							 *
*------------------------------------------------------------------------*
* Созданные примером объекты используются также и в других примерах      *
* работы с библиотекой PKCS#11.                                          *
*************************************************************************/
#define CKU_LOCAL_1 3
#include <Common.h>

int main(void)
{
	HMODULE module;                                              // Хэндл загруженной библиотеки PKCS#11

	CK_FUNCTION_LIST_PTR functionList;                           // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
	CK_C_GetFunctionList getFunctionList;                        // Указатель на функцию C_GetFunctionList
	CK_FUNCTION_LIST_EXTENDED_PTR functionListEx;				 // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST_EXTENDED
	CK_C_EX_GetFunctionListExtended getFunctionListEx;			 // Указатель на функцию C_GetFunctionListExtended


	CK_SLOT_ID_PTR slots;                                        // Массив идентификаторов слотов
	CK_ULONG slotCount;                                          // Количество идентификаторов слотов в массиве

	CK_RV rv;                                                    // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11

	CK_ULONG i;                                                  // Вспомогательная переменная-счетчик в циклах

	int errorCode = 1;                                           // Флаг ошибки

	CK_ULONG	VolumeRWSize = 0;							     // Размер раздела для чтения и записи
	CK_ULONG	VolumeROSize = 0;							     // Размер раздела только для чтения
	CK_ULONG	VolumeCDSize = 0;							     // Размер раздела CD-ROM

	CK_ULONG    ulDriveSize = 0;								 // Общий объем флеш-памяти

	CK_RUTOKEN_INIT_PARAM ckRtInitParams;                                  // структура, задающая параметры форматирования токена

	/* заполнение полей структуры CK_RUTOKEN_INIT_PARAM */
	ckRtInitParams.ulSizeofThisStructure = sizeof(CK_RUTOKEN_INIT_PARAM);   // задаем размер структуры
	ckRtInitParams.UseRepairMode = 0;                                       // требуем ввод PIN-кода Администратора (0 - да, режим восстановления выключен, !0 - нет, режим восстановления включен)
	ckRtInitParams.pNewAdminPin = SO_PIN;                                   // задаем новый PIN-код Администратора (минимум (?), максимум 32 байта)
	ckRtInitParams.ulNewAdminPinLen = SO_PIN_LEN;                       // указываем длину нового PIN-кода Администратора
	ckRtInitParams.pNewUserPin = USER_PIN;                                  // задаем новый PIN-код Пользователя (минимум (?), максимум 32 байта)
	ckRtInitParams.ulNewUserPinLen = USER_PIN_LEN;                     // указываем длину нового PIN-кода Пользователя
	ckRtInitParams.ChangeUserPINPolicy = TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN | TOKEN_FLAGS_USER_CHANGE_USER_PIN; // задаем политику смены PIN-кода пользователя: Администратором и Пользователем
	ckRtInitParams.ulMinAdminPinLen = 6;                                    // задаем минимальную длину PIN-кода Администратора (минимум 6, максимум 32 байта)
	ckRtInitParams.ulMinUserPinLen = 6;                                     // задаем минимальную длину PIN-кода Пользователя (минимум 6, максимум 32 байта)
	ckRtInitParams.ulMaxAdminRetryCount = 10;                               // задаем максимальное количество попыток доступа к PIN-коду Администратора (минимум 3, максимум 10 байтов)
	ckRtInitParams.ulMaxUserRetryCount = 10;                                // задаем максимальное количество попыток доступа к PIN-коду Пользователя (минимум 1, максимум 10 байтов)
	ckRtInitParams.pTokenLabel = "Rutoken label";                           // задаем метку пользователя
	ckRtInitParams.ulLabelLen = 13;                                         // указываем длину метки пользователя

	/*************************************************************************
	* Выполнить действия для начала работы с библиотекой PKCS#11             *
	*************************************************************************/
	printf("Initialization...\n");

	/*************************************************************************
	* Загрузить библиотеку                                                   *
	*************************************************************************/
	module = LoadLibrary(PKCS11ECP_LIBRARY_NAME);
	CHECK(" LoadLibrary", module != NULL, exit);

	/*************************************************************************
	* Получить адрес функции запроса структуры с указателями на функции      *
	*************************************************************************/
	getFunctionList = (CK_C_GetFunctionList)GetProcAddress(module, "C_GetFunctionList");
	CHECK(" GetProcAddress", getFunctionList != NULL, unload_pkcs11);

	/*************************************************************************
	* Получить адрес функции запроса структуры с указателями на функции ex   *
	*************************************************************************/
	getFunctionListEx = (CK_C_EX_GetFunctionListExtended)GetProcAddress(module, "C_EX_GetFunctionListExtended");
	CHECK(" GetProcAddress (C_EX_GetFunctionListExtended)", getFunctionListEx != NULL, unload_pkcs11);

	/*************************************************************************
	* Получить структуру с указателями на функции                            *
	*************************************************************************/
	rv = getFunctionList(&functionList);
	CHECK_AND_LOG(" Get function list", rv == CKR_OK, rvToStr(rv), unload_pkcs11);

	/*************************************************************************
	* Получить структуру с указателями на функции расширения                 *
	*************************************************************************/
	rv = getFunctionListEx(&functionListEx);
	CHECK_AND_LOG(" Get function list extended", rv == CKR_OK, rvToStr(rv), unload_pkcs11);

	/*************************************************************************
	* Инициализировать библиотеку                                            *
	*************************************************************************/
	rv = functionList->C_Initialize(NULL_PTR);
	CHECK_AND_LOG(" C_Initialize", rv == CKR_OK, rvToStr(rv), unload_pkcs11);

	/*************************************************************************
	* Получить количество слотов c подключенными токенами                    *
	*************************************************************************/
	rv = functionList->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
	CHECK_AND_LOG(" C_GetSlotList (number of slots)", rv == CKR_OK, rvToStr(rv), finalize_pkcs11);

	CHECK_AND_LOG(" Checking available tokens", slotCount > 0, " No tokens available", finalize_pkcs11);

	/*************************************************************************
	* Получить список слотов c подключенными токенами                        *
	*************************************************************************/
	slots = (CK_SLOT_ID_PTR)malloc(slotCount * sizeof(CK_SLOT_ID));
	CHECK(" Memory allocation for slots", slots != NULL_PTR, finalize_pkcs11);

	rv = functionList->C_GetSlotList(CK_TRUE, slots, &slotCount);
	CHECK_AND_LOG(" C_GetSlotList", rv == CKR_OK, rvToStr(rv), free_slots);
	printf(" Slots available: %d\n", (int)slotCount);

	/*ЗДЕСЬ СНАЧАЛА ФОРМАТИРОВАНИЕ, ПОТОМ УСТАНОВКА ПАРОЛЯ И СОЗДАНИЕ РАЗДЕЛОВ */

	/*************************************************************************
	* Инициализировать токен                                                 *
	*************************************************************************/
	rv = functionListEx->C_EX_InitToken(slots[0], SO_PIN, SO_PIN_LEN, &ckRtInitParams);
	if (rv == CKR_OK)                                                       // проверка результата
		printf("Token initialization -> OK \n");
	else
		printf("Token initialization -> failed \n");

	/*************************************************************************
	* Создание локального PIN-кода                                           *
	*************************************************************************/
	rv = functionListEx->C_EX_SetLocalPIN(slots[0], USER_PIN, USER_PIN_LEN, LOCAL_PIN, LOCAL_PIN_LEN, CKU_LOCAL_1);		// ЧТО ДЕЛАТЬ С НАЧАЛЬНЫМ ЛОКАЛЬНЫМ PIN-кодом???
	if (rv != CKR_OK)
		printf("C_EX_SetLocalPIN() -> failed \n");
	else
		printf("C_EX_SetLocalPIN() -> OK \n");

	/*************************************************************************
	* Получить объем токена в МБ											 *
	*************************************************************************/
	printf("Get Flash memory size");
	rv = functionListEx->C_EX_GetDriveSize(slots[0],      // Идентификатор слота с подключенным токеном
		&ulDriveSize);  // Возвращаемый размер флеш-памяти в Мб
	if (rv != CKR_OK)
		printf(" -> Failed\n");
	else
	{
		printf(" -> OK\n");
		printf("Memory size: %d Mb\n", (int)ulDriveSize);
	}

	/*************************************************************************
	* Создание 2х разделов (CD + RW) с защитой второго на локальном PIN-коде *
	*************************************************************************/
	CK_VOLUME_FORMAT_INFO_EXTENDED InitParams[] =
	{
		{ 500, ACCESS_MODE_CD, CKU_USER, 0 },
		{ ulDriveSize - 500, ACCESS_MODE_RW, CKU_LOCAL_1, 0 }
	};


	printf("\nFormatting flash memory");
	rv = functionListEx->C_EX_FormatDrive(slots[0],               // Идентификатор слота с подключенным токеном
		CKU_SO,                 // Форматирование выполняется только с правами Администратора
		SO_PIN,                 // Текущий PIN-код Администратора
		SO_PIN_LEN,             // Длина PIN-кода Администратора
		InitParams,             // Массив с информацией о разделах
		arraysize(InitParams)); // Размер массива
	if (rv != CKR_OK)
		printf(" -> Failed\n");
	else
		printf(" -> OK\n");

	/*************************************************************************
	* Постоянное изменение RW раздела на RO                                  *
	*************************************************************************/
	printf("\nChanging volume attributes");
	rv = functionListEx->C_EX_ChangeVolumeAttributes(slots[0],     // Идентификатор слота с подключенным токеном
		CKU_LOCAL_1,            // Владелец раздела
		LOCAL_PIN,			    // PIN-код владельца раздела
		LOCAL_PIN_LEN,		    // Длина PIN-кода владельца раздела
		1,			    // Идентификатор раздела
		ACCESS_MODE_RO,		    // Новые права доступа к разделу
		CK_TRUE);		        // CK_TRUE - постоянное изменение атрибутов, CK_FALSE - временное изменение атрибутов
	if (rv != CKR_OK)
		printf(" -> Failed\n");
	else
		printf(" -> OK\n");

	/*************************************************************************
	* Временное изменение RO раздела на RW                                   *
	*************************************************************************/
	printf("\nChanging volume attributes");
	rv = functionListEx->C_EX_ChangeVolumeAttributes(slots[0],     // Идентификатор слота с подключенным токеном
		CKU_LOCAL_1,		    // Владелец раздела
		LOCAL_PIN,			    // PIN-код владельца раздела
		LOCAL_PIN_LEN,		    // Длина PIN-кода владельца раздела
		1,			    // Идентификатор раздела                                ВОПРОС КАКОЙ РАЗДЕЛ ИМЕННО + КАК ИДЕНТИФИКАТОР
		ACCESS_MODE_RW,		    // Новые права доступа к разделу
		CK_FALSE);			    // CK_TRUE - постоянное изменение атрибутов, CK_FALSE - временное изменение атрибутов
	if (rv != CKR_OK)
		printf(" -> Failed\n");
	else
		printf(" -> OK\n");

	/*************************************************************************
	* Очистить память, выделенную под слоты							         *
	*************************************************************************/
free_slots:
	free(slots);

	/*************************************************************************
	* Деинициализировать библиотеку                                          *
	*************************************************************************/
finalize_pkcs11:
	rv = functionList->C_Finalize(NULL_PTR);
	CHECK_RELEASE_AND_LOG(" C_Finalize", rv == CKR_OK, rvToStr(rv), errorCode);

	/*************************************************************************
	* Выгрузить библиотеку из памяти                                         *
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