/*
 * user_main.c
 *
 *  Created on: 2015��7��13��
 *      Author: Administrator
 */
#include "driver/uart.h"
#include "user_main.h"
#include "json/jsonparse.h"
#include "json/jsontree.h"
#include "wifi_entrance.h"



void user_init() {
	uart_init(BIT_RATE_115200, BIT_RATE_115200);
	uart0_sendStr("\r\n");
//��ʼ��WiFiģ��
	WIFI_Init();
//��ӡ��ǰģʽ
	os_sprintf(out, "\r\ninit completed.\r\nopmode: %d\r\n", wifi_get_opmode());
	uart0_sendStr(out);

//��ʼ��GPIO����
	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTDI_U, FUNC_GPIO12);
	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTCK_U, FUNC_GPIO13);
	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTDO_U, FUNC_GPIO15);
//STA����WiFi
	os_timer_disarm(&Wifi_Init);
	os_timer_setfn(&Wifi_Init,(os_timer_func_t *)wifi_Conn,NULL);
	os_timer_arm(&Wifi_Init,500,0);
//���WiFi״̬
	os_timer_disarm(&checkTimer_wifistate);
	os_timer_setfn(&checkTimer_wifistate,(os_timer_func_t *)Check_WifiState,NULL);
	os_timer_arm(&checkTimer_wifistate,1000,1);
//����TCP������
	os_timer_disarm(&TCP_Init);
	os_timer_setfn(&TCP_Init, (os_timer_func_t *) TCP_Conn, NULL);
//��ʼ��UDP
	Esp8266_UDPServer_Time_Init();
}
void user_rf_pre_init() {
}

