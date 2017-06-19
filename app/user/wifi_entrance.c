/*
 * wifi_entrance.c
 *
 *  Created on: 2017��5��13��
 *      Author: Listener
 */

#include "string.h"
#include "osapi.h"
#include "user_interface.h"
#include "ets_sys.h"
#include "osapi.h"
#include "user_interface.h"
#include "mem.h"
#include "espconn.h"
#include "driver/uart.h"
#include "user_json.h"
#include "wifi_entrance.h"

#define INSTRUCTION_OPEN 1
#define INSTRUCTION_AUTH_APPLY 2
#define INSTRUCTION_GET_OWNER_AUTH 4
#define INSTRUCTION_GET_VISITOR_AUTH 5

auth owner_auth;
authNode *owner_tail;
auth visitor_auth;
authNode *visitor_tail;

void ICACHE_FLASH_ATTR displayBlue() {
	gpio_output_set(BIT13, BIT12 | BIT15, BIT13 | BIT15 | BIT12, 0); //BIT13 ��
}
void ICACHE_FLASH_ATTR displayRed() {
	gpio_output_set(BIT15, BIT12 | BIT13, BIT13 | BIT15 | BIT12, 0); //BIT15 ��
}
void ICACHE_FLASH_ATTR displayGreen() {
	gpio_output_set(BIT12, BIT15 | BIT13, BIT13 | BIT15 | BIT12, 0); //BIT12 ��
}
void ICACHE_FLASH_ATTR displayYellow() {
	gpio_output_set(BIT15 | BIT12, BIT13, BIT13 | BIT15 | BIT12, 0); //BIT12 ��
}
void ICACHE_FLASH_ATTR displayPurple() {
	gpio_output_set(BIT15 | BIT13, BIT12, BIT13 | BIT15 | BIT12, 0); //BIT12 ��
}

/*
 * ������:void Wifi_Init()
 * ����wifi_ap+sta��ʼ��
 */
void WIFI_Init() {

	uart0_sendStr("WIFI_APInit\r\n");
	/***************************ģʽ����************************************/
	if (wifi_set_opmode(STATIONAP_MODE)) {			//	����ΪAPģʽ

	} else {

	}
	/***************************������ͨ����************************************/
	uart0_sendStr("��ʼ��AP\r\n");
	struct softap_config apConfig;
	os_bzero(&apConfig, sizeof(struct softap_config));
	wifi_softap_get_config(&apConfig);
	apConfig.ssid_len = os_strlen("WifiEntrance");						//����ssid����
	os_strcpy(apConfig.ssid, "WifiEntrance");			//����ssid����
	os_strcpy(apConfig.password, "12345678");	//��������
	apConfig.authmode = 3;						//���ü���ģʽ
	ETS_UART_INTR_DISABLE();					//�رմ����ж�
	wifi_softap_set_config(&apConfig);		//����
	ETS_UART_INTR_ENABLE();					//�򿪴���

}
/*
 * ������:void WIFI_TCP_SendNews(unsigned char *dat)
 * ����:��TCP������������Ϣ
 */
void WIFI_TCP_SendNews(unsigned char *dat) {
	uart0_sendStr("��TCP������������ϢWIFI_TCP_SendNews\r\n");
	espconn_sent(pLink.pCon, dat, os_strlen(dat));
}


/*
 * ������:Inter213_Receive(void *arg, char *pdata, unsigned short len)
 * ����:���ջص�����
 */
static void ICACHE_FLASH_ATTR Inter213_Receive(void *arg, char *pdata, unsigned short len) {
	uart0_sendStr("\r\nclient���ջص�Inter213_Receive\r\n");
	int instruction_type = pdata[0] - '0';
	uart0_sendStr(pdata);
	char *data = (char *)os_malloc((len - 1) * sizeof(char));
	strcpy(data, pdata + 1);
	//�·���һ��node
	authNode *node = (authNode *)os_malloc(sizeof(authNode));
	node->value = data;
	node->next = NULL;
	if (instruction_type == INSTRUCTION_GET_OWNER_AUTH) {
		uart0_sendStr("\r\n�ӷ�������ȡһ��ҵ����Ȩ��Ϣ\r\n");
		if(owner_auth.length == NULL) {
			uart0_sendStr("�յ����ǵ�һ��\r\n");
			//��¼ҵ������β
			owner_tail = node;
			owner_auth.head = node;
			owner_auth.length = 1;
		} else {
			uart0_sendStr("�յ��Ĳ��ǵ�һ��\r\n");
			//����ҵ��node
			owner_tail->next = node;

			//��¼ҵ������β
			owner_tail = node;

			owner_auth.length = 1 + owner_auth.length;
		}
		os_sprintf(out, "owner_auth.length��%d\r\n", owner_auth.length);
		uart0_sendStr(out);
		authNode *temp = owner_auth.head;
		while(temp) {
			uart0_sendStr(temp->value);
			temp = temp->next;
		}
	} else if (instruction_type == INSTRUCTION_GET_VISITOR_AUTH) {
		uart0_sendStr("�ӷ�������ȡһ���ÿ���Ȩ��Ϣ\r\n");
		uart0_sendStr("\r\n�ӷ�������ȡһ��ҵ����Ȩ��Ϣ\r\n");
		if(visitor_auth.length == NULL) {
			uart0_sendStr("�յ����ǵ�һ��\r\n");
			//��¼�ÿ�����β
			visitor_tail = node;

			visitor_auth.head = node;
			visitor_auth.length = 1;
		} else {
			uart0_sendStr("�յ��Ĳ��ǵ�һ��\r\n");
			//���ӷÿ�node
			visitor_tail->next = node;

			//��¼�ÿ�����β
			visitor_tail = node;

			visitor_auth.length = 1 + visitor_auth.length;
		}
		os_sprintf(out, "owner_auth.length��%d\r\n", visitor_auth.length);
		uart0_sendStr(out);
		authNode *temp = visitor_auth.head;
		while(temp) {
			uart0_sendStr(temp->value);
			temp = temp->next;
		}
	} else {
		uart0_sendStr("δ֪������ָ��\r\n");
	}
	return;
}
/*
 * ������:Inter213_Send_Cb(void *arg)
 * ����:���ͳɹ��Ļص�����
 */
static void ICACHE_FLASH_ATTR Inter213_Send_Cb(void *arg) {
	uart0_sendStr("client���ͳɹ�Inter213_Send_Cb\r\n");
	uart0_sendStr("\r\n Send Success \r\n");
}

/*
 * ������:Inter213_Connect_Cb(void *arg)
 * ����:���ӳɹ���Ļص�����
 */
static void ICACHE_FLASH_ATTR Inter213_Connect_Cb(void *arg) {
	uart0_sendStr("client���ӳɹ�Inter213_Connect_Cb\r\n");
	struct espconn *pespconn = (struct espconn *) arg;
	clientLinkConType *linkTemp = (clientLinkConType *) pespconn->reverse;

	linkTemp->linkEn = TRUE;
	linkTemp->teType = teClient;
	linkTemp->repeaTime = 0;

	os_timer_disarm(&TCP_Init);
	Inter213_TCP_SendData("i am tcp client\r\n", os_strlen("i am tcp client\r\n"));
	displayBlue();
}

/*
 * ������:Inter213_Disconnect_Cb(void *arg)
 * ����:�Ͽ����ӳɹ���Ļص�����
 */
static void ICACHE_FLASH_ATTR Inter213_Disconnect_Cb(void *arg) {
	uart0_sendStr("client�Ͽ����ӳɹ�Inter213_Disconnect_Cb\r\n");
	struct espconn *pespconn = (struct espconn *) arg;
	clientLinkConType *linkTemp = (clientLinkConType *) pespconn->reverse;

	if (pespconn == NULL) {
		return;
	}
	if (pespconn->proto.tcp != NULL) {
		os_free(pespconn->proto.tcp);
	}
	os_free(pespconn);
	linkTemp->linkEn = FALSE;
}
/*
 * ��������Inter213_Reconnect_Cb(void *arg, sint8 errType)
 * ����: �����ص�����
 */
static void ICACHE_FLASH_ATTR Inter213_Reconnect_Cb(void *arg, sint8 errType) {
	uart0_sendStr("client����Inter213_Reconnect_Cb\r\n");
	struct espconn *pespconn = (struct espconn *) arg;
	clientLinkConType *linkTemp = (clientLinkConType *) pespconn->reverse;
	if (linkTemp->linkEn) {
		return;
	}

	if (linkTemp->teToff == TRUE) {
		linkTemp->teToff = FALSE;
		linkTemp->repeaTime = 0;
		if (pespconn->proto.tcp != NULL) {
			os_free(pespconn->proto.tcp);
		}
		os_free(pespconn);
		linkTemp->linkEn = false;
	} else {
		linkTemp->repeaTime++;
		if (linkTemp->repeaTime >= 1) {
			linkTemp->repeaTime = 0;
			if (pespconn->proto.tcp != NULL) {
				os_free(pespconn->proto.tcp);
			}
			os_free(pespconn);
			linkTemp->linkEn = false;
			return;
		}

		pespconn->proto.tcp->local_port = espconn_port();
		espconn_connect(pespconn);
	}
}
/*
 * ������:Inter213_Dns_Cb(const char *name, ip_addr_t *ipaddr, void *arg)
 * ����:dns��ѯ�ص�����
 */
LOCAL void ICACHE_FLASH_ATTR Inter213_Dns_Cb(const char *name,
		ip_addr_t *ipaddr, void *arg) {
	uart0_sendStr("clientdns��ѯInter213_Dns_Cb\r\n");
	struct espconn *pespconn = (struct espconn *) arg;
	clientLinkConType *linkTemp = (clientLinkConType *) pespconn->reverse;
	if (ipaddr == NULL) {
		linkTemp->linkEn = FALSE;
		return;
	}

	if (host_ip.addr == 0 && ipaddr->addr != 0) {
		if (pespconn->type == ESPCONN_TCP) {
			os_memcpy(pespconn->proto.tcp->remote_ip, &ipaddr->addr, 4);
			espconn_connect(pespconn);
		} else {
			os_memcpy(pespconn->proto.udp->remote_ip, &ipaddr->addr, 4);
			espconn_connect(pespconn);
		}
	}
}
void Inter213_InitUDP(char * Remote_IP, int32_t Remote_port,uint32_t Local_port)
{
	char ipTemp[128];
	uint32_t ip = 0;
	user_contype.pCon = (struct espconn *)os_zalloc(sizeof(struct espconn));
	user_contype.pCon->state = ESPCONN_NONE;
	user_contype.linkId = 0;
	ip = ipaddr_addr(Remote_IP);
	user_contype.pCon->type = ESPCONN_UDP;

	user_contype.pCon->proto.udp = (esp_udp *)os_zalloc(sizeof(esp_udp));
	user_contype.pCon->proto.udp->local_port = Local_port;
	user_contype.pCon->proto.udp->remote_port = Remote_port;
	os_memcpy(user_contype.pCon->proto.udp->remote_ip, &ip, 4);
	user_contype.pCon->reverse = &user_contype;
	user_contype.linkEn = TRUE;
	user_contype.teType = teClient;

	espconn_regist_recvcb(user_contype.pCon, Inter213_UDPReceive);
	espconn_regist_sentcb(user_contype.pCon, Inter213_Send_Cb);
	if((ip == 0xffffffff) && (os_memcmp(ipTemp,"255.255.255.255",16) != 0))  {
	espconn_gethostbyname(user_contype.pCon, ipTemp, &host_ip, Inter213_Dns_Cb);
	} else {
	  espconn_create(user_contype.pCon);
	}
}
void reset_light() {
	os_timer_disarm(&LIGHT_CHANGE);
	displayBlue();
}
/*
 * ������:Inter213_Receive(void *arg, char *pdata, unsigned short len)
 * ����:���ջص�����
 */
static void ICACHE_FLASH_ATTR Inter213_UDPReceive(void *arg, char *pdata, unsigned short len) {
	uart0_sendStr(pdata);

	os_timer_disarm(&LIGHT_CHANGE);
	os_timer_setfn(&LIGHT_CHANGE,(os_timer_func_t *)reset_light,NULL);
	int i;
	int instruction_type = pdata[0] - '0';
	char *data = pdata + 1;
	if(instruction_type == INSTRUCTION_OPEN) {
		uart0_sendStr("\r\n����ָ��\r\n");
		uart0_sendStr("\r\n����ҵ��Ȩ��\r\n");
		authNode *temp = owner_auth.head;
		while(temp && strcmp(data, temp->value) != 0) {
			uart0_sendStr("\r\n");
			uart0_sendStr(temp->value);
			temp = temp->next;
		}
		if(temp != NULL) {
			InterNet_UDP_SendData(user_contype.pCon->proto.udp->remote_ip, user_contype.pCon->proto.udp->remote_port, "{\"code\": 1}", os_strlen("{\"code\": 1}"));
			displayGreen();
			os_timer_arm(&LIGHT_CHANGE,5000,0);
			return;
		}
		uart0_sendStr("\r\n���ҷÿ�Ȩ��\r\n");
		temp = visitor_auth.head;
		while(temp && strcmp(data, temp->value) != 0) {
			uart0_sendStr("\r\n");
			uart0_sendStr(temp->value);
			temp = temp->next;
		}
		if(temp != NULL) {
			InterNet_UDP_SendData(user_contype.pCon->proto.udp->remote_ip, user_contype.pCon->proto.udp->remote_port, "{\"code\": 1}", os_strlen("{\"code\": 1}"));
			displayPurple();
			os_timer_arm(&LIGHT_CHANGE,5000,0);
			return;
		}
		uart0_sendStr("δ�ҵ�\r\n");
		InterNet_UDP_SendData(user_contype.pCon->proto.udp->remote_ip, user_contype.pCon->proto.udp->remote_port, "{\"code\": -1}", os_strlen("{\"code\": -1}"));
		displayRed();
		os_timer_arm(&LIGHT_CHANGE,5000,0);
	} else if(instruction_type == INSTRUCTION_AUTH_APPLY) {
		uart0_sendStr("��Ȩ����ָ��\r\n");
		//ת��
		os_sprintf(out, "{type:\"apply\",data: \"%s\"}", data);
		uart0_sendStr(out);
		Inter213_TCP_SendData(data, os_strlen(data));
	} else {
		uart0_sendStr("δָ֪��\r\n");
	}
	return;
}
/*
 * ������:void (char * Remote_IP, int32_t Remote_port,uint8 *buf,uint16 len)
 * ����:���ݷ���
 */
void InterNet_UDP_SendData(char * Remote_IP, int32_t Remote_port,uint8 *buf,uint16 len)
{
  uint32_t ip = 0;
  ip = ipaddr_addr(Remote_IP);
  user_contype.pCon->proto.udp->remote_port = Remote_port;
  os_memcpy(user_contype.pCon->proto.udp->remote_ip, &ip, 4);
  espconn_sent(user_contype.pCon,buf,len);
}
/*
 * ������:void Inter213_InitTCP(char * ipAddress, int32_t port)
 * ����:����TCP����
 */
//ipAddress:ip��ַ     port:�˿ں�
void Inter213_InitTCP(char * ipAddress, int32_t port) {
	uart0_sendStr("client����TCP����Inter213_InitTCP\r\n");
	char ipTemp[128];
	uint32_t ip = 0;
	client_user_contype.pCon = (struct espconn *) os_zalloc(sizeof(struct espconn));
	client_user_contype.pCon->state = ESPCONN_NONE;
	client_user_contype.linkId = 0;
	ip = ipaddr_addr(ipAddress);
	client_user_contype.pCon->type = ESPCONN_TCP;

	client_user_contype.pCon->proto.tcp = (esp_tcp *) os_zalloc(sizeof(esp_tcp));
	client_user_contype.pCon->proto.tcp->local_port = espconn_port();
	client_user_contype.pCon->proto.tcp->remote_port = port;
	os_memcpy(client_user_contype.pCon->proto.tcp->remote_ip, &ip, 4);
	client_user_contype.pCon->reverse = &client_user_contype;

	espconn_regist_recvcb(client_user_contype.pCon, Inter213_Receive); ////////
	espconn_regist_sentcb(client_user_contype.pCon, Inter213_Send_Cb); ///////
	espconn_regist_connectcb(client_user_contype.pCon, Inter213_Connect_Cb);
	espconn_regist_disconcb(client_user_contype.pCon, Inter213_Disconnect_Cb);
	espconn_regist_reconcb(client_user_contype.pCon, Inter213_Reconnect_Cb);

	if ((ip == 0xffffffff) && (os_memcmp(ipTemp, "255.255.255.255", 16) != 0)) {
		espconn_gethostbyname(client_user_contype.pCon, ipAddress, &host_ip,
				Inter213_Dns_Cb);
	} else {
		espconn_connect(client_user_contype.pCon);
	}
}
/*
 * ������:void Inter213Net_TCP_SendData(uint8 *buf,uint16 len)
 * ����:���ݷ���
 */
//buf:����ָ��    len:����
void Inter213_TCP_SendData(uint8 *buf, uint16 len) {
	uart0_sendStr("client���ݷ���Inter213_TCP_SendData\r\n");
	espconn_sent(client_user_contype.pCon, buf, len);
}
/*
 * ������:Init_InterNet(void)
 * ����:·��������
 */
void Inter213Init(void) {
	uart0_sendStr("client·��������Inter213Init\r\n");
	struct station_config stationConf;
	os_bzero(&stationConf, sizeof(struct station_config));
//	wifi_set_opmode(STATION_MODE);
	//wifi_station_get_config(&stationConf);
	os_strcpy(stationConf.ssid, "TP-LINK_5609");			//ssid
	os_strcpy(stationConf.password, "56095609"); //password
//	os_strcpy(stationConf.ssid, "DDW");			//ssid
//	os_strcpy(stationConf.password, "dengdengwa"); //password
	wifi_station_disconnect();
	ETS_UART_INTR_DISABLE();
	wifi_station_set_config(&stationConf);
	ETS_UART_INTR_ENABLE();
	wifi_station_connect();
}
/*
 * ������:Check_WifiState(void)
 * ����: wifi��ѯ״̬ ���ӻ���δ����
 */
void Check_WifiState(void) {
	uart0_sendStr("clientwifi��ѯ״̬Check_WifiState\r\n");
	uint8 getState;
	getState = wifi_station_get_connect_status();
	if (getState == STATION_GOT_IP) //���״̬��ȷ��֤���Ѿ�����
			{
		uart0_sendStr("GET IP");
		os_timer_disarm(&checkTimer_wifistate);
		os_timer_disarm(&wifi_Conn);
		os_timer_arm(&TCP_Init, 500, 0);
	}
}
/*
 * ������:void wifi_Conn(void)
 * ����:wifi����
 */
void wifi_Conn(void) {
	uart0_sendStr("clientwifi����wifi_Conn\r\n");
	Inter213Init();
}
/*
 * ������:void TCP_Comm(void)
 * ����:TCP����
 */
void TCP_Conn(void) {
	uart0_sendStr("clientTCP����TCP_Comm\r\n");
	Inter213_InitTCP("172.19.10.234", 8266);		//����TCP
//	Inter213_InitTCP("192.168.1.254", 8266);		//����TCP
}
/*
 * ������:void TCP_Comm(void)
 * ����:UDP����
 */
void UDP_Conn(void)
{
	Inter213_InitUDP("192.168.4.1",8266,8235);
}
/*
 * ������:void Esp8266_TCPClient_Time_Init(void)
 * ����:��ʼ����ʱ��
 */
void Esp8266_TCPClient_Time_Init(void) //tcp_client ��ʱ����ʼ��
{
	uart0_sendStr("client��ʼ����ʱ��Esp8266_TCPClient_Time_Init\r\n");
	os_timer_disarm(&checkTimer_wifistate);
	os_timer_setfn(&checkTimer_wifistate, (os_timer_func_t *) Check_WifiState, NULL);
	os_timer_arm(&checkTimer_wifistate, 500, 1);

	os_timer_disarm(&Wifi_Init);
	os_timer_setfn(&Wifi_Init, (os_timer_func_t *) wifi_Conn, NULL);
	os_timer_arm(&Wifi_Init, 500, 0);

	os_timer_disarm(&TCP_Init);
	os_timer_setfn(&TCP_Init, (os_timer_func_t *) TCP_Conn, NULL);

}

/*
 * ������:void Esp8266_TCPClient_Time_Init(void)
 * ����:��ʼ����ʱ��
 */
void Esp8266_UDPServer_Time_Init(void) //tcp_client ��ʱ����ʼ��
{
	  os_timer_disarm(&UDP_Init);
	  os_timer_setfn(&UDP_Init,(os_timer_func_t *)UDP_Conn,NULL);
	  os_timer_arm(&UDP_Init,500,0);

}



