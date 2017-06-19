/*
 * wifi_entrance.c
 *
 *  Created on: 2017年5月13日
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
	gpio_output_set(BIT13, BIT12 | BIT15, BIT13 | BIT15 | BIT12, 0); //BIT13 蓝
}
void ICACHE_FLASH_ATTR displayRed() {
	gpio_output_set(BIT15, BIT12 | BIT13, BIT13 | BIT15 | BIT12, 0); //BIT15 红
}
void ICACHE_FLASH_ATTR displayGreen() {
	gpio_output_set(BIT12, BIT15 | BIT13, BIT13 | BIT15 | BIT12, 0); //BIT12 绿
}
void ICACHE_FLASH_ATTR displayYellow() {
	gpio_output_set(BIT15 | BIT12, BIT13, BIT13 | BIT15 | BIT12, 0); //BIT12 黄
}
void ICACHE_FLASH_ATTR displayPurple() {
	gpio_output_set(BIT15 | BIT13, BIT12, BIT13 | BIT15 | BIT12, 0); //BIT12 黄
}

/*
 * 函数名:void Wifi_Init()
 * 功能wifi_ap+sta初始化
 */
void WIFI_Init() {

	uart0_sendStr("WIFI_APInit\r\n");
	/***************************模式设置************************************/
	if (wifi_set_opmode(STATIONAP_MODE)) {			//	设置为AP模式

	} else {

	}
	/***************************名字设通道置************************************/
	uart0_sendStr("初始化AP\r\n");
	struct softap_config apConfig;
	os_bzero(&apConfig, sizeof(struct softap_config));
	wifi_softap_get_config(&apConfig);
	apConfig.ssid_len = os_strlen("WifiEntrance");						//设置ssid长度
	os_strcpy(apConfig.ssid, "WifiEntrance");			//设置ssid名字
	os_strcpy(apConfig.password, "12345678");	//设置密码
	apConfig.authmode = 3;						//设置加密模式
	ETS_UART_INTR_DISABLE();					//关闭串口中断
	wifi_softap_set_config(&apConfig);		//配置
	ETS_UART_INTR_ENABLE();					//打开串口

}
/*
 * 函数名:void WIFI_TCP_SendNews(unsigned char *dat)
 * 功能:像TCP服务器发送消息
 */
void WIFI_TCP_SendNews(unsigned char *dat) {
	uart0_sendStr("向TCP服务器发送消息WIFI_TCP_SendNews\r\n");
	espconn_sent(pLink.pCon, dat, os_strlen(dat));
}


/*
 * 函数名:Inter213_Receive(void *arg, char *pdata, unsigned short len)
 * 功能:接收回调函数
 */
static void ICACHE_FLASH_ATTR Inter213_Receive(void *arg, char *pdata, unsigned short len) {
	uart0_sendStr("\r\nclient接收回调Inter213_Receive\r\n");
	int instruction_type = pdata[0] - '0';
	uart0_sendStr(pdata);
	char *data = (char *)os_malloc((len - 1) * sizeof(char));
	strcpy(data, pdata + 1);
	//新分配一个node
	authNode *node = (authNode *)os_malloc(sizeof(authNode));
	node->value = data;
	node->next = NULL;
	if (instruction_type == INSTRUCTION_GET_OWNER_AUTH) {
		uart0_sendStr("\r\n从服务器获取一条业主授权信息\r\n");
		if(owner_auth.length == NULL) {
			uart0_sendStr("收到的是第一条\r\n");
			//记录业主链表尾
			owner_tail = node;
			owner_auth.head = node;
			owner_auth.length = 1;
		} else {
			uart0_sendStr("收到的不是第一条\r\n");
			//连接业主node
			owner_tail->next = node;

			//记录业主链表尾
			owner_tail = node;

			owner_auth.length = 1 + owner_auth.length;
		}
		os_sprintf(out, "owner_auth.length：%d\r\n", owner_auth.length);
		uart0_sendStr(out);
		authNode *temp = owner_auth.head;
		while(temp) {
			uart0_sendStr(temp->value);
			temp = temp->next;
		}
	} else if (instruction_type == INSTRUCTION_GET_VISITOR_AUTH) {
		uart0_sendStr("从服务器获取一条访客授权信息\r\n");
		uart0_sendStr("\r\n从服务器获取一条业主授权信息\r\n");
		if(visitor_auth.length == NULL) {
			uart0_sendStr("收到的是第一条\r\n");
			//记录访客链表尾
			visitor_tail = node;

			visitor_auth.head = node;
			visitor_auth.length = 1;
		} else {
			uart0_sendStr("收到的不是第一条\r\n");
			//连接访客node
			visitor_tail->next = node;

			//记录访客链表尾
			visitor_tail = node;

			visitor_auth.length = 1 + visitor_auth.length;
		}
		os_sprintf(out, "owner_auth.length：%d\r\n", visitor_auth.length);
		uart0_sendStr(out);
		authNode *temp = visitor_auth.head;
		while(temp) {
			uart0_sendStr(temp->value);
			temp = temp->next;
		}
	} else {
		uart0_sendStr("未知服务器指令\r\n");
	}
	return;
}
/*
 * 函数名:Inter213_Send_Cb(void *arg)
 * 功能:发送成功的回调函数
 */
static void ICACHE_FLASH_ATTR Inter213_Send_Cb(void *arg) {
	uart0_sendStr("client发送成功Inter213_Send_Cb\r\n");
	uart0_sendStr("\r\n Send Success \r\n");
}

/*
 * 函数名:Inter213_Connect_Cb(void *arg)
 * 功能:连接成功后的回调函数
 */
static void ICACHE_FLASH_ATTR Inter213_Connect_Cb(void *arg) {
	uart0_sendStr("client连接成功Inter213_Connect_Cb\r\n");
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
 * 函数名:Inter213_Disconnect_Cb(void *arg)
 * 功能:断开连接成功后的回调函数
 */
static void ICACHE_FLASH_ATTR Inter213_Disconnect_Cb(void *arg) {
	uart0_sendStr("client断开连接成功Inter213_Disconnect_Cb\r\n");
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
 * 函数名：Inter213_Reconnect_Cb(void *arg, sint8 errType)
 * 功能: 重联回调函数
 */
static void ICACHE_FLASH_ATTR Inter213_Reconnect_Cb(void *arg, sint8 errType) {
	uart0_sendStr("client重联Inter213_Reconnect_Cb\r\n");
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
 * 函数名:Inter213_Dns_Cb(const char *name, ip_addr_t *ipaddr, void *arg)
 * 功能:dns查询回调函数
 */
LOCAL void ICACHE_FLASH_ATTR Inter213_Dns_Cb(const char *name,
		ip_addr_t *ipaddr, void *arg) {
	uart0_sendStr("clientdns查询Inter213_Dns_Cb\r\n");
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
 * 函数名:Inter213_Receive(void *arg, char *pdata, unsigned short len)
 * 功能:接收回调函数
 */
static void ICACHE_FLASH_ATTR Inter213_UDPReceive(void *arg, char *pdata, unsigned short len) {
	uart0_sendStr(pdata);

	os_timer_disarm(&LIGHT_CHANGE);
	os_timer_setfn(&LIGHT_CHANGE,(os_timer_func_t *)reset_light,NULL);
	int i;
	int instruction_type = pdata[0] - '0';
	char *data = pdata + 1;
	if(instruction_type == INSTRUCTION_OPEN) {
		uart0_sendStr("\r\n开门指令\r\n");
		uart0_sendStr("\r\n查找业主权限\r\n");
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
		uart0_sendStr("\r\n查找访客权限\r\n");
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
		uart0_sendStr("未找到\r\n");
		InterNet_UDP_SendData(user_contype.pCon->proto.udp->remote_ip, user_contype.pCon->proto.udp->remote_port, "{\"code\": -1}", os_strlen("{\"code\": -1}"));
		displayRed();
		os_timer_arm(&LIGHT_CHANGE,5000,0);
	} else if(instruction_type == INSTRUCTION_AUTH_APPLY) {
		uart0_sendStr("授权申请指令\r\n");
		//转发
		os_sprintf(out, "{type:\"apply\",data: \"%s\"}", data);
		uart0_sendStr(out);
		Inter213_TCP_SendData(data, os_strlen(data));
	} else {
		uart0_sendStr("未知指令\r\n");
	}
	return;
}
/*
 * 函数名:void (char * Remote_IP, int32_t Remote_port,uint8 *buf,uint16 len)
 * 功能:数据发送
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
 * 函数名:void Inter213_InitTCP(char * ipAddress, int32_t port)
 * 功能:配置TCP连接
 */
//ipAddress:ip地址     port:端口号
void Inter213_InitTCP(char * ipAddress, int32_t port) {
	uart0_sendStr("client配置TCP连接Inter213_InitTCP\r\n");
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
 * 函数名:void Inter213Net_TCP_SendData(uint8 *buf,uint16 len)
 * 功能:数据发送
 */
//buf:数据指针    len:长度
void Inter213_TCP_SendData(uint8 *buf, uint16 len) {
	uart0_sendStr("client数据发送Inter213_TCP_SendData\r\n");
	espconn_sent(client_user_contype.pCon, buf, len);
}
/*
 * 函数名:Init_InterNet(void)
 * 功能:路由器连接
 */
void Inter213Init(void) {
	uart0_sendStr("client路由器连接Inter213Init\r\n");
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
 * 函数名:Check_WifiState(void)
 * 功能: wifi查询状态 连接或者未连接
 */
void Check_WifiState(void) {
	uart0_sendStr("clientwifi查询状态Check_WifiState\r\n");
	uint8 getState;
	getState = wifi_station_get_connect_status();
	if (getState == STATION_GOT_IP) //如果状态正确，证明已经连接
			{
		uart0_sendStr("GET IP");
		os_timer_disarm(&checkTimer_wifistate);
		os_timer_disarm(&wifi_Conn);
		os_timer_arm(&TCP_Init, 500, 0);
	}
}
/*
 * 函数名:void wifi_Conn(void)
 * 功能:wifi连接
 */
void wifi_Conn(void) {
	uart0_sendStr("clientwifi连接wifi_Conn\r\n");
	Inter213Init();
}
/*
 * 函数名:void TCP_Comm(void)
 * 功能:TCP连接
 */
void TCP_Conn(void) {
	uart0_sendStr("clientTCP连接TCP_Comm\r\n");
	Inter213_InitTCP("172.19.10.234", 8266);		//连接TCP
//	Inter213_InitTCP("192.168.1.254", 8266);		//连接TCP
}
/*
 * 函数名:void TCP_Comm(void)
 * 功能:UDP连接
 */
void UDP_Conn(void)
{
	Inter213_InitUDP("192.168.4.1",8266,8235);
}
/*
 * 函数名:void Esp8266_TCPClient_Time_Init(void)
 * 功能:初始化定时器
 */
void Esp8266_TCPClient_Time_Init(void) //tcp_client 定时器初始化
{
	uart0_sendStr("client初始化定时器Esp8266_TCPClient_Time_Init\r\n");
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
 * 函数名:void Esp8266_TCPClient_Time_Init(void)
 * 功能:初始化定时器
 */
void Esp8266_UDPServer_Time_Init(void) //tcp_client 定时器初始化
{
	  os_timer_disarm(&UDP_Init);
	  os_timer_setfn(&UDP_Init,(os_timer_func_t *)UDP_Conn,NULL);
	  os_timer_arm(&UDP_Init,500,0);

}



