/*
 * wifi_entrance.h
 *
 *  Created on: 2017年5月13日
 *      Author: Listener
 */

#ifndef WIFI_ENTRANCE_GUARD_SYSTEM_APP_INCLUDE_WIFI_ENTRANCE_H_
#define WIFI_ENTRANCE_GUARD_SYSTEM_APP_INCLUDE_WIFI_ENTRANCE_H_

os_timer_t checkTimer_wifistate;
os_timer_t Wifi_Init;
os_timer_t UDP_Init;
os_timer_t TCP_Init;
os_timer_t LIGHT_CHANGE;

char out[64];
typedef enum {
	teClient, teServer
} teType;
typedef struct {
	BOOL linkEn;
	BOOL teToff;
	uint8_t linkId;
	teType teType;
	uint8_t repeaTime;
	uint8_t changType;
	uint8 remoteIp[4];
	int32_t remotePort;
	struct espconn *pCon;
} linkConType;

typedef struct {
	BOOL linkEn;
	BOOL teToff;
	uint8_t linkId;
	teType teType;
	uint8_t repeaTime;
	struct espconn *pCon;
} espConnectionType;

struct node{
	char *value;
	struct node *next;
};
typedef struct node authNode;

typedef struct {
	int length;
	authNode *head;
} auth;

linkConType pLink;
espConnectionType user_contype;

#define  clientLinkConType    espConnectionType
espConnectionType client_user_contype;
static ip_addr_t host_ip;

void ICACHE_FLASH_ATTR displayBlue();
void ICACHE_FLASH_ATTR displayRed();
void ICACHE_FLASH_ATTR displayGreen();
void ICACHE_FLASH_ATTR displayYellow();
//初始化tcp服务器
void server_init(struct ip_addr *local_ip,int port);
//授权函数
int ICACHE_FLASH_ATTR authorize(char *owner[], char *visitor[], char *id);
//STA连接WiFi
void wifi_Conn(void);
//查询WiFi状态
void Check_WifiState(void);

//udp
static void ICACHE_FLASH_ATTR Inter213_UDPReceive(void *arg, char *pdata, unsigned short len);
void InterNet_UDP_SendData(char * Remote_IP, int32_t Remote_port,uint8 *buf,uint16 len);

//tcp
void TCP_Conn(void);
void Inter213_TCP_SendData(uint8 *buf, uint16 len);

#endif /* WIFI_ENTRANCE_GUARD_SYSTEM_APP_INCLUDE_WIFI_ENTRANCE_H_ */
