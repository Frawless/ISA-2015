#ifndef _TABLES_H_
#define _TABLES_H_ 


#include <string>

#include <pcap.h>
#include <sys/types.h>
#include <netinet/in.h>

/* Potřebné hlavičky pro RIP packety */
/* RIP header */
typedef struct{
	u_int8_t cmd;
	u_int8_t version;
	u_int16_t zero;
} RIP_HEADER;

/* RIP entry/extension */
typedef struct{
	u_int16_t AdrFamId;
	u_int16_t routeTag;
	in_addr ipAddr;
	in_addr subnetMask;	
	in_addr nextHop;
	u_int32_t metric;
} RIP_EXT;

/* RIP authorization */
typedef struct{
	u_int16_t AdrFamId;
	u_int16_t type;
	u_int8_t password[16];
} RIP_AUTH;

/* RIPng entry */
typedef struct{
	in6_addr ipPrefix;
	u_int16_t routeTag;
	u_int8_t prefixLen;
	u_int8_t metric;
} RIPng_EXT;

#endif /* _TABLES_H_ */