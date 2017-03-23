/************************************************
*                                               *
*   Autor: Jakub Stejskal                       *
*   Login: xstejs24                             *
*   Nazev souboru: myriprequeste.cpp            *
*   Projekt: projek do předmětu ISA        		*
*                                               *
************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

#include <ctype.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

#include <netdb.h> 
#include "tables.h"
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;    // Or using std::string;

//výčet chybových stavů
enum states{
	ParamOK = 0,
	ErrParam = -1,
	ErrMetric = -10,
	ErrNextHop = -20,
	ErrRouteTag = -30,
	ErrPassword = -40,
	ErrIP_r = -50,
	ErrIP_n = -60,
	ErrMask = -70
};

//struktura pro zadané argumenty
typedef struct{
	int retCode;
	int optindNumber;
	char interface[255], IPaddress[255],subnetMask[255],IPnextHop[255], password[17], IPdestination[255];
	int metric, routerTagValue;
	int optR, optN, optM, optT, optP, optI;
} PROGRAM_PARAMS;


/**
 * Funkce ověří parametry z příkazové řádky
 * @param argc počet argumentů
 * @param argv pole argumentů
 **/
PROGRAM_PARAMS getParams (int argc, char *argv[])
{
	PROGRAM_PARAMS ripResponse = {0,0,"","0.0.0.0","","0.0.0.0","","224.0.0.9",0,0,0,0,0,0,0,0};
	int c;
	char *pend;
	string optarglength;

	//zkouška rozdělení -r přepínače
	std::string delimiter = "/";
	std::string tokenIP;
	std::string tokenMask;
	//pomocné proměnné pro výpočet masky
	int cidrMask;
	unsigned long mask;
		
	//ověření správnosti a počtu argumentů
	//FUNKČNÍ POUZE PRO JEDEN INTERFACE (-i vLan1 vLan0  nejde!!!)
	while((c = getopt(argc,argv, "i:r:p:d:")) != -1)
	{
		switch(c)
		{
			case 'i':
				strcpy(ripResponse.interface, optarg);
				ripResponse.optI++;
				break;
			case 'r':
				 //zkopírování obsahu optarg
				tokenMask = optarg;
				//oddělení Ip adresy od zbytku obsahu
				tokenIP = tokenMask.substr(0, tokenMask.find(delimiter));
				//smazání tokenIP + / -> zbyde jen maska
				tokenMask.erase(0, (tokenIP.length() + delimiter.length()));
								
				//ověření, zda je zadaná IP syntakticky správně
				if(!inet_pton(AF_INET,tokenIP.c_str(), &ripResponse.IPaddress)){
					ripResponse.retCode = ErrIP_r;
				}				
				//nakopírování hodnot
				strcpy(ripResponse.IPaddress, tokenIP.c_str());
				
				//ověření správné syntaxe zadané masky
				cidrMask = strtol(tokenMask.c_str(),&pend,10);
				if(*pend != '\0')
					ripResponse.retCode = ErrMask;
				
				//převedení masky podítě z číselného vyjádření na IP vyjádření - zdroj stackowerflow
				mask = (0xFFFFFFFF << (32 - cidrMask)) & 0xFFFFFFFF;
				sprintf(ripResponse.subnetMask,"%lu.%lu.%lu.%lu", mask >> 24, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF);
				//cerr<<ripResponse.subnetMask<<endl;				
				  
				ripResponse.optR++;
				break;
			case 'd':
				//ověření, zda je zadaná IP syntakticky správně
				if(!inet_pton(AF_INET,optarg, &ripResponse.IPdestination)){
					ripResponse.retCode = ErrIP_n;
				}
				strcpy(ripResponse.IPdestination, optarg);
				ripResponse.optN++;
				break;
			case 'p':
				 optarglength = optarg;
				/*if(optarglength.length() != 16)
					ripResponse.retCode = ErrPassword;
				else
					strcpy(ripResponse.password, optarg);*/
				strcpy(ripResponse.password, optarg);
				ripResponse.optP++;
				break;				
			default:
				ripResponse.retCode = ErrParam;
				break;
		}
	}

	ripResponse.optindNumber = optind;
	
	//testovací vpis
	/*cerr<<"Interface: "<<ripResponse.interface<<endl;
	cerr<<"Ip address -r: "<<ripResponse.IPaddress<<endl;
	cerr<<"Ip address -n: "<<ripResponse.IPnextHop<<endl;
	cerr<<"Metric: "<<ripResponse.metric<<endl;
	cerr<<"Router-tag: "<<ripResponse.routerTagValue<<endl;
	cerr<<"Password: "<<ripResponse.password<<endl;
	cerr<<"Return code: "<<ripResponse.retCode<<endl;*/

	//duplicita parametrů
	if(ripResponse.optR > 1 || ripResponse.optI > 1 ||
	   ripResponse.optN > 1 || ripResponse.optM > 1 ||
	   ripResponse.optP > 1 || ripResponse.optT > 1)
		ripResponse.retCode = ErrParam;		
	
	//swich pro vyhodnocení chybových stavů
	switch(ripResponse.retCode){
		
	  case ErrIP_r:
		cerr<<"Wrong IP - r option!"<<endl;
		exit(1);				
		
	  case ErrPassword:
		cerr<<"Wrong Password!"<<endl;
		exit(1);
		
	  case ErrMask:
		cerr<<"Wrong MASK!"<<endl;
		exit(1);
	
	  case ErrIP_n:
		cerr<<"Destination IP!"<<endl;
		exit(1);
		
	  case ErrParam:
		cerr<<"Multiple parameters!"<<endl;
		exit(1);
	}
	
	//vrací se struktura s názvem interface a optind number
	return ripResponse;
}

/**
 * Funkce naplní strukturu RIP_HEADER potřebnými daty.
 * @param ripHdr ukazatel na strukturu Authentication
 * @param ptr ukazatel na pcket
 * @param datalen hodnota zbývajícího místa v packetuů 
 **/
u_char * hdrFill(RIP_HEADER* ripHdr,
				 u_char* ptr,
				 ssize_t &datalen,
				 size_t sizeofRIP)
{  
	//vytvoření místa v pamětu a namapování packetu na strukturu
	memset(ptr,0, sizeofRIP);
	ripHdr = (RIP_HEADER*)ptr;
	datalen += sizeofRIP;
	
	ripHdr->cmd = 1;
	ripHdr->version = 2;
	
	return ptr + sizeofRIP;
}

/**
 * Funkce naplní strukturu RIP_AUTH potřebnými daty.
 * @param ripAuth ukazatel na strukturu Authentication
 * @param ptr ukazatel na pcket
 * @param datalen hodnota zbývajícího místa v packetu
 * @param ripResponse struktura zpracovaných parametrů 
 **/
u_char * authFill(RIP_AUTH* ripAuth,
				  u_char* ptr,
				  ssize_t &datalen,
				  PROGRAM_PARAMS &ripResponse,
				  size_t sizeofRIP_A
 				)
{
	//vytvoření místa v pamětu a namapování packetu na strukturu
	memset(ptr,0, sizeofRIP_A);
	ripAuth = (RIP_AUTH*)ptr;
	datalen += sizeofRIP_A;
			
	ripAuth->AdrFamId = 0xFFFF;
	ripAuth->type = htons(2);
	strncpy((char *)ripAuth->password, ripResponse.password, sizeof(ripAuth->password));		
	
	return ptr + sizeofRIP_A;
}

/**
 * Funkce naplní strukturu RIP_EXT potřebnými daty.
 * @param ripExt ukazatel na strukturu Extension
 * @param ptr ukazatel na pcket
 * @param datalen hodnota zbývajícího místa v packetu
 * @param ripResponse struktura zpracovaných parametrů 
 **/
u_char * extFill(RIP_EXT* ripExt,
				 u_char* ptr,
				 ssize_t &datalen,
				 PROGRAM_PARAMS &ripResponse,
				 size_t sizeofRIP_E
				)
{  
	//vytvoření místa v pamětu a namapování packetu na strukturu
	memset(ptr,0, sizeofRIP_E);
	ripExt = (RIP_EXT*)ptr;
	datalen += sizeofRIP_E;
	ptr += sizeofRIP_E;	
	
	inet_pton(AF_INET, ripResponse.subnetMask, &ripExt->subnetMask);
	
	if(ripResponse.optN == 0)
	{
		inet_pton(AF_INET, "0.0.0.0", &ripExt->subnetMask);
		ripExt->metric = htonl(16);
		ripExt->AdrFamId = htons(0);
	}
	else
		ripExt->AdrFamId = htons(2);
	//k vložení správných hodnot použijeme strukturu se pracovanými vstupními parametry
	inet_pton(AF_INET, ripResponse.IPaddress, &ripExt->ipAddr);
	ripExt->routeTag = htons(ripResponse.routerTagValue);
	inet_pton(AF_INET, ripResponse.IPnextHop, &ripExt->nextHop);
	return ptr + sizeofRIP_E;
}

/**
 * Funkce pro bind adresy ks ocketu a odeslání packetu.
 * @param sockfd číslo socketu
 * @param src_address zdrojová adresa
 * @param dst_address cílová adresa
 * @param datalen délka packetu 
 * @param packetPtr ukazatel na packet 
 **/
void  bindANDSend(int sockfd,sockaddr_in src_address, sockaddr_in dst_address, ssize_t datalen, u_char *packetPtr)
{
	//bind socketu
	if(bind(sockfd, (struct sockaddr *)&src_address, sizeof(src_address)) < 0)
	{
		cerr <<"Bind() error"<< endl;
		exit(1);
	}

	//odeslání packetu
	if(sendto(sockfd,
			  packetPtr,
			  datalen, 
			  0,
			  (struct sockaddr *)&dst_address,
			  sizeof(dst_address)) != datalen)
	{
		cerr << "Sendto() error"<< endl;
		exit(1);
	}
	close(sockfd);
}

/**
 * Funkce pro zpracování zdrojových adres packetu a odeslánípacketu.
 * @param packetPtr ukazatel na packet
 * @param datalen délka packetu 
 * @param ripResponse struktura se zpracovanými argumenty 
 **/
void sendPacket(u_char *packetPtr, ssize_t datalen, PROGRAM_PARAMS ripResponse)
{
	//struktura pro převod interfacu na adresu
	struct ifreq ifr;
	//struktury pro získání ip adres aktivních interface
	struct ifaddrs *ifaddr, *ifa;
	int flag;
	//adresa rozhraní v podobě řetězce
	char current_ip[NI_MAXHOST];
	//##########################################
	//vytvoření socketu a potřebných adres
	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	sockaddr_in src_address;
	sockaddr_in dst_address;
	memset(&src_address, 0, sizeof(src_address));
	memset(&dst_address, 0, sizeof(dst_address));
	
	src_address.sin_port = htons(520);
	src_address.sin_family = AF_INET;
	//src_address.sin_addr.s_addr = INADDR_ANY;
	
	//vytvoření cílové adresy a portu
	dst_address.sin_port = htons(520);
	dst_address.sin_family = AF_INET;

	inet_pton(AF_INET, ripResponse.IPdestination, &dst_address.sin_addr);
	   
	
	//pokud byl zadán parametr -i
	if(strcmp(ripResponse.interface,"") != 0){
		//převod zadaného interface na adresu
		ifr.ifr_addr.sa_family = AF_INET;

		strncpy(ifr.ifr_name, ripResponse.interface, IFNAMSIZ-1);
		ioctl(sockfd, SIOCGIFADDR, &ifr);	
		
		//uložení adresy zadaného interface
		src_address.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
		
		//odeslání packetu
		bindANDSend(sockfd,src_address,dst_address,datalen,packetPtr);
		
		return;
	}
	else
	{
		//získání všech přístupných síťí	  
		if (getifaddrs(&ifaddr) == -1) 
		{
			cerr << "getifaddrs() error"<< endl;
			exit(EXIT_FAILURE);
		}

		//procházení získaných interface -> přebráno z http://linux.die.net/man/3/getifaddrs  a upraveno //
		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
		{
			if (ifa->ifa_addr == NULL)
				continue;

			if ((ifa->ifa_addr->sa_family == AF_INET)) 
			{
				flag = getnameinfo(ifa->ifa_addr,
						sizeof(struct sockaddr_in),
						current_ip, NI_MAXHOST,
						NULL, 0, NI_NUMERICHOST);
				if (flag != 0) 
				{
					cerr<<"getnameinfo() failed: "<<gai_strerror(flag)<<endl;
					exit(EXIT_FAILURE);
				}

				if(strcmp(current_ip, "") != 0)
				{
					//znovuvytvoření socketu -> nutno pro odelání na více rozraní, nelze použít stejný socket pro bind u více odeslání
					sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
					//orientační výpis
					//printf("%-8s: X%sY\n", ifa->ifa_name, current_ip);
					
					//nastavení získané adresy jako zdroj (ze všech interface se "odešle")
					inet_pton(AF_INET, current_ip, &src_address.sin_addr);
					//odeslání packetu
					bindANDSend(sockfd,src_address,dst_address,datalen,packetPtr);
				}	
			} 
		}
		//free
		freeifaddrs(ifaddr);
	}   	   
}


/**
 * Main
 * @param argc počet argumentů
 * @param argv pole argumentů
 **/
int main(int argc, char* argv[])
{	
	//inicializace struktur pro data RIPu
	PROGRAM_PARAMS ripResponse;
	RIP_HEADER *ripHdr = NULL;
	RIP_AUTH *ripAuth = NULL;
	RIP_EXT *ripExt = NULL;
	
	//potřebné velikosti struktur
	size_t sizeofRIP = sizeof(RIP_HEADER);
	size_t sizeofRIP_E = sizeof(RIP_EXT);
	size_t sizeofRIP_A = sizeof(RIP_AUTH);
	
	
	//vytvoření ukazatele na packet o velikosti "header" + "auth" + "ext" částí
	u_char packetPtr[sizeof(RIP_HEADER) + sizeof(RIP_EXT) + sizeof(RIP_AUTH)];

	//znaménková hodnota pro posouvání v packetu
	ssize_t datalen = 0;
	//ukazatel na ukazatel na packet
	u_char *packetSize = packetPtr;
	
	//zpracování parametrů
	ripResponse = getParams(argc,argv);

	//########################################################
	//naplnění základní hlavičky
	packetSize = hdrFill(ripHdr, packetSize, datalen, sizeofRIP);
	
	//ověření, zda chceme mít packet zaheslovaný
	if(strcmp(ripResponse.password,"") != 0){
		//naplnění části packetu "Authentication"
		packetSize = authFill(ripAuth, packetSize, datalen, ripResponse, sizeofRIP_A);
	}
	
	//baplnění části packetu "Extension"
	packetSize = extFill(ripExt, packetSize, datalen, ripResponse, sizeofRIP_E);

	//vytvoření adres a poslání paketu
	sendPacket(packetPtr,datalen,ripResponse);
	
	exit(0);
}