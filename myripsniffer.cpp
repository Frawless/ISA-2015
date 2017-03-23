/************************************************
*                                               *
*   Autor: Jakub Stejskal                       *
*   Login: xstejs24                             *
*   Nazev souboru: myripsniffer.cpp             *
*   Projekt: projek do předmětu ISA        	*
*                                               *
************************************************/

//inkludované knihovny
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#include <iostream>
#include <fstream>
#include <sstream>

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <netinet/ip6.h>
#include <netinet/if_ether.h>

#include "tables.h"


using namespace std;    // Or using std::string
typedef std::string NetError;

//pcap socket deskriptor
pcap_t* packetDesc;
//globální proměnná pro velikost hlavičky
int linkhdrlen;

//struktura pro jméno interface
typedef struct{
	int ErrParam;
	int optindNumber;
	char interface[255];
} INTERFACE_NAME;

	
/**
 * Funkce pro ukončení snifferu
 * @param ripHdr RIP_HEADER struktura s informacemi o RIP hlavičce
 * @param ripAuth RIP_AUTH struktura s informacemi o RIP zabezpeční
 * @param udpHdr UDP struktura s informacemi o UDP části packetu
 * @param srcip Zdrojová IP packetu
 * @param dstip Cílová IP packetu
 * @param out Výpis informací z RIP_EXT struktury
 * @param passSet Hodnota true/false podle toho, zda je zadané heslo.
 **/
void printfRIP(RIP_HEADER* ripHdr, 
			   RIP_AUTH* ripAuth, 
			   udphdr* udpHdr, 
			   char* srcip, 
			   char* dstip,
			   string out,
			   bool passSet
			  )
{
		
	//čas
	time_t now = time(0);
	// convert now to string form
	char* dt = ctime(&now);
	//typ RIP packetu
	char packetType[10];
	
	sprintf(packetType,((int)ripHdr->cmd == 1 ? "REQUEST" : "RESPONSE"));
	
	//switch na verzi RIP packetu 
	switch((int)ripHdr->version){
	  case 1:
		cout<<"+++++++++++++++++++++[RIPv1]+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;
		cout<<"Time: "<<dt;
		cout<<"UDP-RIP-IPv4 "<<srcip<<" -> "<<dstip<<endl;
		cout<<"PortNumber: "<<ntohs(udpHdr->dest)<<endl;
		cout<<"RIP packet type: "<<packetType<<endl;	
		cout<<"Password: NONE"<<endl;
		cout<<"========================================================================================="<<endl;
		cout<<"IP address\t  Netmask\t    NextHop\t      Metrika\tRouteTag   Address Family"<<endl;
		cout<<out;		
		cout<<"========================================================================================="<<endl;
		cout<<"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;
		break;
		
	  case 2:
		switch(passSet){
		  case true:
			cout<<"+++++++++++++++++++++[RIPv2]+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;
			cout<<"Time: "<<dt;
			cout<<"UDP-RIP-IPv4 "<<srcip<<" -> "<<dstip<<endl;
			cout<<"PortNumber: "<<ntohs(udpHdr->dest)<<endl;
			cout<<"RIP packet type: "<<packetType<<endl;
			cout<<"Password: "<<(char*)ripAuth->password<<endl;	
			cout<<"========================================================================================="<<endl;
			cout<<"IP address\t  Netmask\t    NextHop\t      Metrika\tRouteTag   Address Family"<<endl;
			cout<<out;
			cout<<"========================================================================================="<<endl;
			cout<<"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;			
			break;
			
		  case false:
			cout<<"+++++++++++++++++++++[RIPv2]+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;
			cout<<"Time: "<<dt;
			cout<<"UDP-RIP-IPv4 "<<srcip<<" -> "<<dstip<<endl;
			cout<<"PortNumber: "<<ntohs(udpHdr->dest)<<endl;
			cout<<"RIP packet type: "<<packetType<<endl;
			cout<<"Password: NONE"<<endl;	
			cout<<"========================================================================================="<<endl;
			cout<<"IP address\t  Netmask\t    NextHop\t      Metrika\tRouteTag   Address Family"<<endl;;
			cout<<out;	
			cout<<"========================================================================================="<<endl;
			cout<<"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;			
			break;
		}
		break;
	}  
}


/**
 * Funkce ověří parametry z příkazové řádky
 * @param argc počet argumentů
 * @param argv pole argumentů
 * @param argInt struktura s názvem interface pros puštění
 **/
INTERFACE_NAME getParams (int argc, char *argv[], INTERFACE_NAME argInt)
{
	int c;

	//ověření správnosti a počtu argumentů
	//FUNKČNÍ POUZE PRO JEDEN INTERFACE (-i vLan1 vLan0  nejde!!!)
	while((c = getopt(argc,argv, "i:")) != -1 && argc == 3)
	{
		//parametr i + interface_name
		switch(c)
		{
			case 'i':
				strcpy(argInt.interface, optarg);
				argInt.ErrParam = 0;
				break;
			default:
				break;
		}
	}

	argInt.optindNumber = optind;

	//kontrolní výpis pro jméno interface
	//cerr<<argInt.interface<<endl;
	
	//vrací se struktura s názvem interface a optind number
	return argInt;
}

/**
 * Funkce pro otevření požadovaného interfacu
 * @param interface jmeno interface
 * @param secondPar
 **/ 
pcap_t* openInterface(char* interface, const char* secondPar)
{
	pcap_t* packetDesc;  					//packetDescriptor
  
    char errBuf[PCAP_ERRBUF_SIZE];
    
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;


	//otevření zadaného interface
	/** 
	  * pcap_open_live - vestavěná funkce pro poslech na daném interface
	  * @param interface 
      * @param BUFSIZ  - maximální velikost packetu
      * @param promiskuitní mód (1 = true, 0 = false)
      * @param packet read timeout
	  * @param odložný prostor pro chybové zprávy
	  **/
	if((packetDesc = pcap_open_live(interface, BUFSIZ, 1, -1, errBuf)) == NULL)
	{
		cerr<<"Nepovedlo se připojit na interface ->"<<endl;
		cerr<< "pcap_open_live() failed: " << errBuf << endl;
		return NULL;
	}

	//získání Ip adresy a masky
	if(pcap_lookupnet(interface, &srcip, &netmask, errBuf) < 0)
	{
		cerr<<"Nenalezena IP..."<<endl;
		cerr<< "pcap_lookupnet failed: " << errBuf << endl;
		return NULL;
	}

	//konverze paketu
	if(pcap_compile(packetDesc, &bpf, (char*)secondPar, 0, netmask))
	{
		cerr<<"Nepovedlo se konvertovat paket"<<endl;
 		cerr<<"pcap_compile() failed: " <<pcap_geterr(packetDesc)<<endl;
		return NULL;
	} 

	//nastavení filtru
	if(pcap_setfilter(packetDesc, &bpf) < 0)
	{
		cerr<<"Nelze nastavit filter"<<endl;
		cerr<<"pcap_setfilter() failed: " <<pcap_geterr(packetDesc)<<endl;
		return NULL;
	}

	cerr<<"Func: openInterface exit(succes)"<<endl;
	return packetDesc;
}

/**
 * Funkce pro opakované zachtávání packetů
 * @param packetDesc - deskriptor
 * @param func - callback function pro relativní data 
 **/
void capturePacket(pcap_t* packetDesc, pcap_handler func)
{ 
	//funkce pro chytání packetů - dokud není program ukončen
	if(pcap_loop(packetDesc, 0, func, NULL) < 0)
	{
		cerr << "pcap_loop() failed: " << pcap_geterr(packetDesc)<<endl;
		return;
	}
	cerr<<"Func: capturePacket exit(succes)"<<endl;
}

/**
 * Funkce pro parsování přijatých packetů
 * @param 
 **/
//void parsePacket(u_char *user, struct pcap_pkthdr *packetHdr, u_char *packetptr)
void parsePacket(u_char *, struct pcap_pkthdr *, u_char *packetptr)
{
  	//čas
	time_t now = time(0);
	// convert now to string form
	char* localTime = ctime(&now);
	
	
	//struktury pro IP pakety a UDP podsložk
	struct ether_header* etHdr;
	struct ip* ipHdr;
	struct ip6_hdr* ip6Hdr;
	struct udphdr* udpHdr;
	RIP_HEADER* ripHdr;
	RIP_EXT* ripExt;
	RIP_AUTH* ripAuth = NULL;
	RIPng_EXT* ripngExt;
	
	size_t sizeofEth = sizeof(ether_header);
	size_t sizeofIP = sizeof(ip);
	size_t sizeofIPv6 = sizeof(ip6_hdr);
	size_t sizeofUDP = sizeof(udphdr);
	size_t sizeofRIP = sizeof(RIP_HEADER);
	size_t sizeofRIP_E = sizeof(RIP_EXT);
	size_t sizeofRIPng_E = sizeof(RIPng_EXT);
	//size_t sizeofRIP_A = sizeof(RIP_AUTH);
	
	char extInfo[1024];
	string out = "";
	string textov = "";
		
	//#######
	size_t ripExtCount;
		
	//struktura pro hlavičku ethernetu
	etHdr = (struct ether_header*)packetptr;
	packetptr += sizeofEth;

	//řetězce pro zdrojovou a cílovou adresu a informace v hlavičce
	char srcip[255], dstip[255];
	char IPaddress[INET_ADDRSTRLEN];
	char mask[INET_ADDRSTRLEN];
	char nextHop[INET_ADDRSTRLEN];
	
	char IPv6prefix[INET6_ADDRSTRLEN];
	
	//pomocná proměnná pro indikaci zadaného hesla
	bool passSet = false;
		
	//switch na rozeznání IPv4 a IPv6
	switch(ntohs(etHdr->ether_type)){
	
		case ETHERTYPE_IP:

		  ipHdr = (struct ip*)packetptr;
		  packetptr += sizeofIP;
		  
		  //strng copy - překopírujeme zdrojovou a cílovou IP packetu
		  strcpy(srcip, inet_ntoa(ipHdr->ip_src));
		  strcpy(dstip, inet_ntoa(ipHdr->ip_dst));	
		    
		  //vyplnění RIP a UDP header
		  udpHdr = (struct udphdr*)packetptr;
		  packetptr += sizeofUDP;
		  
		  ripHdr = (RIP_HEADER*)packetptr;
		  packetptr += sizeofRIP;
		  
		  //#####################################################################
		  ripExtCount = (ntohs(udpHdr->len)- sizeofUDP) - sizeofRIP;

		  //ověření, zda zbývající velikost packetu odpovídá násobku extension tabulek
		  if(ripExtCount % sizeofRIP_E){
			  return;
		  }

		  //naplělní rip_extension -> neprováděj posun
		  ripExt = (RIP_EXT*)packetptr;
		 // packetptr += sizeofRIP_E;
		  ripExtCount -= sizeofRIP_E;
		  
		  //pokud je zadáno heslo
		  if(ripExt->AdrFamId == 0xFFFF){
			  passSet = true;
			  ripAuth = (RIP_AUTH*)packetptr;

		  }
		  else{
			  //pokud není zadané heslo tak vypisujeme současnou extension tabulku -> další se nenaplní (do cyklu se nedostaneme)
			  inet_ntop(AF_INET, &ripExt->ipAddr, IPaddress, INET_ADDRSTRLEN);
			  inet_ntop(AF_INET, &ripExt->subnetMask, mask, INET_ADDRSTRLEN);
			  inet_ntop(AF_INET, &ripExt->nextHop, nextHop, INET_ADDRSTRLEN);
			  //vyplnění dodatečných informací o ripExt
			  sprintf(extInfo, "%-18s%-18s%-18s%-10d%-11d%-10d\n",
					IPaddress, mask, nextHop, ntohl(ripExt->metric),ntohs(ripExt->routeTag),ntohs(ripExt->AdrFamId));
			  out.append(extInfo);
		  }
		  
		  		 
		  //plnění všech rp_extension pro metriky
		  for(; ripExtCount >= sizeofRIP_E; ripExtCount -= sizeofRIP_E){
			  //
			  packetptr += sizeofRIP_E;
			  ripExt = (RIP_EXT*)packetptr;  
			  
			  //získání adress a masky
			  inet_ntop(AF_INET, &ripExt->ipAddr, IPaddress, INET_ADDRSTRLEN);
			  inet_ntop(AF_INET, &ripExt->subnetMask, mask, INET_ADDRSTRLEN);
			  inet_ntop(AF_INET, &ripExt->nextHop, nextHop, INET_ADDRSTRLEN);
			  
			  //vyplnění dodatečných informací o ripExt
			  sprintf(extInfo, "%-18s%-18s%-18s%-10d%-11d%-10d\n",
					  IPaddress, mask, nextHop, ntohl(ripExt->metric),ntohs(ripExt->routeTag),ntohs(ripExt->AdrFamId));
			  
			  out.append(extInfo);
			  
		  }		  
		  
		  //#####################################################################
		  //výpis RIP IPv4
		  printfRIP(ripHdr, ripAuth, udpHdr, srcip, dstip,out,passSet);
		  out = "";
		  break;
		
		case ETHERTYPE_IPV6:

		  ip6Hdr = (struct ip6_hdr*)packetptr;
		  packetptr += sizeofIPv6;
		  char ipv6_src[INET6_ADDRSTRLEN];
		  char ipv6_dst[INET6_ADDRSTRLEN];
		  inet_ntop(AF_INET6, &(ip6Hdr->ip6_src), ipv6_src, INET6_ADDRSTRLEN);
		  inet_ntop(AF_INET6, &(ip6Hdr->ip6_dst), ipv6_dst, INET6_ADDRSTRLEN);
		  		  
		  //vyplnění RIP a UDP header
		  udpHdr = (struct udphdr*)packetptr;
		  packetptr += sizeofUDP;

		  ripHdr = (RIP_HEADER*)packetptr;
		  packetptr += sizeofRIP;
		  
		  //#####################################################################
		  ripExtCount = (ntohs(udpHdr->len)- sizeofUDP) - sizeofRIP;
		  if(ripExtCount % sizeofRIPng_E){
			  return;
		  }
		  ripExtCount /= sizeofRIPng_E;
		  if(!ripExtCount){
			  return;
		  }
		  
		  //naplělní rip_extension -> neprovádět žádný posun
		  ripngExt = (RIPng_EXT*)packetptr;
		  //packetptr += sizeofRIP_E;
		  //--ripExtCount;
		  
		  //plnění všech rp_extension pro metriky
		  for(; ripExtCount; --ripExtCount){
			  ripngExt = (RIPng_EXT*)packetptr;
			  packetptr += sizeofRIPng_E;
			   
			  inet_ntop(AF_INET6, &ripngExt->ipPrefix, IPv6prefix, INET6_ADDRSTRLEN);

			   //vyplnění dodatečných informací o ripngExt
			  sprintf(extInfo, "%-23s %-15d %-15d %-10d\n",
					  IPv6prefix,ntohs(ripngExt->routeTag), ripngExt->prefixLen, ripngExt->metric);
			  
			  out.append(extInfo);			  
		  }		  
		  
		  char packetType[10];
		  //typ RIP packetu		  
		  sprintf(packetType,((int)ripHdr->cmd == 1 ? "REQUEST" : "RESPONSE"));
		  
		  //výpis informací o packetu
		  cout<<"+++++++++++++++++++++[RIPng]+++++++++++++++++++++++++++++++++++"<<endl;
		  cout<<"Time: "<<localTime;
		  cout<<"UDP-RIPng "<<ipv6_src<<" -> "<<ipv6_dst<<":"<<endl;
		  cout<<"PortNumber: "<<ntohs(udpHdr->dest)<<endl;
		  cout<<"RIP packet type: "<<packetType<<endl;
		  cout<<"==============================================================="<<endl;
		  cout<<"Prefix\t\t\tRouteTag\tPrefixLen\tMetrika"<<endl;
		  cout<<out;
		  cout<<"==============================================================="<<endl;
		  cout<<"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;		  
		  break;
	}
}

/**
 * Funkce pro ukončení snifferu
 * @param signo
 **/
void terminate(int signo)
{
    struct pcap_stat stats;
    if (pcap_stats(packetDesc, &stats) >= 0)
    {
		cerr<<"Packets received: "<<stats.ps_recv<<endl;
		cerr<<"Packets droped: "<<stats.ps_drop<<endl;
    }
    //zavření spojení
    pcap_close(packetDesc);
	cerr<<"Signo number: "<<signo<<endl;
	cerr<<"Func: terminate exit(0)"<<endl;	
    exit(0);
}


//main
int main(int argc, char* argv[])
{
	int i;	//čítač
	INTERFACE_NAME argInt = {1, 1, ""};

	//filtr pro udp RIP and RIPng
	char bpfstr[255] = "((udp) and ((dst port 520) or (dst port 521)))";

	//parsování argumentů
	argInt = getParams(argc,argv,argInt);

	if(argInt.ErrParam != 0){
		cerr<<"Bad arguments format"<<endl;
		exit(1);
	}

    // Get the packet capture filter expression, if any.
    for (i = argInt.optindNumber; i < argc; i++)
    {
        strcat(bpfstr, argv[i]);
        strcat(bpfstr, " ");
    }

	//návázání spojení sd aným interface
	packetDesc = openInterface(argInt.interface, bpfstr);
	
	if(packetDesc == NULL){
		cerr<<"Open interface error"<<endl;
		exit(1);
	}
	
	//ukončení aplikace
	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGQUIT, terminate);
	capturePacket(packetDesc, (pcap_handler)parsePacket);
	
	cerr<<"Func: main exit(succes)"<<endl;
	terminate(0);
}