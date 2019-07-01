#include <node_api.h>
#include <map>
#include <stdio.h>
#include <iostream>
#include <pcap.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#endif
struct networkInterface
{
	char* address;
	char* names;
	bool error;
};
networkInterface getInterfaces(pcap_if_t *d);
char *iptos(u_long in);
using namespace std;
napi_value MyFunction(napi_env env, napi_callback_info info) {

  // const obj = {}
  pcap_if_t *alldevs;
	map <char*, char*> interfaces;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	char source[PCAP_ERRBUF_SIZE + 1];
	source[PCAP_ERRBUF_SIZE] = '\0';
      
	if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

  napi_value arr;
  napi_create_array(env, &arr);

	/* Scan the list printing every entry */
  int cnt  = 0;
	for (d = alldevs; d; d = d->next)
	{
		networkInterface deviceInfo = getInterfaces(d);
		if (!deviceInfo.error) {
      napi_value obj, name, address;
      napi_create_object(env, &obj);
      napi_create_string_utf8(env, deviceInfo.names, NAPI_AUTO_LENGTH, &name);
      napi_create_string_utf8(env, deviceInfo.address, NAPI_AUTO_LENGTH, &address);
      napi_set_named_property(env, obj, "name", name);
      napi_set_named_property(env, obj, "address", address);
      napi_set_element(env, arr, cnt, obj);
      cnt += 1;
		}
	}
  return arr;

}

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;
  napi_value fn;

  status = napi_create_function(env, NULL, 0, MyFunction, NULL, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }

  status = napi_set_named_property(env, exports, "listInterfaces", fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  return exports;
}

networkInterface getInterfaces(pcap_if_t *d)
{
	networkInterface network;
	pcap_addr_t *a;
	if (d->description)
		network.names = d->description;
	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family)
		{
		case AF_INET:
			if (a->addr)
				network.address = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
				network.error = false;
				return network;
		}
	}
	network.error = true;

}
#define IPTOSBUFFERS	12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)