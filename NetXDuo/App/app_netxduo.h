#ifndef __APP_NETXDUO_H__
#define __APP_NETXDUO_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "nx_api.h"
#include "nxd_dhcp_client.h"
#include "nxd_mqtt_client.h"
#include "nxd_sntp_client.h"
#include "nxd_dns.h"
#include "nx_stm32_eth_driver.h"
#include "main.h"

/* The APP_DEFAULT_PAYLOAD_SIZE should match with RxBuffLen configured via MX_ETH_Init */
#ifndef APP_DEFAULT_PAYLOAD_SIZE
#define APP_DEFAULT_PAYLOAD_SIZE                          1536
#endif
#define APP_PACKET_POOL_SIZE                              ((APP_DEFAULT_PAYLOAD_SIZE + sizeof(NX_PACKET)) * 10)

/**
 * Golden rule of network thread priorities.
 * When setting priorities, always structure them from the bottom of the network stack to the top:
 * 1. Highest Priority: Network Interface / Driver Thread (Handles hardware interrupts and moves
 *    packets from the Ethernet/Wi-Fi hardware to RAM).
 * 2. Medium-High Priority: IP Instance / Core TCP/IP Stack Thread (Processes routing, ARP, TCP
 *    state machines, and ICMP).
 * 3. Medium-Low Priority: Standard Network Services (DHCP, DNS, NTP).
 * 4. Lowest Network Priority: Application Protocols (MQTT, HTTP, CoAP)
 * Why? If your MQTT application thread has a higher priority than the IP stack, it will starve
 * the IP stack of CPU time. The IP stack won't be able to process incoming packets, causing the
 * MQTT socket to timeout and drop.
 * Exception Note: If using the AutoIP protocol alongside DHCP, NetX Duo constraints require that
 * the DHCP thread has a higher priority than both the IP instance thread and the AutoIP thread.
 *
 * DHCP and SNTP client thread priority are defined in nx_user.h.
 */
#define APP_MAIN_THREAD_PRIORITY                          5
#define APP_IP_INSTANCE_PRIORITY                          APP_MAIN_THREAD_PRIORITY
#define APP_SNTP_APPLICATION_PRIORITY                     8
#define APP_MQTT_CLIENT_THREAD_PRIORTY                    10
#define APP_MQTT_SEND_MESSAGE_PRIORITY                    11
#define APP_MQTT_RECEIVED_MESSAGE_PRIORITY                12
#define APP_TELEMETRY_DATA_PRIORITY                       13
#define APP_DEVICE_REPORT_PRIORITY                        14
#define APP_LINK_CHECK_PRIORITY                           18
#define APP_MQTT_CONNECTION_CHECK_PRIORITY                19


/* Thread stack size */
#define APP_MAIN_THREAD_STACK_SIZE                        (2 * 1024)
#define APP_IP_INSTANCE_THREAD_STACK_SIZE                 (4 * 1024)
#define APP_SNTP_APPLICATION_THREAD_STACK_SIZE            (2 * 1024)
#define APP_MQTT_CLIENT_THREAD_STACK_SIZE                 (4 * 1024)
#define APP_RECEIVED_MESSAGE_THREAD_STACK_SIZE            (4 * 1024)
#define APP_TELEMETRY_DATA_THREAD_STACK_SIZE              (4 * 1024)
#define APP_DEVICE_REPORT_THREAD_STACK_SIZE               (2 * 1024)
#define APP_SEND_MESSAGE_THREAD_STACK_SIZE                (4 * 1024)
#define APP_MQTT_CONNECTION_CHECK_THREAD_STACK_SIZE       (4 * 1024)
#define APP_LINK_CHECK_THREAD_STACK_SIZE                  (2 * 1024)


/* ARP configuration */
#define APP_ARP_CACHE_SIZE                                1024

/* DNS server address */
#define APP_DNS_ADDRESS                                   IP_ADDRESS(1, 1, 1, 1)

/* SNTP Client configuration */
#define APP_SNTP_SERVER_NAME                              "time1.google.com"
#define APP_SNTP_CLIENT_REQUEST_TIMEOUT                   10  /* 10s */


/* MQTT Client configuration */
//#define MOSQUITTO_MQTT_PUBLIC
#ifdef MOSQUITTO_MQTT_PUBLIC
#define MQTT_BROKER_NAME                                  "test.mosquitto.org"
#else
#define LOCAL_SERVER_ADDRESS                              (IP_ADDRESS(192, 168, 0, 104))
#endif /* MOSQUITTO_MQTT_PUBLIC */

#define APP_BROKER_CERT_FILE                              "mosquitto.cert.h"
/* Define the MQTT keep alive timer for 5 minutes */
#define APP_MQTT_KEEP_ALIVE_TIMER                         300
#define APP_MQTT_CLEAN_SESSION                            NX_TRUE
#define APP_MQTT_PORT                                     NXD_MQTT_TLS_PORT
#define APP_MQTT_QOS0                                     0
#define APP_MQTT_QOS1                                     1
#define APP_DEVICE_ID                                     "6ad04be599d793e64d265b72"
#define APP_DEVICE_TOKEN                                  "111111"
#define APP_MQTT_MESSAGE_RECEIVED_EVENT                   1
#define APP_MQTT_MAX_TOPIC_LENGTH                         128
#define APP_MQTT_MAX_MESSAGE_LENGTH                       256


#define APP_DEFAULT_IP_ADDRESS                            0
#define APP_DEFAULT_NET_MASK                              0
#define APP_NULL_IP_ADDRESS                               0
/* Equivalent to 70 years in sec calculated with www.epochconverter.com/date-difference */
#define APP_EPOCH_TIME_DIFF                               2208988800
#define APP_CABLE_CONNECTION_CHECK_PERIOD                 (3 * NX_IP_PERIODIC_RATE)
#define APP_DEFAULT_TIMEOUT                               (5 * NX_IP_PERIODIC_RATE)
#define APP_LINK_STATUS_UP                                1
#define APP_LINK_STATUS_DOWN                              0

/* Sending message queue type */
#define APP_SENDING_MESSAGE_QUEUE_SIZE                    10
#define APP_MESSAGE_TYPE_SEND_REPORT                      1
#define APP_MESSAGE_TYPE_SEND_TELEMETRY_DATA              2

/* Common wrapper structure for sending message type in queue */
typedef struct
{
    UINT message_type;
    union
    {
        INT temperature;
    } payload;
} APP_SENDING_MESSAGE_INFO;

/* STM32CubeMX export function for NetxDuo application */
UINT MX_NetXDuo_Init(VOID *memory_ptr);

#ifdef __cplusplus
}
#endif
#endif /* __APP_NETXDUO_H__ */
