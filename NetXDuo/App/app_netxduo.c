#include "app_netxduo.h"
#include  APP_BROKER_CERT_FILE
#include "lwjson/lwjson.h"
#include "lwjson/lwjson_serializer.h"

/**
 * Todo:
 * 1. Review error handling mechanism
 *     - How to handle error when initialize network stack failed?
 *     - Mechanism to detect error and restart application?
 *     - Replace Error_Handler() in main.h.
 * 2. Evaluate application configuration
 *     - Heap, stack size
 *     - Threads' stack size
 *     - Memory section in linker file, memory section address.
 *         + NetX memory poll size
 *         + Ethernet descriptor size
 *     - Threads' priority
 * 3. Create MAC address using STM32 UID to avoid address collision.
 * 4. Review the usage of STM32 MPU, Flash/DTCM/ITCM memories,
 *    cacheable and non-cacheable memory. Refer to README.md file.
 */
#define PRINT_IP_ADDRESS(addr)                        \
    do                                                \
    {                                                 \
        printf("STM32 %s: %lu.%lu.%lu.%lu \n", #addr, \
               (addr >> 24) & 0xff,                   \
               (addr >> 16) & 0xff,                   \
               (addr >> 8) & 0xff,                    \
               (addr & 0xff));                        \
    } while (0)

/* Variables use to work with IP instance */
static NX_IP app_ip_instance;
static NX_PACKET_POOL app_packet_pool;
static ULONG app_ip_address;
static ULONG app_net_mask;

/* Main application thread */
static TX_THREAD app_main_thread;

/* Variables use for DHCP protocol communication */
static NX_DHCP app_dhcp_client;
static TX_SEMAPHORE app_dhcp_semaphore;

/* Variables use for SNTP protocol communication */
static TX_THREAD app_sntp_thread;
static NX_SNTP_CLIENT app_sntp_client;
static ULONG app_sntp_time_from_epoch;

/* DNS client use to get IP address */
static NX_DNS app_dns_client;

/*
 * Thread variable use to check link status and
 * get new IP address if cable reconnected.
 */
static TX_THREAD app_link_check_thread;

/* Variables use for MQTT communication */
static TX_THREAD app_process_received_message_thread;
static TX_THREAD app_telemetry_data_thread;
static TX_THREAD app_device_report_thread;
static TX_THREAD app_mqtt_connection_check_thread;
static TX_THREAD app_send_message_thread;
static NXD_MQTT_CLIENT app_mqtt_client;
static ULONG app_mqtt_client_stack[APP_MQTT_CLIENT_THREAD_STACK_SIZE];
static TX_EVENT_FLAGS_GROUP app_message_received_flag;
static TX_QUEUE app_send_message_queue;
/* Memory pool for allocating messages to put on queue */
static TX_BLOCK_POOL app_message_block_pool;
extern RNG_HandleTypeDef hrng;

/* Variable use for MQTT TLS communication */
/* Todo: Review how to use these buffers for TLS communication */
/* TLS buffers and certificate containers. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
/* Calculated with nx_secure_tls_metadata_size_calculate */
static CHAR app_crypto_metadata_client[11600];
/* Define the TLS packet reassembly buffer. */
static UCHAR app_tls_packet_buffer[4000];

/* Variables use for LwJson to parse and serialize MQTT messages */
static lwjson_t app_lwjson;
static lwjson_token_t app_tokens_buffer[128];

/* List of thread entry function prototype */
static VOID app_main_thread_entry(ULONG thread_input);
static VOID app_sntp_thread_entry(ULONG thread_input);
static VOID app_process_received_message_thread_entry(ULONG thread_input);
static VOID app_telemetry_data_thread_entry(ULONG thread_input);
static VOID app_device_report_thread_entry(ULONG thread_input);
static VOID app_mqtt_connection_check_thread_entry(ULONG thread_input);
static VOID app_send_message_thread_entry(ULONG thread_input);
static VOID app_link_check_thread_entry(ULONG thread_input);

/* List of callback functions */
static VOID app_ip_address_change_cb(NX_IP *ip_instance, VOID *ptr);
static VOID app_sntp_time_update_cb(NX_SNTP_TIME_MESSAGE *time_update_ptr,
                                    NX_SNTP_TIME *local_time);
static ULONG app_tls_session_time_function(void);
static UINT app_tls_setup_callback(NXD_MQTT_CLIENT *client_pt,
                                   NX_SECURE_TLS_SESSION *TLS_session_ptr,
                                   NX_SECURE_X509_CERT *certificate_ptr,
                                   NX_SECURE_X509_CERT *trusted_certificate_ptr);

static UINT app_dns_create(NX_DNS *dns_ptr);
static UINT app_message_generate_stub(void);

UINT MX_NetXDuo_Init(VOID *memory_ptr)
{
    UINT ret = NX_SUCCESS;
    TX_BYTE_POOL *byte_pool = (TX_BYTE_POOL *)memory_ptr;
    CHAR *pointer;

    /* Initialize the NetXDuo system. */
    nx_system_initialize();

    /* Allocate the memory for packet_pool.  */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_PACKET_POOL_SIZE, TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /**
     * Create the Packet pool to be used for packet allocation,
     * If extra NX_PACKET are to be used the APP_PACKET_POOL_SIZE should be increased.
     */
    ret = nx_packet_pool_create(&app_packet_pool, "NetXDuo App Pool",
                                APP_DEFAULT_PAYLOAD_SIZE, pointer,
                                APP_PACKET_POOL_SIZE);
    if (ret != NX_SUCCESS)
    {
        return NX_POOL_ERROR;
    }

    /* Allocate the memory for Ip_Instance */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_IP_INSTANCE_THREAD_STACK_SIZE,
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* Create the main NX_IP instance */
    ret = nx_ip_create(&app_ip_instance, "NetX Ip instance",
                       APP_DEFAULT_IP_ADDRESS, APP_DEFAULT_NET_MASK,
                       &app_packet_pool, nx_stm32_eth_driver, pointer,
                       APP_IP_INSTANCE_THREAD_STACK_SIZE,
                       APP_IP_INSTANCE_PRIORITY);
    if (ret != NX_SUCCESS)
    {
        return NX_NOT_SUCCESSFUL;
    }

    /* Allocate the memory for ARP */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_ARP_CACHE_SIZE, TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* Enable the ARP protocol and provide the ARP cache size for the IP instance */
    ret = nx_arp_enable(&app_ip_instance, (VOID *)pointer, APP_ARP_CACHE_SIZE);
    if (ret != NX_SUCCESS)
    {
        return NX_NOT_SUCCESSFUL;
    }

    /* Enable the ICMP */
    ret = nx_icmp_enable(&app_ip_instance);
    if (ret != NX_SUCCESS)
    {
        return NX_NOT_SUCCESSFUL;
    }

    /* Enable TCP Protocol */
    ret = nx_tcp_enable(&app_ip_instance);
    if (ret != NX_SUCCESS)
    {
        return NX_NOT_SUCCESSFUL;
    }

    /* Enable the UDP protocol required for  DHCP communication */
    ret = nx_udp_enable(&app_ip_instance);
    if (ret != NX_SUCCESS)
    {
        return NX_NOT_SUCCESSFUL;
    }

    /* Allocate the memory for main thread   */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_MAIN_THREAD_STACK_SIZE, TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* Create NetxDuo main thread */
    ret = tx_thread_create(&app_main_thread, "NetXDuo main thread",
                           app_main_thread_entry, 0, pointer,
                           APP_MAIN_THREAD_STACK_SIZE,
                           APP_MAIN_THREAD_PRIORITY,
                           APP_MAIN_THREAD_PRIORITY,
                           TX_NO_TIME_SLICE,
                           TX_AUTO_START);
    if (ret != TX_SUCCESS)
    {
        return TX_THREAD_ERROR;
    }

    /* Create the DHCP client */
    ret = nx_dhcp_create(&app_dhcp_client, &app_ip_instance, "DHCP client");
    if (ret != NX_SUCCESS)
    {
        return NX_DHCP_ERROR;
    }

    /* Create semaphore for DHCP notification callback  */
    tx_semaphore_create(&app_dhcp_semaphore, "DHCP semaphore", 0);

    printf("Nx_MQTT_Client application started..\n");

    /* Allocate the memory for SNTP client thread   */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_SNTP_APPLICATION_THREAD_STACK_SIZE,
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* create the SNTP client thread */
    ret = tx_thread_create(&app_sntp_thread, "SNTP application thread",
                           app_sntp_thread_entry, 0, pointer,
                           APP_SNTP_APPLICATION_THREAD_STACK_SIZE,
                           APP_SNTP_APPLICATION_PRIORITY,
                           APP_SNTP_APPLICATION_PRIORITY,
                           TX_NO_TIME_SLICE, TX_DONT_START);
    if (ret != TX_SUCCESS)
    {
        return NX_NOT_ENABLED;
    }

    /* Allocate the memory for MQTT message received thread */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_RECEIVED_MESSAGE_THREAD_STACK_SIZE,
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* Create the MQTT message received thread */
    ret = tx_thread_create(&app_process_received_message_thread,
                           "MQTT message received thread",
                           app_process_received_message_thread_entry,
                           0, pointer, APP_RECEIVED_MESSAGE_THREAD_STACK_SIZE,
                           APP_MQTT_RECEIVED_MESSAGE_PRIORITY,
                           APP_MQTT_RECEIVED_MESSAGE_PRIORITY,
                           TX_NO_TIME_SLICE, TX_DONT_START);
    if (ret != TX_SUCCESS)
    {
        return NX_NOT_ENABLED;
    }

    /* Allocate the memory for MQTT telemetry data thread   */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_TELEMETRY_DATA_THREAD_STACK_SIZE,
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* Create MQTT telemetry data thread */
    ret = tx_thread_create(&app_telemetry_data_thread, "Telemetry data thread",
                           app_telemetry_data_thread_entry, 0, pointer,
                           APP_TELEMETRY_DATA_THREAD_STACK_SIZE,
                           APP_TELEMETRY_DATA_PRIORITY,
                           APP_TELEMETRY_DATA_PRIORITY,
                           TX_NO_TIME_SLICE,
                           TX_DONT_START);
    if (ret != TX_SUCCESS)
    {
        return NX_NOT_ENABLED;
    }

    /* Allocate the memory for device status report thread   */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_DEVICE_REPORT_THREAD_STACK_SIZE,
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* Create the device status report thread */
    ret = tx_thread_create(&app_device_report_thread,
                           "Device status report thread",
                           app_device_report_thread_entry,
                           0, pointer,
                           APP_DEVICE_REPORT_THREAD_STACK_SIZE,
                           APP_DEVICE_REPORT_PRIORITY,
                           APP_DEVICE_REPORT_PRIORITY,
                           TX_NO_TIME_SLICE,
                           TX_DONT_START);
    if (ret != TX_SUCCESS)
    {
        return NX_NOT_ENABLED;
    }

    /* Allocate the memory for sending message thread */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_SEND_MESSAGE_THREAD_STACK_SIZE,
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* Create sending message thread */
    ret = tx_thread_create(&app_send_message_thread,
                           "Sending message thread",
                           app_send_message_thread_entry,
                           0, pointer,
                           APP_SEND_MESSAGE_THREAD_STACK_SIZE,
                           APP_MQTT_SEND_MESSAGE_PRIORITY,
                           APP_MQTT_SEND_MESSAGE_PRIORITY,
                           TX_NO_TIME_SLICE,
                           TX_DONT_START);
    if (ret != TX_SUCCESS)
    {
        return NX_NOT_ENABLED;
    }

    /* Allocate the memory for MQTT connection check thread   */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_MQTT_CONNECTION_CHECK_THREAD_STACK_SIZE,
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* Create MQTT connection check thread */
    ret = tx_thread_create(&app_mqtt_connection_check_thread,
                           "MQTT connection check thread",
                           app_mqtt_connection_check_thread_entry,
                           0, pointer,
                           APP_MQTT_CONNECTION_CHECK_THREAD_STACK_SIZE,
                           APP_MQTT_CONNECTION_CHECK_PRIORITY,
                           APP_MQTT_CONNECTION_CHECK_PRIORITY,
                           TX_NO_TIME_SLICE, TX_DONT_START);
    if (ret != TX_SUCCESS)
    {
        return NX_NOT_ENABLED;
    }

    /* Allocate the memory for link check thread   */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_LINK_CHECK_THREAD_STACK_SIZE,
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        return TX_POOL_ERROR;
    }
    /* Create the link check thread */
    ret = tx_thread_create(&app_link_check_thread, "Link check thread",
                           app_link_check_thread_entry, 0, pointer,
                           APP_LINK_CHECK_THREAD_STACK_SIZE,
                           APP_LINK_CHECK_PRIORITY,
                           APP_LINK_CHECK_PRIORITY,
                           TX_NO_TIME_SLICE,
                           TX_AUTO_START);
    if (ret != TX_SUCCESS)
    {
        return NX_NOT_ENABLED;
    }

    /* Allocate the memory for message queue */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_SENDING_MESSAGE_QUEUE_SIZE * sizeof(ULONG),
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        ret = TX_POOL_ERROR;
    }
    /* Create the message queue for sending MQTT message */
    if (tx_queue_create(&app_send_message_queue,
                        "MQTT sending message queue",
                        TX_1_ULONG, pointer,
                        APP_SENDING_MESSAGE_QUEUE_SIZE * sizeof(ULONG)) != TX_SUCCESS)
    {
        ret = TX_QUEUE_ERROR;
    }

    /**
     * Allocate memory for block pool use to allocate sending message information.
     * Block memory size is rounded up for alignment. Need to allocate more memory
     * than (number of message * each message size).
     */
    if (tx_byte_allocate(byte_pool, (VOID **)&pointer,
                         APP_SENDING_MESSAGE_QUEUE_SIZE * 2 * sizeof(APP_SENDING_MESSAGE_INFO),
                         TX_NO_WAIT) != TX_SUCCESS)
    {
        ret = TX_POOL_ERROR;
    }
    /* Create block pool use to allocate sending message information */
    tx_block_pool_create(&app_message_block_pool,
                         "MQTT Sending Message Block Pool",
                         sizeof(APP_SENDING_MESSAGE_INFO), pointer,
                         APP_SENDING_MESSAGE_QUEUE_SIZE * 2 * sizeof(APP_SENDING_MESSAGE_INFO));

    return ret;
}

static VOID app_ip_address_change_cb(NX_IP *ip_instance, VOID *ptr)
{
    /* Release the semaphore as soon as an IP address is available */
    if (nx_ip_address_get(&app_ip_instance,
                          &app_ip_address, &app_net_mask) != NX_SUCCESS)
    {
        Error_Handler();
    }
    if (app_ip_address != APP_NULL_IP_ADDRESS)
    {
        tx_semaphore_put(&app_dhcp_semaphore);
    }
}

static VOID app_main_thread_entry(ULONG thread_input)
{
    UINT ret = NX_SUCCESS;

    /* Create a DNS client */
    ret = app_dns_create(&app_dns_client);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    /* Register the IP address change callback */
    ret = nx_ip_address_change_notify(&app_ip_instance,
                                      app_ip_address_change_cb, NULL);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    /* Start the DHCP client */
    printf("Looking for DHCP server ..\n");
    ret = nx_dhcp_start(&app_dhcp_client);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }
    
    /* Wait until an IP address is ready */
    if (tx_semaphore_get(&app_dhcp_semaphore, TX_WAIT_FOREVER) != TX_SUCCESS)
    {
        Error_Handler();
    }

    PRINT_IP_ADDRESS(app_ip_address);

    /* Start the SNTP client thread */
    tx_thread_resume(&app_sntp_thread);

    /* This thread is not needed any more, we relinquish it */
    tx_thread_relinquish();
}

UINT app_dns_create(NX_DNS *dns_ptr)
{
    UINT ret = NX_SUCCESS;

    /* Create a DNS instance for the Client */
    ret = nx_dns_create(dns_ptr, &app_ip_instance, (UCHAR *)"DNS client");
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    /* Initialize DNS instance with a dummy server */
    ret = nx_dns_server_add(dns_ptr, APP_DNS_ADDRESS);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    return ret;
}

static VOID app_mqtt_disconnect_cb(NXD_MQTT_CLIENT *client_ptr)
{
    NX_PARAMETER_NOT_USED(client_ptr);

    printf("Client disconnected from broker.\n");
    nxd_mqtt_client_disconnect(&app_mqtt_client);
}

static VOID app_mqtt_received_cb(NXD_MQTT_CLIENT *client_ptr,
                                 UINT number_of_messages)
{
    NX_PARAMETER_NOT_USED(client_ptr);
    NX_PARAMETER_NOT_USED(number_of_messages);

    tx_event_flags_set(&app_message_received_flag,
                       APP_MQTT_MESSAGE_RECEIVED_EVENT, TX_OR);

    return;
}

static UINT app_message_generate_stub(void)
{
    uint32_t random_number = 0;

    /* Generate a random number */
    if (HAL_RNG_GenerateRandomNumber(&hrng, &random_number) != HAL_OK)
    {
        Error_Handler();
    }

    return random_number %= 50;
}

/* Function (set by user) to call when TLS needs the current time. */
static ULONG app_tls_session_time_function(void)
{
    return (app_sntp_time_from_epoch);
}

/* Callback to setup TLS parameters for secure MQTT connection. */
static UINT app_tls_setup_callback(NXD_MQTT_CLIENT *client_pt,
                                   NX_SECURE_TLS_SESSION *tls_session_ptr,
                                   NX_SECURE_X509_CERT *certificate_ptr,
                                   NX_SECURE_X509_CERT *trusted_certificate_ptr)
{
    UINT ret = NX_SUCCESS;
    NX_PARAMETER_NOT_USED(client_pt);

    /* Initialize TLS module */
    nx_secure_tls_initialize();

    /* Create a TLS session */
    ret = nx_secure_tls_session_create(tls_session_ptr,
                                       &nx_crypto_tls_ciphers,
                                       app_crypto_metadata_client,
                                       sizeof(app_crypto_metadata_client));
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    /* Need to allocate space for the certificate. */
    memset((certificate_ptr), 0, sizeof(NX_SECURE_X509_CERT));
    ret = nx_secure_tls_session_time_function_set(tls_session_ptr,
                                                  app_tls_session_time_function);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    /* Allocate space for packet reassembly. */
    ret = nx_secure_tls_session_packet_buffer_set(tls_session_ptr,
                                                  app_tls_packet_buffer,
                                                  sizeof(app_tls_packet_buffer));
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    /* Allocate space for the certificate coming in from the remote host */
    ret = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                    certificate_ptr,
                                                    app_tls_packet_buffer,
                                                    sizeof(app_tls_packet_buffer));
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    /* Initialize Certificate to verify incoming server certificates. */
    ret = nx_secure_x509_certificate_initialize(trusted_certificate_ptr,
                                                (UCHAR *)mosquitto_org_der,
                                                mosquitto_org_der_len,
                                                NX_NULL, 0, NULL, 0,
                                                NX_SECURE_X509_KEY_TYPE_NONE);
    if (ret != NX_SUCCESS)
    {
        printf("Certificate issue..\nPlease make sure that your X509_certificate is valid.\n");
        Error_Handler();
    }

    /* Add a CA Certificate to our trusted store */
    ret = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                trusted_certificate_ptr);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    return ret;
}

static VOID app_sntp_time_update_cb(NX_SNTP_TIME_MESSAGE *time_update_ptr,
                                    NX_SNTP_TIME *local_time)
{
    NX_PARAMETER_NOT_USED(time_update_ptr);

    printf("SNTP time update: %lu\n", local_time->seconds);
    app_sntp_time_from_epoch = local_time->seconds - APP_EPOCH_TIME_DIFF;
}

static VOID app_sntp_thread_entry(ULONG thread_input)
{
    UINT ret;
    NXD_ADDRESS sntp_server_ip;

    sntp_server_ip.nxd_ip_version = 4;
    do
    {
        /* Look up SNTP Server address until success. */
        ret = nx_dns_host_by_name_get(&app_dns_client,
                                      (UCHAR *)APP_SNTP_SERVER_NAME,
                                      &sntp_server_ip.nxd_ip_address.v4,
                                      APP_DEFAULT_TIMEOUT);
        if (ret != NX_SUCCESS)
        {
            tx_thread_sleep(APP_DEFAULT_TIMEOUT);
        }
    } while (ret != NX_SUCCESS);

    /* Create the SNTP Client */
    ret = nx_sntp_client_create(&app_sntp_client, &app_ip_instance,
                                0, &app_packet_pool, NULL, NULL, NULL);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    /* Setup time update callback function. */
    nx_sntp_client_set_time_update_notify(&app_sntp_client,
                                          app_sntp_time_update_cb);

    /* Use the IPv4 service to set up the client and set the IPv4 SNTP server. */
    ret = nx_sntp_client_initialize_unicast(&app_sntp_client,
                                            sntp_server_ip.nxd_ip_address.v4);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    /* Run whichever service the client is configured for. */
    ret = nx_sntp_client_run_unicast(&app_sntp_client);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

    do
    {
        /* Get time from SNTP server until success */
        ret = nx_sntp_client_request_unicast_time(&app_sntp_client,
                                                  APP_SNTP_CLIENT_REQUEST_TIMEOUT);
        if (ret != NX_SUCCESS)
        {
            tx_thread_sleep(APP_DEFAULT_TIMEOUT);
        }
    } while (ret != NX_SUCCESS);

    /* Start the MQTT client thread */
    tx_thread_resume(&app_mqtt_connection_check_thread);
}

static void send_device_report(void)
{
    lwjson_serializer_t serializer;
    size_t outputBytes = 0;
    CHAR report_topic[APP_MQTT_MAX_TOPIC_LENGTH];
    CHAR serialized_json[APP_MQTT_MAX_MESSAGE_LENGTH];
    lwjsonr_t res;

    if (app_mqtt_client.nxd_mqtt_client_state == NXD_MQTT_CLIENT_STATE_CONNECTED)
    {
        snprintf(report_topic, APP_MQTT_MAX_TOPIC_LENGTH,
                 "d2c/%s/report", APP_DEVICE_ID);

        /* Initialize serializer with output buffer */
        res = lwjson_serializer_init(&serializer, serialized_json,
                                     APP_MQTT_MAX_MESSAGE_LENGTH);
        if (res != lwjsonOK)
        {
            printf("Failed to initialize serializer: %d\n", res);
            return;
        }

        /* Start root object */
        res = lwjson_serializer_start_object(&serializer, NULL, 0);
        if (res != lwjsonOK)
        {
            printf("Failed to start object: %d\n", res);
            return;
        }

        /* Serialize property object */
        res = lwjson_serializer_start_object(&serializer, "property",
                                             strlen("property"));
        if (res != lwjsonOK)
        {
            printf("Failed to start property: %d\n", res);
            return;
        }
        /* Serialize led status */
        // Pin high --> led off
        // Pin low  --> led on
        res = lwjson_serializer_add_bool(&serializer, "green_led",
                                         strlen("green_led"),
                                         (HAL_GPIO_ReadPin(GPIOC, LED_GREEN_Pin) ? 0 : 1));
        if (res != lwjsonOK)
        {
            printf("Failed to add green led status: %d\n", res);
            return;
        }
        res = lwjson_serializer_add_bool(&serializer, "red_led",
                                         strlen("red_led"),
                                         (HAL_GPIO_ReadPin(GPIOC, LED_RED_Pin) ? 0 : 1));
        if (res != lwjsonOK)
        {
            printf("Failed to add red led status: %d\n", res);
            return;
        }
        /* End property object */
        res = lwjson_serializer_end_object(&serializer);
        if (res != lwjsonOK)
        {
            printf("Failed to end property: %d\n", res);
            return;
        }

        /* End root object */
        res = lwjson_serializer_end_object(&serializer);
        if (res != lwjsonOK)
        {
            printf("Failed to end object: %d\n", res);
            return;
        }

        res = lwjson_serializer_finalize(&serializer, &outputBytes);
        if (res != lwjsonOK)
        {
            printf("Failed to finalize serializer: %d\n", res);
            return;
        }

        /* Ensure null termination */
        serialized_json[outputBytes] = '\0';
        printf("Serialize report string: %s\n", serialized_json);

        nxd_mqtt_client_publish(&app_mqtt_client, report_topic,
                                strlen(report_topic), (CHAR *)serialized_json,
                                outputBytes, NX_FALSE, APP_MQTT_QOS1,
                                NX_WAIT_FOREVER);
    }
}

// Todo: MQTT client is not able to reconnect to broker. Need to understand root cause.
// MQTT client observation when disconnect ETH cable:
//    - MQTT client status is CONNECTED even cable disconnected for a while.
//      It changes status to DISCONNECTED after timeout period if cable still disconnected.
//      If MQTT client status is CONNECTED when cable disconnected, nxd_mqtt_client_subscribe()
//      and nxd_mqtt_client_publish() return no error to user. User can publish/subscribe topic
//      unsuccessfully, but the error is not notified to user.
//    - There is the case reconnecting to broker is unsuccessfully.
//      + Publish some messages when MQTT client status is CONNECTED and cable disconnected.
//      + MQTT client change status to DISCONNECTED and disconnect callback function called,
//        reconnect to broker is unsuccessfully. Publishing data rate and application thread
//        priority affect very much to MQTT client behavior. If the rate is greater than 0.5
//        messages per second (publish 1 message every 2 seconds), and application thread is
//        higher than other threads, we can observe corrupt behavior of MQTT client more frequently,
//        it is not able to reconnect to broker.
//        --> Need to study MQTT client source code and identify the root cause.
//            Maybe MQTT client state is corrupt if sending messages when cable disconnected.
//        --> Review how to set thread priority properly: IP thread, MQTT thread, Application thread.
//    --> MQTT client state can be corrupt, consider solution to detect communication error with broker
//        and restart SW using watchdog timer.

static UINT connect_to_broker(void)
{
    CHAR allDeviceTopic[APP_MQTT_MAX_TOPIC_LENGTH];
    NXD_ADDRESS mqtt_server_ip;
    ULONG broker_addr;
    UINT ret = NX_SUCCESS;

#ifdef MOSQUITTO_MQTT_PUBLIC
    do
    {
        /* Look up MQTT Server address until success. */
        ret = nx_dns_host_by_name_get(&DnsClient, (UCHAR *)MQTT_BROKER_NAME,
                                      &broker_addr, APP_DEFAULT_TIMEOUT);
        if (ret != NX_SUCCESS)
        {
            tx_thread_sleep(APP_DEFAULT_TIMEOUT);
        }
    } while (ret != NX_SUCCESS);
#else
    broker_addr = LOCAL_SERVER_ADDRESS;
#endif
    mqtt_server_ip.nxd_ip_version = 4;
    mqtt_server_ip.nxd_ip_address.v4 = broker_addr;
    nxd_mqtt_client_login_set(&app_mqtt_client,
                              APP_DEVICE_ID, strlen(APP_DEVICE_ID),
                              APP_DEVICE_TOKEN, strlen(APP_DEVICE_TOKEN));

    printf("Connecting to broker\n");
    /* Start a secure connection to the server. */
    ret = nxd_mqtt_client_secure_connect(&app_mqtt_client, &mqtt_server_ip,
                                         APP_MQTT_PORT, app_tls_setup_callback,
                                         APP_MQTT_KEEP_ALIVE_TIMER,
                                         APP_MQTT_CLEAN_SESSION,
                                         NX_WAIT_FOREVER);
    if (ret != NX_SUCCESS)
    {
        printf("MQTT client failed to connect to broker 0x%x.\n", ret);
        return ret;
    }
    else
    {
        printf("MQTT client connected to broker.\n");
    }

    /* Subscribe to the all topics related to device with QoS level 1. */
    snprintf(allDeviceTopic, APP_MQTT_MAX_TOPIC_LENGTH,
             "c2d/%s/#", APP_DEVICE_ID);
    ret = nxd_mqtt_client_subscribe(&app_mqtt_client, allDeviceTopic,
                                    strlen(allDeviceTopic), APP_MQTT_QOS1);
    /** 
     * Todo: How to handle error when subscribe failed?
     * If cable disconnected and mqtt client status is CONNECTED,
     * nxd_mqtt_client_subscribe() does not return error to user.
     * Is it possible to subscribe failed, but mqtt client does not
     * change status to DISCONNECTED?
     * --> Device will never try to reconnect to broker and never
     *     receive any messages from broker.
     */
    if (ret != NX_SUCCESS)
    {
        return ret;
    }

    return NX_SUCCESS;
}

static void add_report_request_to_queue(void)
{
    APP_SENDING_MESSAGE_INFO *msg_ptr;

    /* Allocate a message from the pool */
    if (tx_block_allocate(&app_message_block_pool,
                          (VOID **)&msg_ptr, TX_NO_WAIT) == TX_SUCCESS)
    {
        msg_ptr->message_type = APP_MESSAGE_TYPE_SEND_REPORT;

        /* Send the pointer through the queue */
        tx_queue_send(&app_send_message_queue, &msg_ptr, TX_WAIT_FOREVER);
    }
}

static VOID app_device_report_thread_entry(ULONG thread_input)
{
    while (1)
    {
        add_report_request_to_queue();
        /* Send report every 60s */
        tx_thread_sleep(6000);
    }
}

static void send_telemetry_data(APP_SENDING_MESSAGE_INFO *msg_ptr)
{
    lwjson_serializer_t serializer;
    size_t outputBytes = 0;
    CHAR telemetry_topic[APP_MQTT_MAX_TOPIC_LENGTH];
    CHAR serialized_json[APP_MQTT_MAX_MESSAGE_LENGTH];
    lwjsonr_t res;

    if (app_mqtt_client.nxd_mqtt_client_state == NXD_MQTT_CLIENT_STATE_CONNECTED)
    {
        snprintf(telemetry_topic, APP_MQTT_MAX_TOPIC_LENGTH,
                 "d2c/%s/data", APP_DEVICE_ID);

        /* Initialize serializer with output buffer */
        res = lwjson_serializer_init(&serializer, serialized_json,
                                     APP_MQTT_MAX_MESSAGE_LENGTH);
        if (res != lwjsonOK)
        {
            printf("Failed to initialize serializer: %d\n", res);
            return;
        }

        /* Start root object */
        res = lwjson_serializer_start_object(&serializer, NULL, 0);
        if (res != lwjsonOK)
        {
            printf("Failed to start object: %d\n", res);
            return;
        }

        res = lwjson_serializer_add_uint(&serializer, "Temperature",
                                         strlen("Temperature"),
                                         msg_ptr->payload.temperature);
        if (res != lwjsonOK)
        {
            printf("Failed to add Temperature data: %d\n", res);
            return;
        }

        /* End root object */
        res = lwjson_serializer_end_object(&serializer);
        if (res != lwjsonOK)
        {
            printf("Failed to end object: %d\n", res);
            return;
        }

        res = lwjson_serializer_finalize(&serializer, &outputBytes);
        if (res != lwjsonOK)
        {
            printf("Failed to finalize serializer: %d\n", res);
            return;
        }

        /* Ensure null termination */
        serialized_json[outputBytes] = '\0';
        printf("Serialize data string: %s\n", serialized_json);

        nxd_mqtt_client_publish(&app_mqtt_client, telemetry_topic,
                                strlen(telemetry_topic),
                                (CHAR *)serialized_json,
                                outputBytes,
                                NX_FALSE,
                                APP_MQTT_QOS1,
                                NX_WAIT_FOREVER);
    }
}

static VOID app_telemetry_data_thread_entry(ULONG thread_input)
{
    APP_SENDING_MESSAGE_INFO *msg_ptr;
    UINT temprature_val;

    while (1)
    {
        temprature_val = app_message_generate_stub();

        /* Allocate a message from the pool */
        if (tx_block_allocate(&app_message_block_pool,
                              (VOID **)&msg_ptr, TX_NO_WAIT) == TX_SUCCESS)
        {
            msg_ptr->message_type = APP_MESSAGE_TYPE_SEND_TELEMETRY_DATA;
            msg_ptr->payload.temperature = temprature_val;

            /* Send the pointer through the queue */
            tx_queue_send(&app_send_message_queue, &msg_ptr, TX_WAIT_FOREVER);
        }
        /* Send data every 10s */
        tx_thread_sleep(1000);
    }
}

static VOID app_send_message_thread_entry(ULONG thread_input)
{
    APP_SENDING_MESSAGE_INFO *received_msg_ptr;

    while (1)
    {
        /* Wait for a pointer message to arrive */
        if (tx_queue_receive(&app_send_message_queue,
                             &received_msg_ptr, TX_WAIT_FOREVER) == TX_SUCCESS)
        {
            /* Handle based on message type */
            switch (received_msg_ptr->message_type)
            {
            case APP_MESSAGE_TYPE_SEND_REPORT:
                send_device_report();
                break;
            case APP_MESSAGE_TYPE_SEND_TELEMETRY_DATA:
                send_telemetry_data(received_msg_ptr);
                break;
            default:
                break;
            }

            /* CRITICAL: Always release the block back to the pool after processing */
            tx_block_release(received_msg_ptr);
        }
    }
}

static VOID app_process_received_message_thread_entry(ULONG thread_input)
{
    ULONG events;
    UINT topic_length, message_length;
    CHAR cmp_topic[APP_MQTT_MAX_TOPIC_LENGTH];
    UCHAR message_buffer[APP_MQTT_MAX_MESSAGE_LENGTH];
    UCHAR topic_buffer[APP_MQTT_MAX_TOPIC_LENGTH];
    UINT ret = NX_SUCCESS;

    while (1)
    {
        /* wait for the broker to publish the message. */
        tx_event_flags_get(&app_message_received_flag,
                           APP_MQTT_MESSAGE_RECEIVED_EVENT,
                           TX_OR_CLEAR, &events, TX_WAIT_FOREVER);

        /* Check event received */
        if (events & APP_MQTT_MESSAGE_RECEIVED_EVENT)
        {
            /* Get message from the broker */
            ret = nxd_mqtt_client_message_get(&app_mqtt_client,
                                              topic_buffer,
                                              sizeof(topic_buffer),
                                              &topic_length,
                                              message_buffer,
                                              sizeof(message_buffer),
                                              &message_length);
            if (ret == NXD_MQTT_SUCCESS)
            {
                if (lwjson_parse_ex(&app_lwjson,
                                    (CHAR *)message_buffer,
                                    message_length) == lwjsonOK)
                {
                    const lwjson_token_t *top_obj;

                    /* Device receives command from broker */
                    snprintf(cmp_topic, APP_MQTT_MAX_TOPIC_LENGTH,
                             "c2d/%s/command", APP_DEVICE_ID);
                    if ((strncmp((CHAR *)topic_buffer, cmp_topic, topic_length) == 0) &&
                        (strlen(cmp_topic) == topic_length))
                    {
                        /* Get very first token as top object */
                        top_obj = lwjson_get_first_token(&app_lwjson);
                        if (top_obj->type == LWJSON_TYPE_OBJECT)
                        {
                            const lwjson_token_t *tk_name;
                            const lwjson_token_t *tk_led_type;

                            /* Find command name */
                            tk_name = lwjson_find(&app_lwjson, "name");
                            if ((tk_name != NULL) && (tk_name->type == LWJSON_TYPE_STRING))
                            {
                                if ((strncmp(tk_name->u.str.token_value, "turn_on_led",
                                             tk_name->u.str.token_value_len) == 0) &&
                                    (tk_name->u.str.token_value_len == strlen("turn_on_led")))
                                {
                                    // Find LED type
                                    tk_led_type = lwjson_find(&app_lwjson, "type");
                                    if ((tk_led_type != NULL) && (tk_led_type->type == LWJSON_TYPE_STRING))
                                    {
                                        if ((strncmp(tk_led_type->u.str.token_value, "green",
                                                     tk_led_type->u.str.token_value_len) == 0) &&
                                            (tk_led_type->u.str.token_value_len == strlen("green")))
                                        {
                                            HAL_GPIO_WritePin(GPIOC, LED_GREEN_Pin, GPIO_PIN_RESET);
                                            // Change led state, send report to update all clients.
                                            add_report_request_to_queue();
                                        }
                                        else if ((strncmp(tk_led_type->u.str.token_value, "red",
                                                          tk_led_type->u.str.token_value_len) == 0) &&
                                                 (tk_led_type->u.str.token_value_len == strlen("red")))
                                        {
                                            HAL_GPIO_WritePin(GPIOC, LED_RED_Pin, GPIO_PIN_RESET);
                                            // Change led state, send report to update all clients.
                                            add_report_request_to_queue();
                                        }
                                        else
                                        {
                                            printf("Unknown led type\n");
                                        }
                                    }
                                }
                                else if ((strncmp(tk_name->u.str.token_value, "turn_off_led",
                                                  tk_name->u.str.token_value_len) == 0) &&
                                         (tk_name->u.str.token_value_len == strlen("turn_off_led")))
                                {
                                    if ((strncmp(tk_led_type->u.str.token_value, "green",
                                                 tk_led_type->u.str.token_value_len) == 0) &&
                                        (tk_led_type->u.str.token_value_len == strlen("green")))
                                    {
                                        HAL_GPIO_WritePin(GPIOC, LED_GREEN_Pin, GPIO_PIN_SET);
                                        // Change led state, send report to update all clients.
                                        add_report_request_to_queue();
                                    }
                                    else if ((strncmp(tk_led_type->u.str.token_value, "red",
                                                      tk_led_type->u.str.token_value_len) == 0) &&
                                             (tk_led_type->u.str.token_value_len == strlen("red")))
                                    {
                                        HAL_GPIO_WritePin(GPIOC, LED_RED_Pin, GPIO_PIN_SET);
                                        // Change led state, send report to update all clients.
                                        add_report_request_to_queue();
                                    }
                                    else
                                    {
                                        printf("Unknown led type\n");
                                    }
                                }
                                else
                                {
                                    printf("Unknown command\n");
                                }
                            }
                            else
                            {
                                printf("Not found command name\n");
                            }
                        }
                        continue;
                    }

                    /* Device receives status report request */
                    snprintf(cmp_topic, APP_MQTT_MAX_TOPIC_LENGTH,
                             "c2d/%s/report", APP_DEVICE_ID);
                    if ((strncmp((CHAR *)topic_buffer, cmp_topic, topic_length) == 0) &&
                        (strlen(cmp_topic) == topic_length))
                    {
                        /* Get very first token as top object */
                        top_obj = lwjson_get_first_token(&app_lwjson);
                        if (top_obj->type == LWJSON_TYPE_OBJECT)
                        {
                            const lwjson_token_t *tk_topic;
                            const lwjson_token_t *tk_topic_element;

                            // Find topic
                            tk_topic = lwjson_find(&app_lwjson, "topic");
                            if ((tk_topic != NULL) && (tk_topic->type == LWJSON_TYPE_ARRAY))
                            {
                                for (tk_topic_element = lwjson_get_first_child(tk_topic);
                                     tk_topic_element != NULL;
                                     tk_topic_element = tk_topic_element->next)
                                {
                                    // Report device status
                                    if ((tk_topic_element->type == LWJSON_TYPE_STRING) &&
                                        (strncmp(tk_topic_element->u.str.token_value, "property",
                                                 tk_topic_element->u.str.token_value_len) == 0) &&
                                        (strlen("property") == tk_topic_element->u.str.token_value_len))
                                    {
                                        // Add the request to send the report.
                                        add_report_request_to_queue();
                                    }
                                }
                            }
                        }
                        continue;
                    }
                }
            }
            else
            {
                Error_Handler();
            }
        }
    }
}

static VOID app_mqtt_connection_check_thread_entry(ULONG thread_input)
{
    UINT ret = NX_SUCCESS;

    /* Initialize lwjson and pass statically allocated tokens */
    lwjson_init(&app_lwjson, app_tokens_buffer,
                LWJSON_ARRAYSIZE(app_tokens_buffer));

    /* Create MQTT client instance. */
    ret = nxd_mqtt_client_create(&app_mqtt_client, "MQTT client",
                                 APP_DEVICE_ID, strlen(APP_DEVICE_ID),
                                 &app_ip_instance, &app_packet_pool,
                                 (VOID *)app_mqtt_client_stack,
                                 APP_MQTT_CLIENT_THREAD_STACK_SIZE,
                                 APP_MQTT_CLIENT_THREAD_PRIORTY, NX_NULL, 0);
    if (ret != NX_SUCCESS)
    {
        Error_Handler();
    }

#if 0
      /**
       * Should use periodic report message for device online/offline detection.
       *
       * Observed will message behavior with Mosquitto broker:
       * - Will message will be published after (1.5 x keep alive) period (set when connect to broker).
       * - If device reconnect (resends CONNECT message) to broker within (1.5 x keep alive) period,
       *   user receive unexpected will message.
       * - If device reconnect (resends CONNECT message) to broker after (1.5 x keep alive) period,
       *   broker will not publish will message.
       */
      snprintf(cmp_topic, STRLEN(cmp_topic), "d2c/%s/status", APP_DEVICE_ID);
      nxd_mqtt_client_will_message_set(&MqttClient, (UCHAR*)cmp_topic, strlen(cmp_topic),
                                       (UCHAR*)"offline", strlen("offline"), NX_FALSE, APP_MQTT_QOS1);
#endif

    /* Register the disconnect notification function. */
    nxd_mqtt_client_disconnect_notify_set(&app_mqtt_client,
                                          app_mqtt_disconnect_cb);

    /* Set the receive notify function. */
    nxd_mqtt_client_receive_notify_set(&app_mqtt_client,
                                       app_mqtt_received_cb);

    /* Create an MQTT message received flag */
    ret = tx_event_flags_create(&app_message_received_flag,
                                "MQTT message received event");
    if (ret != TX_SUCCESS)
    {
        Error_Handler();
    }
    /* Todo: Review how to handle error here? */
    connect_to_broker();
    tx_thread_resume(&app_telemetry_data_thread);
    tx_thread_resume(&app_device_report_thread);
    tx_thread_resume(&app_process_received_message_thread);
    tx_thread_resume(&app_send_message_thread);

    while (1)
    {
        if ((app_mqtt_client.nxd_mqtt_client_state != NXD_MQTT_CLIENT_STATE_CONNECTED) &&
            (app_mqtt_client.nxd_mqtt_client_state != NXD_MQTT_CLIENT_STATE_CONNECTING))
        {
            connect_to_broker();
            // Check MQTT connection every 5s.
            tx_thread_sleep(500);
        }
    }
}

static VOID app_link_check_thread_entry(ULONG thread_input)
{
    ULONG actual_status;
    UINT status;
    UINT link_status = APP_LINK_STATUS_UP;

    while (1)
    {
        /* Send request to check if the Ethernet cable is connected. */
        status = nx_ip_interface_status_check(&app_ip_instance, 0,
                                              NX_IP_LINK_ENABLED,
                                              &actual_status, 10);

        if (status == NX_SUCCESS)
        {
            if (link_status == APP_LINK_STATUS_DOWN)
            {
                link_status = APP_LINK_STATUS_UP;

                /* The network cable is connected. */
                printf("The network cable is connected.\n");

                /* Send request to enable PHY Link. */
                nx_ip_driver_direct_command(&app_ip_instance,
                                            NX_LINK_ENABLE,
                                            &actual_status);

                /* Send request to check if an address is resolved. */
                status = nx_ip_interface_status_check(&app_ip_instance, 0,
                                                      NX_IP_ADDRESS_RESOLVED,
                                                      &actual_status, 10);
                if (status == NX_SUCCESS)
                {
                    /* Stop DHCP */
                    nx_dhcp_stop(&app_dhcp_client);

                    /* Reinitialize DHCP */
                    nx_dhcp_reinitialize(&app_dhcp_client);

                    /* Start DHCP */
                    nx_dhcp_start(&app_dhcp_client);

                    /* Wait until an IP address is ready */
                    if (tx_semaphore_get(&app_dhcp_semaphore,
                                         TX_WAIT_FOREVER) != TX_SUCCESS)
                    {
                        Error_Handler();
                    }
                    PRINT_IP_ADDRESS(app_ip_address);
                }
                else
                {
                    /**
                     *  Set the DHCP Client's remaining lease time to 0 seconds
                     *  to trigger an immediate renewal request for a DHCP address.
                     */
                    nx_dhcp_client_update_time_remaining(&app_dhcp_client, 0);
                }
            }
        }
        else
        {
            if (link_status == APP_LINK_STATUS_UP)
            {
                link_status = APP_LINK_STATUS_DOWN;
                /* The network cable is not connected. */
                printf("The network cable is not connected.\n");
                nx_ip_driver_direct_command(&app_ip_instance,
                                            NX_LINK_DISABLE, &actual_status);
            }
        }
        tx_thread_sleep(APP_CABLE_CONNECTION_CHECK_PERIOD);
    }
}
