/**
 * @file mqtt_client_module.c
 * @brief Simple MQTT Client Kernel Module
 *
 * This kernel module implements a simple MQTT client that connects to an MQTT broker,
 * sends a CONNECT packet, and publishes a message to a specified topic.
 *
 * @author
 * Pawel Ratanczuk
 *
 * @license
 * GPL
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/types.h>
#include <linux/slab.h>

#define BROKER_PORT 1883
#define BROKER_IP htonl(INADDR_LOOPBACK)  /**< Connect to localhost */

static struct task_struct *client_thread_st;

#define MQTT_QOS0 0x00

/**
 * Encodes the MQTT "Remaining Length" field according to MQTT specifications.
 *
 * @param buffer The buffer where the encoded length will be stored.
 * @param length The length value to encode.
 * @return The number of bytes used to encode the length.
 */
static int encode_remaining_length(uint8_t *buffer, int length) {
    int index = 0;
    do {
        buffer[index] = length % 128;
        length /= 128;
        if (length > 0) {
            buffer[index] |= 0x80; // Set the continuation bit
        }
        index++;
    } while (length > 0);
    return index;
}

/**
 * Creates an MQTT CONNECT message with optional username and password fields.
 *
 * @param buffer The buffer where the encoded CONNECT message will be stored.
 * @param client_id The client ID string to use in the CONNECT message.
 * @param username Optional username string for authentication (set NULL if not used).
 * @param password Optional password string for authentication (set NULL if not used).
 * @return The total length of the encoded CONNECT message in bytes.
 *
 * This function constructs an MQTT CONNECT message, including setting the protocol name,
 * version, flags, and payload according to the MQTT 3.1.1 specification. The username
 * and password fields are included in the payload if provided.
 */
static int mqtt_connect_message(uint8_t *buffer, const char *client_id, const char *username, const char *password) {
    int index = 0;
    int client_id_len = strlen(client_id);
    int username_len = username ? strlen(username) : 0;
    int password_len = password ? strlen(password) : 0;
    int payload_len = 2 + client_id_len; // Initial payload length for Client ID field

    // Adjust payload length if username and/or password are provided
    if (username) payload_len += 2 + username_len;
    if (password) payload_len += 2 + password_len;

    // Fixed header
    buffer[index++] = 0x10; // CONNECT packet type and flags

    // Variable header: calculate remaining length and encode
    uint8_t remaining_length[4];
    int variable_header_len = 10 + payload_len;
    int len_bytes = encode_remaining_length(remaining_length, variable_header_len);
    memcpy(buffer + index, remaining_length, len_bytes);
    index += len_bytes;

    // Protocol Name
    buffer[index++] = 0x00; // Protocol Name Length MSB
    buffer[index++] = 0x04; // Protocol Name Length LSB
    memcpy(buffer + index, "MQTT", 4); // Protocol Name
    index += 4;

    // Protocol Level
    buffer[index++] = 0x04; // Protocol Level (4 for MQTT 3.1.1)

    // Connect Flags
    uint8_t connect_flags = 0x02; // Clean Session by default
    if (username) connect_flags |= 0x80; // Set Username Flag if username is provided
    if (password) connect_flags |= 0x40; // Set Password Flag if password is provided
    buffer[index++] = connect_flags;

    // Keep Alive
    buffer[index++] = 0x00; // Keep Alive MSB (0x003C = 60 seconds)
    buffer[index++] = 0x3C; // Keep Alive LSB

    // Payload - Client ID
    buffer[index++] = (client_id_len >> 8) & 0xFF; // Client ID Length MSB
    buffer[index++] = client_id_len & 0xFF;         // Client ID Length LSB
    memcpy(buffer + index, client_id, client_id_len);
    index += client_id_len;

    // Payload - Username (if provided)
    if (username) {
        buffer[index++] = (username_len >> 8) & 0xFF; // Username Length MSB
        buffer[index++] = username_len & 0xFF;         // Username Length LSB
        memcpy(buffer + index, username, username_len);
        index += username_len;
    }

    // Payload - Password (if provided)
    if (password) {
        buffer[index++] = (password_len >> 8) & 0xFF; // Password Length MSB
        buffer[index++] = password_len & 0xFF;         // Password Length LSB
        memcpy(buffer + index, password, password_len);
        index += password_len;
    }

    return index; // Return the total length of the CONNECT message
}

/**
 * Creates an MQTT PUBLISH message.
 *
 * @param buffer The buffer where the encoded PUBLISH message will be stored.
 * @param topic The topic to publish to.
 * @param payload The payload data to publish (optional, can be NULL).
 * @param payload_len The length of the payload data (0 if no payload).
 * @param qos The Quality of Service level (0, 1, or 2).
 * @param retain Set to 1 if the message should be retained by the broker.
 * @return The total length of the encoded PUBLISH message in bytes.
 *
 * This function constructs an MQTT PUBLISH message according to the MQTT 3.1.1 specification.
 * The message includes the topic and optional payload, with variable header fields and flags.
 */
static int mqtt_publish_message(uint8_t *buffer, const char *topic, const uint8_t *payload, int payload_len, uint8_t qos, uint8_t retain) {
    int index = 0;
    int topic_len = strlen(topic);

    // Fixed header
    uint8_t publish_flags = 0x30; // PUBLISH packet type (0x30)
    publish_flags |= (qos << 1);  // Set QoS level
    if (retain) publish_flags |= 0x01; // Set Retain flag if needed
    buffer[index++] = publish_flags;

    // Variable header: calculate remaining length and encode
    int variable_header_len = 2 + topic_len + payload_len;
    if (qos > 0) variable_header_len += 2; // Add 2 bytes for packet ID if QoS > 0

    uint8_t remaining_length[4];
    int len_bytes = encode_remaining_length(remaining_length, variable_header_len);
    memcpy(buffer + index, remaining_length, len_bytes);
    index += len_bytes;

    // Topic
    buffer[index++] = (topic_len >> 8) & 0xFF; // Topic Length MSB
    buffer[index++] = topic_len & 0xFF;         // Topic Length LSB
    memcpy(buffer + index, topic, topic_len);
    index += topic_len;

    // Packet Identifier (if QoS > 0)
    if (qos > 0) {
        buffer[index++] = 0x00; // Packet Identifier MSB (default 0 for example)
        buffer[index++] = 0x01; // Packet Identifier LSB
    }

    // Payload (if provided)
    if (payload && payload_len > 0) {
        memcpy(buffer + index, payload, payload_len);
        index += payload_len;
    }

    return index; // Return the total length of the PUBLISH message
}


/**
 * @brief MQTT client thread function.
 *
 * This function creates a socket, connects to the MQTT broker,
 * sends a CONNECT packet, publishes a message to a topic, and waits
 * for the thread to be stopped.
 *
 * @param data Unused parameter.
 * @return 0 on success, negative error code on failure.
 */
static int mqtt_client_thread(void *data)
{
    struct socket *conn_socket = NULL;
    struct sockaddr_in broker_addr;
    int ret;
    struct kvec vec;
    struct msghdr msg;
    char *topic = "kernel/test";
    char *user = "user";
    char *password = "password";
    char *message = "Hello from kernel module!";
    uint8_t qos = 1; // Quality of Service level 1
    uint8_t retain = 0; // Do not retain the message

    /* Allow signals */
    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    /* Create socket */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);
    if (ret < 0) {
        pr_err("MQTT Client: Socket creation failed with error %d\n", ret);
        return ret;
    }

    /* Prepare the broker address */
    memset(&broker_addr, 0, sizeof(broker_addr));
    broker_addr.sin_family = AF_INET;
    broker_addr.sin_port = htons(BROKER_PORT);
    broker_addr.sin_addr.s_addr = BROKER_IP;

    /* Connect to the broker */
    ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&broker_addr, sizeof(broker_addr), 0);
    if (ret < 0) {
        pr_err("MQTT Client: Unable to connect to broker, error %d\n", ret);
        sock_release(conn_socket);
        return ret;
    }

    pr_info("MQTT Client: Connected to broker\n");

    uint8_t packet[256];
    int packet_len;

    // With username and password
    packet_len = mqtt_connect_message(packet, "ME", user, password);

    // Without username and password
    //connect_len = mqtt_connect_message(connect_packet, "ME", NULL, NULL);

    /* Send CONNECT packet */

    memset(&vec, 0, sizeof(vec));
    memset(&msg, 0, sizeof(msg));
    vec.iov_base = packet;
    vec.iov_len = packet_len;

    ret = kernel_sendmsg(conn_socket, &msg, &vec, 1, packet_len);
    if (ret < 0) {
        pr_err("MQTT Client: Failed to send CONNECT packet, error %d\n", ret);
        sock_release(conn_socket);
        return ret;
    } else {
        pr_info("MQTT Client: CONNECT packet sent\n");
    }

    /* Normally, we should wait for CONNACK packet here ...*/


    // Call the mqtt_publish_message function
    packet_len = mqtt_publish_message(packet, topic, (const uint8_t *)message, strlen(message), qos, retain);

    memset(&vec, 0, sizeof(vec));
    memset(&msg, 0, sizeof(msg));
    vec.iov_base = packet;
    vec.iov_len = packet_len;

    ret = kernel_sendmsg(conn_socket, &msg, &vec, 1, packet_len);
    if (ret < 0) {
        pr_err("MQTT Client: Failed to send PUBLISH packet, error %d\n", ret);
    } else {
        pr_info("MQTT Client: PUBLISH packet sent\n");
    }

    /* Close the socket */
    sock_release(conn_socket);

    /* Wait for kthread_stop */
    set_current_state(TASK_INTERRUPTIBLE);
    while (!kthread_should_stop()) 
    {
        schedule();
        set_current_state(TASK_INTERRUPTIBLE);
    }

    set_current_state(TASK_RUNNING);

    /* Exit the thread */
    return 0;
}

/**
 * @brief Module initialization function.
 *
 * Initializes the MQTT client module by starting the client thread.
 *
 * @return 0 on success, negative error code on failure.
 */
static int __init mqtt_client_init(void)
{
    pr_info("MQTT Client Module: Initializing\n");

    /* Start the client thread */
    client_thread_st = kthread_run(mqtt_client_thread, NULL, "mqtt_client_thread");
    if (IS_ERR(client_thread_st)) {
        pr_err("MQTT Client: Failed to create kernel thread\n");
        return PTR_ERR(client_thread_st);
    }

    pr_info("MQTT Client: Kernel thread created successfully\n");
    return 0;
}

/**
 * @brief Module exit function.
 *
 * Cleans up the MQTT client module by stopping the client thread if it's running.
 */
static void __exit mqtt_client_exit(void)
{
    pr_info("MQTT Client Module: Exiting\n");

    /* Terminate the client thread if it's still running */
    if (client_thread_st) {
        /* Signal the thread to stop */
        kthread_stop(client_thread_st);
        pr_info("MQTT Client: Kernel thread stopped\n");
    }
}

module_init(mqtt_client_init);
module_exit(mqtt_client_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pawel Ratanczuk");
MODULE_DESCRIPTION("Simple MQTT Client Kernel Module");
