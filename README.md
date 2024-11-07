# Simple MQTT Client Kernel Module

This repository contains a Linux kernel module implementing a basic MQTT client. The module is capable of connecting to an MQTT broker, sending a `CONNECT` packet, and publishing messages to a specified topic. This example demonstrates the essential steps to perform MQTT communication within the Linux kernel.

## Features

-   **MQTT Protocol**: Implements core MQTT operations (connect and publish) for use within the kernel space.
-   **Connect to Broker**: Establishes a socket connection to the MQTT broker, defaulting to `localhost` on port `1883`.
-   **Publish Messages**: Sends a PUBLISH packet to a specified MQTT topic, with options for QoS (Quality of Service) and retain flag.
-   **Configurable Client**: Supports customizable client ID, topic, username, and password in the `CONNECT` message.

## Requirements

-   **Linux Kernel**: Compatible with the Linux kernel's in-tree socket API.
-   **MQTT Broker**: Requires an accessible MQTT broker on the network, configured to accept connections on port 1883.

## Code Overview

The module contains functions to:

-   **Encode MQTT Packets**: Encode and create `CONNECT` and `PUBLISH` MQTT packets according to the MQTT 3.1.1 specification.
-   **Create and Send Packets**: Utilize Linux kernel socket APIs to open a connection, send MQTT packets, and publish data to the broker.
-   **Threaded Operation**: Runs in a kernel thread to maintain the connection and handle publish operations.

### Main Functions

-   `mqtt_connect_message`: Constructs a `CONNECT` packet, with optional username and password fields.
-   `mqtt_publish_message`: Constructs a `PUBLISH` packet with the specified topic, payload, QoS, and retain flag.
-   `mqtt_client_thread`: The primary client thread function that connects to the broker and sends messages.

## Getting Started

### Compilation

To compile this module, ensure you have kernel headers installed. Run the following commands:

`make` 

### Inserting and Running the Module

Load the module into the kernel using:

`sudo insmod mqtt_client.ko` 

Check `dmesg` to verify that the client has connected to the broker and sent a publish message.

### Removing the Module

To unload the module, use:

`sudo rmmod mqtt_client
