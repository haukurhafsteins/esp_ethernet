# **ESP32 Ethernet & WiFi Network Management**

## **Overview**
This module provides an **Ethernet and WiFi management** system for ESP32, allowing dynamic switching between **Ethernet**, **WiFi Station (STA)**, and **WiFi Access Point (AP)** modes. It also handles **IP configuration**, **event management**, **hostname settings**, and **JSON-based configuration parsing**.

### **Key Features**
- Supports **Ethernet**, **WiFi STA**, and **WiFi AP** modes.
- Uses **ESP-IDF event handling** for network events.
- Handles **static and dynamic IP addressing**.
- Supports **hostname management**.
- Synchronizes system time using **SNTP**.
- Supports **JSON-based configuration parsing**.

---

## **Table of Contents**
1. [Initialization](#initialization)
2. [Network Event Handling](#network-event-handling)
3. [IP Address Management](#ip-address-management)
4. [Hostname Management](#hostname-management)
5. [WiFi Functions](#wifi-functions)
6. [Ethernet Functions](#ethernet-functions)
7. [JSON Configuration](#json-configuration)
8. [Function Documentation](#function-documentation)

---

## **1. Initialization**
Before using the network functionalities, initialize the Ethernet/WiFi settings by calling:

```c
ethernet_initialize(&ethernet_settings);
ethernet_start();
