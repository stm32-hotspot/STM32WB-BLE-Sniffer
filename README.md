# STM32WB BLE Sniffer

Go to /doc to find the readme file about setup and user guide. 

Delivered binaries:
- BLE Sniffer stack : stm32wb55_ble_sniffer_cm0_stack.bin (flash at address 0x080CE000)
- BLE Sniffer app :
  - STM32WB55 Nucleo board : stm32wb55_ble_sniffer_cm4_nucleo.hex
  - STM32WB5MM Discovery kit : stm32wb55_ble_sniffer_cm4_dk.hex

## v1.0.0

First release version. Features implemented :

- Bluetooth LE features supported :
  - Connection update
  - Data length extension
  - Channel selection algorithm 2
  - PHY update asymmetrical 1M/2M
  - Legacy pairing with just work method link decryption or with necessary key provided
  - Secure pairing with at least one device in debug mode link decryption or with necessary key
- Sniffer protocol features :
  - Timestamp
  - RSSI
  - Channel index
  - PHY used
  - Connection event counter
  - Encryption status
  - Extended data length with sniffer report event fragmentation
- Wireshark plugins :
  - Custom dissector 
  - Extcap plugin multi board capture
  - Toolbar controls to send keys

## Boards available

  * STM32WB55
    * [P-NUCLEO-WB55.Nucleo](https://www.st.com/en/evaluation-tools/p-nucleo-wb55.html)
    * [STM32WB5MM-DK](https://www.st.com/en/evaluation-tools/stm32wb5mm-dk.html)

## User's documentation

You can find on the ST Wiki pages :
- how to install the STM32WB BLE Sniffer software parts and firmware [here](https://wiki.st.com/stm32mcu/wiki/Connectivity:STM32_Sniffer_for_BLE_Setup_guide)
- how to use the STM32WB BLE Sniffer [here](https://wiki.st.com/stm32mcu/wiki/Connectivity:STM32_Sniffer_for_BLE_User_guide)

## UART Interface

You can find all the details of the ST BLE Sniffer protocol in the [STM32WB_BLE_Sniffer_Interface.txt](/doc/STM32WB_BLE_Sniffer_Interface.txt) file

## Troubleshooting

**Caution** : Issues and the pull-requests are **not supported** to submit problems or suggestions related to the software delivered in this repository. The STM32WB-BLE-Sniffer is being delivered as-is, and not necessarily supported by ST.

**For any other question** related to the product, the hardware performance or characteristics, the tools, the environment, you can submit it to the **ST Community** on the STM32 MCUs related [page](https://community.st.com/s/topic/0TO0X000000BSqSWAW/stm32-mcus).

