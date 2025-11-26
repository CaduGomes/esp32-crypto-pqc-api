# Crypto API

Code for my final university project/thesis titled "Digital Certification in IoT Devices."

## Goal

This project aims to provide a quick way to benchmark between the most popular and high-rated cryptography libraries available to ESP32. The main focus is in digital signatures and certifications.

## Requirements

- ESP-IDF: This project uses the ESP-IDF framework, so you'll need ESP-IDF installed and configured on your machine (follow the instructions on [ESP-IDF official documentation](https://docs.espressif.com/projects/esp-idf/en/v5.3.1/esp32/get-started/index.html) on how to do it)
- VSCode: Although it is possible to execute this project without VSCode, it is highly recommended that you do use VSCode, due to it's ease of use.
- WolfSSL: This project uses wolfssl, but in it's source code needs to be outside of it. Follow the instructions below on how to do it.

## Setting up WolfSSL

1) Download the WolfSSL source code from it's [GitHub page (v5.7.4-stable)](https://github.com/wolfSSL/wolfssl/releases/tag/v5.7.4-stable);
2) Unzip the downloaded zip file, and move it to your desired location (ex: ```C:/wolfssl-source```);
3) Create a system-wide environment variable called ```WOLFSSL_ROOT```, pointing to the location of the wolfssl source code (ex: ```C:/wolfssl-source```);
4) Restart your machine;
5) After these steps, when compiling the project, it should be able to automatically detect the wolfssl folder and use it to generate the builder folder.

## Choosing which library and algorithm to use

In the main.cpp file, there's a call to a function named "perform_tests". This function is used for testing purposes, and it's parameters enable you to choose which library, signature algorithm and hash algorithm to use. Change them as you like.

## Running the project

First of all, make sure your esp32 device is connected to your mahcine. Then open the ```ESP-IDF PowerShell``` or ```ESP-IDF CMD``` that was installed when you installed ESP-IDF, and navigate to project root folder (ex: ```cd <path-to-project>/esp32-crypto-api```).

The project already has a build folder, so you can try simply running the project with ```idf.py flash``` and then ```idf.py monitor``` to flash the project to your device and start monitoring it. However, if this fails for some reason, delete the build folder, and execute the following commands:

1) ```idf.py set-target esp32```
2) ```idf.py build``` (alternatively, if using VSCode, ```CTRL + SHIFT + P``` and select ```ESP-IDF: Build your project```
3) ```idf.py flash``` (alternatively, if using VSCode, ```CTRL + SHIFT + P``` and select ```ESP-IDF: Flash your project```
4) ```idf.py monitor``` (alternatively, if using VSCode, ```CTRL + SHIFT + P``` and select ```ESP-IDF: Monitor device```

After this, the project should be up and running on your device.

## Integração liboqs e Alterações para PQC

Para suportar algoritmos Post-Quantum Cryptography (PQC) utilizando a biblioteca `liboqs` no ESP32, foram realizadas diversas modificações e configurações específicas.

### Alterações de Configuração (sdkconfig.defaults)

Para garantir a execução correta dos algoritmos PQC, que são intensivos em memória e processamento, as seguintes configurações foram aplicadas:

*   **Task Watchdog:** O timeout foi aumentado para **60 segundos** (`CONFIG_ESP_TASK_WDT_TIMEOUT_S=60`) para evitar resets durante a execução do algoritmo SLH-DSA, que pode levar cerca de 20 segundos para assinar.
*   **Stack Size:** O tamanho da pilha da tarefa principal foi aumentado para **100KB** (`CONFIG_ESP_MAIN_TASK_STACK_SIZE=102400`) para suportar o consumo elevado de memória do algoritmo ML-DSA (Dilithium).
*   **System Event Stack:** Aumentado para 4KB (`CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE=4096`) como precaução.
*   **Heap Debugging:** Habilitado `CONFIG_HEAP_POISONING_COMPREHENSIVE=y` para detecção precoce de corrupção de memória.
*   **SHA3:** Habilitado suporte a SHA3 no MbedTLS (`CONFIG_MBEDTLS_SHA3_C=y`).
*   **Partition Table:** Configurado para usar uma tabela de partições personalizada (`CONFIG_PARTITION_TABLE_CUSTOM=y`, `partitions.csv`) para incluir uma partição `littlefs` necessária para o sistema de arquivos.

### Alterações na Biblioteca liboqs (Porting para ESP32)

A biblioteca `liboqs` foi integrada como um componente ESP-IDF em `components/liboqs`, com as seguintes adaptações:

1.  **Configuração (oqsconfig.h):**
    *   Criado arquivo de configuração específico para ESP32.
    *   Habilitados apenas os algoritmos necessários: **SPHINCS+**, **ML-DSA** (Dilithium), **FALCON** e **SLH-DSA**.
    *   Desabilitadas instruções específicas de arquitetura não suportadas pelo ESP32 (AVX, SSE, NEON, AES-NI, etc.).

2.  **Build System (CMakeLists.txt):**
    *   Implementado filtro para excluir arquivos fonte que utilizam instruções de arquitetura incompatíveis (x86, ARM, AVX, SSE).
    *   Configurada a cópia automática de headers necessários e inclusão de diretórios específicos do PQClean.

3.  **Correções de Código (Patches):**
    *   **`src/common/common.c`**:
        *   A função `OQS_MEM_aligned_alloc` foi ajustada para garantir um alinhamento mínimo de 4 bytes, evitando erros de acesso à memória no ESP32.
        *   Correção de erros de sintaxe (diretivas de pré-processador).
    *   **`src/sig/sphincs/.../merkle.c`**: Adicionados *type casts* explícitos `(uint32_t *)` para corrigir avisos de tipos de ponteiro incompatíveis.

4.  **Integração com Hardware (RNG):**
    *   **`components/CryptoAPI/src/LiboqsModule.cpp`**: Implementada a função `oqs_esp32_randombytes` que utiliza o gerador de números aleatórios de hardware do ESP32 (`esp_fill_random`). Esta função foi registrada no `liboqs` via `OQS_randombytes_custom_algorithm` para substituir a leitura padrão de `/dev/urandom`.

### Outras Adições

*   **`partitions.csv`**: Arquivo de tabela de partições criado para definir o layout da flash, incluindo a partição `littlefs`.
