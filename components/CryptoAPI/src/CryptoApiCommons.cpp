#include "CryptoApiCommons.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "CryptoApiCommons";

// CryptoApiCommons::CryptoApiCommons() : littlefs_initialized(false) {}
CryptoApiCommons::CryptoApiCommons() {}

Algorithms CryptoApiCommons::get_chosen_algorithm()
{
  return chosen_algorithm;
}

void CryptoApiCommons::set_chosen_algorithm(Algorithms algorithm)
{
  chosen_algorithm = algorithm;
}

Hashes CryptoApiCommons::get_chosen_hash()
{
  return chosen_hash;
}

void CryptoApiCommons::set_chosen_hash(Hashes hash)
{
  chosen_hash = hash;
}

void CryptoApiCommons::set_shake256_hash_length(size_t length)
{
  shake256_hash_length = length;
}

size_t CryptoApiCommons::get_hash_length()
{
  switch (chosen_hash)
  {
  case Hashes::MY_SHA_256:
    return 32;
  case Hashes::MY_SHA_512:
    return 64;
  case Hashes::MY_SHA3_256:
    return 32;
  case Hashes::MY_SHAKE_256:
    return shake256_hash_length;
  default:
    return 32;
  }
}

/*
esp_err_t CryptoApiCommons::init_littlefs()
{
  conf = {
      .base_path = "/littlefs",
      .partition_label = "littlefs",
      .format_if_mount_failed = true,
      .dont_mount = false};

  esp_err_t ret = esp_vfs_littlefs_register(&conf);

  if (ret != ESP_OK)
  {
    littlefs_initialized = false;
    if (ret == ESP_FAIL)
    {
      ESP_LOGE(TAG, "Failed to mount or format filesystem");
    }
    else if (ret == ESP_ERR_NOT_FOUND)
    {
      ESP_LOGE(TAG, "Failed to find LittleFS partition");
    }
    else
    {
      ESP_LOGE(TAG, "Failed to initialize LittleFS (%s)", esp_err_to_name(ret));
    }
    return ret;
  }

  littlefs_initialized = true;

  size_t total = 0, used = 0;
  ret = esp_littlefs_info(conf.partition_label, &total, &used);
  if (ret != ESP_OK)
  {
    ESP_LOGE(TAG, "Failed to get LittleFS partition information (%s)", esp_err_to_name(ret));
  }
  else
  {
    ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
  }

  return ESP_OK;
}

void CryptoApiCommons::close_littlefs()
{
  if (!littlefs_initialized)
  {
    return;
  }

  esp_err_t ret = esp_vfs_littlefs_unregister(conf.partition_label);
  if (ret == ESP_OK)
  {
    littlefs_initialized = false;
  }
  else
  {
    ESP_LOGE(TAG, "Failed to unregister LittleFS: %s", esp_err_to_name(ret));
  }
}

void CryptoApiCommons::write_file(const char *file_path, const unsigned char *data)
{
  // Open the file for writing
  FILE *file = fopen(file_path, "w");
  if (file != NULL)
  {
    // Write data to the file
    fprintf(file, "%s", data);
    fclose(file);
    ESP_LOGI(TAG, "Data written to %s successfully", file_path);
  }
  else
  {
    ESP_LOGE(TAG, "Failed to open file for writing");
  }
}

void CryptoApiCommons::write_binary_file(const char *file_path, const unsigned char *data, size_t data_len)
{
  // Open the file for writing in binary mode
  FILE *file = fopen(file_path, "wb");
  if (file != NULL)
  {
    // Write the data to the file
    size_t written = fwrite(data, 1, data_len, file);
    fclose(file);

    // Check if all data was written
    if (written == data_len)
    {
      ESP_LOGI(TAG, "Data successfully written to %s", file_path);
    }
    else
    {
      ESP_LOGE(TAG, "Only %zu out of %zu bytes written to %s", written, data_len, file_path);
    }
  }
  else
  {
    ESP_LOGE(TAG, "Failed to open file for writing: %s", file_path);
  }
}

void CryptoApiCommons::read_file(const char *file_path, unsigned char *buffer, size_t buffer_size)
{
  FILE *file = fopen(file_path, "r");
  if (file != NULL)
  {
    size_t read_size = fread(buffer, 1, buffer_size, file);
    fclose(file);

    if (read_size != buffer_size)
    {
      ESP_LOGE(TAG, "Failed to read entire file: %s", file_path);
      free(buffer);
      return;
    }

    ESP_LOGI(TAG, "Loaded from %s:\n%s", file_path, buffer);
  }
  else
  {
    ESP_LOGE(TAG, "Failed to open file for reading");
  }
}

long CryptoApiCommons::get_file_size(const char *file_path)
{
  FILE *file = fopen(file_path, "rb");
  if (file == NULL)
  {
    ESP_LOGE(TAG, "Failed to open file: %s", file_path);
    return -1;
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (file_size <= 0)
  {
    ESP_LOGE(TAG, "File size error: %ld", file_size);
    fclose(file);
    return file_size;
  }

  fclose(file);
  return file_size;
}
*/

void CryptoApiCommons::log_success(const char *msg)
{
  ESP_LOGI(TAG, "SUCCESS AT %s", msg);
}

void CryptoApiCommons::log_error(const char *msg)
{
  ESP_LOGE(TAG, "Failed at %s", msg);
}

void CryptoApiCommons::print_elapsed_time(unsigned long start, unsigned long end, const char *label)
{
  ESP_LOGI(TAG, "\n\n%s time: %lu ms", label, end - start);
}

void CryptoApiCommons::print_used_memory(unsigned long initial, unsigned long final, const char *label)
{
  ESP_LOGI(TAG, "%s memory: %lu bytes", label, initial - final);
}

void CryptoApiCommons::print_total_cycles(unsigned long initial, unsigned long final, const char *label)
{
  ESP_LOGI(TAG, "%s clock cycle count: %lu", label, final - initial);
}