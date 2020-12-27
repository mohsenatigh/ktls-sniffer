#include <linux/tls.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc, char *argv[]) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(sock, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));

  /**
   * TODO Handshake and get the key from the server
   *
   */
  uint8_t iv[16] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
                    0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};
  uint8_t key[16] = {0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
                     0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2};
  uint8_t seq[8] = {0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3};
  uint8_t salt[4] = {0x4, 0x4, 0x4, 0x4};

  struct tls12_crypto_info_aes_gcm_128 crypto_info;
  crypto_info.info.version = TLS_1_2_VERSION;
  crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
  memcpy(crypto_info.iv, iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
  memcpy(crypto_info.rec_seq, seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
  memcpy(crypto_info.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
  memcpy(crypto_info.salt, salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
  setsockopt(sock, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
}
